/*
 * scanner.h - TCP半连接端口扫描器 头文件
 *
 * 功能：定义扫描器的接口、回调类型和常量
 */

#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>

/* 扫描结果状态 */
#define PORT_OPEN    0    /* 端口开放 (收到SYN+ACK) */
#define PORT_CLOSED  1    /* 端口关闭 (收到RST)   */
#define PORT_FILTERED 2   /* 被过滤 (无响应)       */

/* 最大端口号 */
#define MAX_PORT 65535

/* 默认超时时间(毫秒) */
#define DEFAULT_TIMEOUT_MS 2000

/* 每个端口扫描结果 */
typedef struct {
    uint16_t port;          /* 端口号 */
    int      status;        /* PORT_OPEN / PORT_CLOSED / PORT_FILTERED */
    char     service[64];   /* 常见服务名称 */
} scan_result_t;

/*
 * 结果回调函数类型
 * 每扫描完一个端口就调用一次，在GUI线程的idle回调中执行
 * user_data: 用户自定义数据指针
 */
typedef void (*scan_callback_t)(const scan_result_t *result, void *user_data);

/*
 * 完成回调函数类型
 * 所有端口扫描完成后调用
 */
typedef void (*scan_done_callback_t)(void *user_data);

/*
 * 扫描上下文（不透明指针）
 */
typedef struct scan_context scan_context_t;

/*
 * 初始化扫描器
 * device:   网络接口名称 (如 "eth0")，传NULL则自动检测
 * errbuf:   错误信息缓冲区 (至少256字节)
 * 返回值:   成功返回上下文指针，失败返回NULL
 */
scan_context_t *scanner_init(const char *device, char *errbuf);
/*
 * 通过路由表解析到达目标IP应使用的网卡
 * target_ip: 目标IP地址（点分十进制），为NULL则回退到默认检测
 * dev:       输出缓冲区，存放解析出的网卡名
 * dev_len:   输出缓冲区大小
 * 返回值:    0成功, -1失败
 */
int scanner_resolve_device(const char *target_ip, char *dev, int dev_len);

/*
 * 开始扫描
 * ctx:          扫描上下文
 * target_ip:    目标IP地址 (点分十进制字符串)
 * start_port:   起始端口
 * end_port:     结束端口
 * timeout_ms:   每个端口的超时时间(毫秒)
 * callback:     结果回调 (每扫描一个端口调用一次)
 * done_cb:      扫描完成回调
 * user_data:    用户数据，会传给回调函数
 * 返回值:       0成功, -1失败
 */

/*
 * 设置ACK二次探测
 * 启用后，SYN无响应的端口会额外发ACK包判断是被过滤还是Windows沉默
 */

int scanner_scan(scan_context_t *ctx,
                 const char *target_ip,
                 uint16_t start_port,
                 uint16_t end_port,
                 int timeout_ms,
                 scan_callback_t callback,
                 scan_done_callback_t done_cb,
                 void *user_data);

/*
 * 停止正在进行的扫描
 */
void scanner_stop(scan_context_t *ctx);

/*
 * 清理并释放扫描器资源
 */
void scanner_cleanup(scan_context_t *ctx);

/*
 * 根据端口号获取常见服务名称
 */
const char *scanner_get_service(uint16_t port);

/*
 * 获取当前使用的网络接口名称
 */
const char *scanner_get_device(scan_context_t *ctx);

/*
 * 扫描统计
 */
typedef struct {
    int ports_attempted;   /* 实际尝试发送 SYN 的端口数 */
    int send_failures;     /* 发送失败次数 */
    int completed;         /* 1=扫描完整结束，0=被停止 */
} scan_stats_t;

/*
 * 扫描一组指定端口（可非连续，用于按端口策略巡检）
 * ports:     端口数组（长度 n_ports）
 * stats_out: 统计输出，可为 NULL
 * errbuf:    错误信息缓冲（至少 256 字节），可为 NULL
 * 返回值:    0 成功, -1 失败
 */
int scanner_scan_ports(scan_context_t *ctx,
                       const char *target_ip,
                       const uint16_t *ports,
                       int n_ports,
                       int timeout_ms,
                       scan_callback_t callback,
                       scan_done_callback_t done_cb,
                       void *user_data,
                       scan_stats_t *stats_out,
                       char *errbuf);
#endif /* SCANNER_H */