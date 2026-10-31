/*
 * scanner.c - TCP半连接端口扫描器 核心实现
 *
 * 原理：
 *   1. 向目标主机的每个端口发送一个 TCP SYN 数据包（使用libnet构造）
 *   2. 通过 libpcap 捕获目标返回的响应包：
 *      - 收到 SYN+ACK → 端口开放，立即发送 RST 断开半连接
 *      - 收到 RST     → 端口关闭
 *      - 超时无响应   → 被防火墙过滤
 *
 * 依赖库: libnet (构造发送数据包) + libpcap (捕获响应数据包)
 */

#include "scanner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>

#include <pcap.h>
#include <libnet.h>

/* TCP 标志位常量：部分 libnet 版本或平台上未必随头文件提供，
 * 这里做保底定义；若已被定义则不会重复定义，保证跨发行版可编译。 */
#ifndef TH_ACK
#define TH_ACK 0x10
#endif
#ifndef TH_SYN
#define TH_SYN 0x02
#endif
#ifndef TH_RST
#define TH_RST 0x04
#endif

/* ===== 扫描上下文结构 ===== */
struct scan_context {
    libnet_t    *libnet_ctx;    /* libnet 上下文 */
    pcap_t      *pcap_handle;   /* libpcap 句柄 */
    char         device[64];    /* 网络接口名称 */
    uint32_t     src_ip;        /* 本机IP */
    int          stop_flag;     /* 停止标志 */
};

/* ===== 常见端口-服务对照表 ===== */
static const struct {
    uint16_t port;
    const char *service;
} port_services[] = {
    {7,    "Echo"},       {20,   "FTP-Data"},   {21,   "FTP"},
    {22,   "SSH"},        {23,   "Telnet"},      {25,   "SMTP"},
    {53,   "DNS"},        {67,   "DHCP-Server"}, {68,   "DHCP-Client"},
    {69,   "TFTP"},       {80,   "HTTP"},        {110,  "POP3"},
    {111,  "RPC"},        {123,  "NTP"},         {135,  "RPC"},
    {137,  "NetBIOS-NS"}, {138,  "NetBIOS-DGM"}, {139,  "NetBIOS-SSN"},
    {143,  "IMAP"},       {161,  "SNMP"},        {162,  "SNMP-Trap"},
    {179,  "BGP"},        {389,  "LDAP"},        {443,  "HTTPS"},
    {445,  "SMB"},        {465,  "SMTPS"},       {514,  "Syslog"},
    {554,  "RTSP"},       {587,  "SMTP-Submit"}, {636,  "LDAPS"},
    {873,  "Rsync"},      {993,  "IMAPS"},       {995,  "POP3S"},
    {1080, "SOCKS"},      {1194, "OpenVPN"},     {1433, "MSSQL"},
    {1521, "Oracle"},     {1723, "PPTP"},        {1883, "MQTT"},
    {2049, "NFS"},        {2181, "ZooKeeper"},   {2375, "Docker"},
    {3128, "Squid"},      {3306, "MySQL"},       {3389, "RDP"},
    {5060, "SIP"},        {5353, "mDNS"},        {5432, "PostgreSQL"},
    {5672, "RabbitMQ"},   {5900, "VNC"},         {6379, "Redis"},
    {6443, "K8s-API"},    {7001, "WebLogic"},    {8080, "HTTP-Alt"},
    {8443, "HTTPS-Alt"},  {8888, "HTTP-Proxy"},  {9090, "Web-GUI"},
    {9200, "Elasticsearch"},{9300, "ES-Node"},   {11211,"Memcached"},
    {27017,"MongoDB"},    {50070,"HDFS"},
    {0,     NULL}  /* 结束标记 */
};

/* ===== 工具函数 ===== */

/* 根据端口号查找服务名 */
const char *scanner_get_service(uint16_t port) {
    for (int i = 0; port_services[i].service != NULL; i++) {
        if (port_services[i].port == port)
            return port_services[i].service;
    }
    return "未知";
}

/* 获取可用的网络接口名称
 * 策略：优先选择有真实网络IP的接口，跳过WSL内部NAT接口(198.18.x.x)和loopback */
static int get_default_device(char *dev, size_t dev_len) {
    char errbuf[PCAP_ERRBUF_SIZE];  // 错误信息字符串缓冲区 
    pcap_if_t *alldevs;     // 指向网卡列表的指针

    /* 系统返回所有网卡 */
    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        return -1;
    }

    /* 第一遍：找一个有真实IP的非loopback、非WSL-NAT接口 */
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;  // 网卡是 loopback，跳过

        /* 遍历这个网卡上的 IP 地址 */
        for (pcap_addr_t *a = d->addresses; a != NULL; a = a->next) {
            /* 地址不为空 且 是IPv4 */
            if (a->addr && a->addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;    // 把通用的地址结构强制转成 IPv4 专用结构
                uint32_t ip = ntohl(sin->sin_addr.s_addr);      // 把 IP 地址从网络字节序（大端）转成本机字节序（小端）
                /* 跳过 WSL2 内部NAT网段 198.18.0.0/15 */
                if ((ip & 0xFFFE0000) == 0xC6120000) continue;
                /* 跳过 169.254.x.x (自动配置/APIPA) */
                if ((ip & 0xFFFF0000) == 0xA9FE0000) continue;

                strncpy(dev, d->name, dev_len - 1);
                pcap_freealldevs(alldevs);  // 释放内存
                return 0;
            }
        }
    }

    /* 第二遍：放宽条件，选第一个非loopback且有IP的接口 */
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        if (d->flags & PCAP_IF_LOOPBACK) continue;
        if (d->addresses != NULL) {
            strncpy(dev, d->name, dev_len - 1);
            pcap_freealldevs(alldevs);
            return 0;
        }
    }

    /* 最后兜底：用第一个设备 */
    if (alldevs) {
        strncpy(dev, alldevs->name, dev_len - 1);
        pcap_freealldevs(alldevs);
        return 0;
    }

    pcap_freealldevs(alldevs);
    return -1;
}

/* ===== 通过路由表解析网卡 ===== */

/*
 * 查路由表确定到达目标IP应使用的网卡
 * Linux: 执行 ip route get <target_ip>，解析 dev <名称>
 * 如果 target_ip 为 NULL 或路由查询失败，回退到 get_default_device()
 */
int scanner_resolve_device(const char *target_ip, char *dev, int dev_len) {
    if (!dev || dev_len <= 0) return -1;
    dev[0] = '\0';

    /* 没有目标IP，直接用默认策略 */
    if (!target_ip || !target_ip[0]) {
        return get_default_device(dev, (size_t)dev_len);
    }

    /* 构造 ip route get 命令 */
    char cmd[256];
    int written = snprintf(cmd, sizeof(cmd), "ip route get %s 2>/dev/null", target_ip);
    if (written < 0 || (size_t)written >= sizeof(cmd)) {
        return get_default_device(dev, (size_t)dev_len);
    }

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        return get_default_device(dev, (size_t)dev_len);
    }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        /* 在输出中找 "dev <网卡名>" */
        char *p = strstr(line, " dev ");
        if (p) {
            p += 5;  /* 跳过 " dev " */
            /* 提取网卡名（到空格或换行/回车为止） */
            char *end = p;
            while (*end && *end != ' ' && *end != '\n' && *end != '\r')
                end++;
            size_t len = (size_t)(end - p);
            if (len > 0 && len < (size_t)dev_len) {
                memcpy(dev, p, len);
                dev[len] = '\0';
                found = 1;
                break;
            }
        }
    }
    pclose(fp);

    if (!found) {
        return get_default_device(dev, (size_t)dev_len);
    }

    /* 如果路由表指向了 loopback，改用默认策略 */
    if (strcmp(dev, "lo") == 0) {
        return get_default_device(dev, (size_t)dev_len);
    }

    return 0;
}

/* ===== 扫描器初始化 ===== */

scan_context_t *scanner_init(const char *device, char *errbuf) {
    scan_context_t *ctx = calloc(1, sizeof(scan_context_t));
    if (!ctx) {
        snprintf(errbuf, 256, "内存分配失败");
        return NULL;
    }

    /* 1. 确定网络接口 */
    if (device) {
        strncpy(ctx->device, device, sizeof(ctx->device) - 1);
    } else {
        if (get_default_device(ctx->device, sizeof(ctx->device)) != 0) {
            snprintf(errbuf, 256, "无法自动检测网络接口，请手动指定");
            free(ctx);
            return NULL;
        }
    }

    /* 2. 初始化 libnet (用于发送数据包) */
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];
    ctx->libnet_ctx = libnet_init(LIBNET_RAW4, ctx->device, libnet_errbuf);
    if (!ctx->libnet_ctx) {
        snprintf(errbuf, 256, "libnet初始化失败: %.230s", libnet_errbuf);
        free(ctx);
        return NULL;
    }

    /* 获取本机IP */
    ctx->src_ip = libnet_get_ipaddr4(ctx->libnet_ctx);
    if (ctx->src_ip == (uint32_t)-1) {
        snprintf(errbuf, 256, "无法获取本机IP地址");
        libnet_destroy(ctx->libnet_ctx);
        free(ctx);
        return NULL;
    }

    /* 3. 初始化 libpcap (用于捕获响应数据包) */
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    /* 打开 ctx->device 网卡，每个数据包最多捕获 65535 字节，开启混杂模式，超时时间 1s */
    /* 混杂模式：表示让网卡尽量接收经过它的其他数据包，而不仅仅是发给本机的数据包 */
    ctx->pcap_handle = pcap_open_live(ctx->device, 65535, 1, 1000, pcap_errbuf);
    if (!ctx->pcap_handle) {
        snprintf(errbuf, 256, "pcap_open_live失败: %.230s", pcap_errbuf);
        libnet_destroy(ctx->libnet_ctx);
        free(ctx);
        return NULL;
    }

    return ctx;
}


/* ===== 发送SYN探测包 ===== */

/*
 * 发送一个 TCP SYN 数据包到目标IP:端口
 * 返回: 使用的源端口号，失败返回 -1
 */
static int send_syn_packet(scan_context_t *ctx, uint32_t dst_ip,
                           uint16_t dst_port, uint16_t src_port) {
    /* 避免前一次构造留下的协议头或数据继续混入新包 */
    libnet_clear_packet(ctx->libnet_ctx);

    /* 使用随机序列号 */
    uint32_t seq = (uint32_t)rand() ^ ((uint32_t)time(NULL) << 16);

    /* 构建 TCP 头部：SYN标志，窗口大小1024 */
    libnet_ptag_t tcp_tag = libnet_build_tcp(
        src_port,        /* 源端口 */
        dst_port,        /* 目标端口 */
        seq,             /* 序列号 */
        0,               /* 确认号 (SYN包无ACK) */
        TH_SYN,          /* 控制标志: SYN */
        1024,            /* 窗口大小 */
        0,               /* 校验和 (0=自动计算) */
        0,               /* 紧急指针 */
        LIBNET_TCP_H,    /* TCP头部长度 (最小长度) */
        NULL,            /* 无负载 */
        0,               /* 负载长度 */
        ctx->libnet_ctx, /* libnet上下文 */
        0                /* 创建新的 TCP 协议块 */
    );

    if (tcp_tag == -1) {
        fprintf(stderr, "构建TCP头失败: %s\n", libnet_geterror(ctx->libnet_ctx));
        return -1;
    }

    /* 构建 IP 头部 */
    libnet_ptag_t ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H,  /* IP包总长度：IPv4 头部 20 字节 + TCP 头部 20 字节 = 40 字节 */
        0,                              /* TOS */
        0,                              /* IP标识 (0=自动) */
        0,                              /* 分段偏移 */
        64,                             /* TTL */
        IPPROTO_TCP,                    /* 上层协议：表明 IP 包内承载的是 TCP */
        0,                              /* 校验和 (0=自动计算) */
        ctx->src_ip,                    /* 源IP */
        dst_ip,                         /* 目标IP */
        NULL,                           /* 无负载 */
        0,                              /* 负载长度 */
        ctx->libnet_ctx,                /* libnet上下文 */
        0                               /* 新协议块 */
    );

    if (ip_tag == -1) {
        fprintf(stderr, "构建IP头失败: %s\n", libnet_geterror(ctx->libnet_ctx));
        return -1;
    }

    /* 发送数据包 */
    int bytes = libnet_write(ctx->libnet_ctx);
    if (bytes == -1) {
        fprintf(stderr, "发送数据包失败: %s\n", libnet_geterror(ctx->libnet_ctx));
        return -1;
    }

    return 0;
}



/* ===== 发送RST包 (收到SYN+ACK后断开半连接) ===== */

static int send_rst_packet(scan_context_t *ctx, const u_char *syn_ack_packet) {
    /*
     * 从收到的SYN+ACK包中提取信息来构造RST包
     * 注意：需要跳过以太网头和IP头，定位到TCP头
     */

    /* 以太网头 14字节 */
    struct libnet_ipv4_hdr *ip_hdr =
        (struct libnet_ipv4_hdr *)(syn_ack_packet + 14);
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    struct libnet_tcp_hdr *tcp_hdr =
        (struct libnet_tcp_hdr *)(syn_ack_packet + 14 + ip_hdr_len);

    libnet_clear_packet(ctx->libnet_ctx);

    /* RST包的序列号 = 收到的ACK号 */
    uint32_t seq = ntohl(tcp_hdr->th_ack);
    /* RST包的确认号 = 收到的SEQ号 + 1 (因为SYN占一个序号) */
    uint32_t ack = ntohl(tcp_hdr->th_seq) + 1;

    /* 构建RST包：目标端口 -> 我们的源端口 */
    libnet_build_tcp(
        ntohs(tcp_hdr->th_dport),   /* 源端口 (收到的目标端口) */
        ntohs(tcp_hdr->th_sport),   /* 目标端口 (收到的源端口) */
        seq,
        ack,
        TH_RST,                      /* RST标志 */
        0,
        0,                           /* 校验和自动 */
        0,
        LIBNET_TCP_H,
        NULL, 0,
        ctx->libnet_ctx, 0
    );

    libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H,
        0, 0, 0, 64,
        IPPROTO_TCP,
        0,                           /* 校验和自动 */
        ctx->src_ip,                 /* 本机IP */
        ip_hdr->ip_src.s_addr,       /* 目标IP (即收到的包的源IP) */
        NULL, 0,
        ctx->libnet_ctx, 0
    );

    libnet_write(ctx->libnet_ctx);
    return 0;
}

/* ===== 设置BPF过滤器 ===== */

static int set_pcap_filter(pcap_t *handle, const char *target_ip_str) {
    char filter[256];
    /*
     * BPF过滤器：只捕获从目标IP发来的TCP包
     * src host: 源主机 = 目标IP
     * tcp:      只捕获TCP协议
     */
    snprintf(filter, sizeof(filter), "src host %s and tcp", target_ip_str);

    /* 把人读的过滤规则编译成 libpcap 可以执行的过滤程序 */
    struct bpf_program fp;  // 编译后的过滤程序
    /* 0：不要求对编译结果进行优化 */
    /* PCAP_NETMASK_UNKNOWN：当前不知道网络掩码（对这条规则不需要掩码） */
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile失败: %s\n", pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter失败: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }

    pcap_freecode(&fp);
    return 0;
}

/* ===== 分析捕获到的响应包 ===== */

/*
 * 分析pcap捕获的TCP包，判断端口状态
 * 返回: PORT_OPEN / PORT_CLOSED / PORT_FILTERED
 */
static int analyze_response(const u_char *packet, uint16_t expected_dport) {
    /* 跳过以太网头 (14字节) */
    struct libnet_ipv4_hdr *ip = (struct libnet_ipv4_hdr *)(packet + 14);
    int ip_hdr_len = ip->ip_hl * 4;

    struct libnet_tcp_hdr *tcp =
        (struct libnet_tcp_hdr *)(packet + 14 + ip_hdr_len);

    /* 检查目标端口是否匹配 */
    if (ntohs(tcp->th_sport) != expected_dport)
        return PORT_FILTERED;

    uint8_t flags = tcp->th_flags;

    /*
     * TCP标志位含义:
     *   TH_SYN(0x02) + TH_ACK(0x10) = 0x12 → SYN+ACK → 端口开放
     *   TH_RST(0x04)                   = 0x04 → RST     → 端口关闭
     *   TH_RST(0x04) + TH_ACK(0x10)   = 0x14 → RST+ACK → 端口关闭
     */
    if ((flags & TH_SYN) && (flags & TH_ACK)) {
        return PORT_OPEN;   /* SYN+ACK: 端口开放 */
    }
    if (flags & TH_RST) {
        return PORT_CLOSED; /* RST或RST+ACK: 端口关闭 */
    }

    return PORT_FILTERED;
}

/* ===== 扫描指定端口列表 ===== */

int scanner_scan_ports(scan_context_t *ctx,
                       const char *target_ip_str,
                       const uint16_t *ports,
                       int n_ports,
                       int timeout_ms,
                       scan_callback_t callback,
                       scan_done_callback_t done_cb,
                       void *user_data,
                       scan_stats_t *stats_out,
                       char *errbuf)
{
    if (stats_out) { stats_out->ports_attempted = 0; stats_out->send_failures = 0; stats_out->completed = 0; }
    if (!ctx || !target_ip_str || !ports || n_ports <= 0) {
        if (errbuf) snprintf(errbuf, 256, "参数错误");
        return -1;
    }
    if (timeout_ms < 100) timeout_ms = 100;

    /* 转换IP为网络字节序 */
    uint32_t target_ip = inet_addr(target_ip_str);
    if (target_ip == INADDR_NONE) {
        if (errbuf) snprintf(errbuf, 256, "无效的目标IP: %s", target_ip_str);
        fprintf(stderr, "无效的目标IP: %s\n", target_ip_str);
        return -1;
    }

    /* 设置pcap过滤器，只捕获目标IP的TCP响应 */
    if (set_pcap_filter(ctx->pcap_handle, target_ip_str) != 0) {
        if (errbuf) snprintf(errbuf, 256, "设置抓包过滤器失败");
        return -1;
    }

    /* 初始化随机数种子 */
    srand((unsigned int)time(NULL) ^ (unsigned int)pthread_self());

    ctx->stop_flag = 0;
    int total_ports = n_ports;
    int scanned = 0;

    printf("\n========== TCP半连接扫描开始 ==========\n");
    printf("目标IP:   %s\n", target_ip_str);
    printf("本机IP:   %s\n", inet_ntoa(*(struct in_addr *)&ctx->src_ip));
    printf("接口:     %s\n", ctx->device);
    printf("端口数量: %d\n", total_ports);
    printf("超时时间: %dms\n", timeout_ms);
    printf("========================================\n\n");

    /* 逐端口扫描：发送SYN → 等待响应 → 分析结果 */
    for (int idx = 0; idx < n_ports; idx++) {
        if (ctx->stop_flag) break;

        uint16_t port = ports[idx];

        /* 使用随机源端口 (49152-65535 是动态/私有端口范围) */
        uint16_t src_port = 49152 + (rand() % 16384);

        if (stats_out) stats_out->ports_attempted++;

        /* 1. 发送 SYN 探测包 */
        if (send_syn_packet(ctx, target_ip, port, src_port) != 0) {
            if (stats_out) stats_out->send_failures++;
            fprintf(stderr, "发送SYN到端口 %u 失败\n", port);
            continue;
        }

        /* 2. 等待响应 */
        scan_result_t result = {0};
        result.port = port;
        result.status = PORT_FILTERED;  /* 默认：无响应/被过滤 */
        strncpy(result.service, scanner_get_service(port),
                sizeof(result.service) - 1);

        struct pcap_pkthdr *header;
        const u_char *packet;

        {
            int pcap_fd = pcap_get_selectable_fd(ctx->pcap_handle);
            time_t start_time = time(NULL);
            int poll_interval_ms = 50;

            while (time(NULL) - start_time < (timeout_ms / 1000) + 1) {
                if (ctx->stop_flag) break;
                fd_set rfds;
                struct timeval tv;
                FD_ZERO(&rfds);
                FD_SET(pcap_fd, &rfds);
                tv.tv_sec = 0;
                tv.tv_usec = poll_interval_ms * 1000;

                int sel_ret = select(pcap_fd + 1, &rfds, NULL, NULL, &tv);

                if (sel_ret > 0) {
                    int ret = pcap_next_ex(ctx->pcap_handle, &header, &packet);
                    if (ret == 1) {
                        int status = analyze_response(packet, port);
                        if (status != PORT_FILTERED) {
                            result.status = status;
                            if (status == PORT_OPEN) {
                                send_rst_packet(ctx, packet);
                            }
                            break;
                        }
                    } else if (ret == -1) {
                        fprintf(stderr, "pcap_next_ex错误: %s\n",
                                pcap_geterr(ctx->pcap_handle));
                        break;
                    }
                } else if (sel_ret == -1) {
                    fprintf(stderr, "select错误: %s\n", strerror(errno));
                    break;
                }
            }
        }



        /* 3. 输出结果到控制台 */
        const char *status_str[] = {"开放  ", "关闭  ", "无响应", "无响应(静默关闭)"};
        printf("[%5d/%5d] 端口 %5u: %s  (%s)\n",
               ++scanned, total_ports, port,
               status_str[result.status], result.service);

        /* 4. 通过回调通知上层 */
        if (callback) {
            callback(&result, user_data);
        }
    }

    if (stats_out) stats_out->completed = !ctx->stop_flag;

    printf("\n========== 扫描结束 ==========\n");

    /* 通知完成 */
    if (done_cb) {
        done_cb(user_data);
    }

    return 0;
}

/* ===== 主扫描函数（连续端口范围，保持向后兼容） ===== */

int scanner_scan(
    scan_context_t *ctx,
    const char *target_ip_str,
    uint16_t start_port,
    uint16_t end_port,
    int timeout_ms,
    scan_callback_t callback,
    scan_done_callback_t done_cb,
    void *user_data
) {
    if (!ctx || !target_ip_str) return -1;

    if (start_port < 1) start_port = 1;
    if (end_port < start_port) end_port = MAX_PORT;

    int n = (int)end_port - (int)start_port + 1;
    uint16_t *ports = malloc(sizeof(uint16_t) * (size_t)n);
    if (!ports) return -1;
    for (int i = 0; i < n; i++) ports[i] = (uint16_t)(start_port + i);

    int rc = scanner_scan_ports(ctx, target_ip_str, ports, n, timeout_ms,
                                callback, done_cb, user_data, NULL, NULL);
    free(ports);
    return rc;
}
/* ===== 停止与控制 ===== */

void scanner_stop(scan_context_t *ctx) {
    if (ctx) ctx->stop_flag = 1;
}

const char *scanner_get_device(scan_context_t *ctx) {
    return ctx ? ctx->device : NULL;
}

void scanner_cleanup(scan_context_t *ctx) {
    if (!ctx) return;
    if (ctx->pcap_handle)  pcap_close(ctx->pcap_handle);
    if (ctx->libnet_ctx)   libnet_destroy(ctx->libnet_ctx);
    free(ctx);
}