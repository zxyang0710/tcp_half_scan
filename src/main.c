/*
 * main.c - TCP半连接端口扫描器 主入口
 *
 * 用法:
 *   图形模式:  ./tcp_scanner
 *   命令行模式: ./tcp_scanner -c <目标IP> [起始端口] [结束端口] [超时ms]
 *   示例:      ./tcp_scanner -c 192.168.1.1 1 1024 2000
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "gui.h"
#include "scanner.h"

static void print_usage(const char *prog) {
    printf("TCP半连接端口扫描器\n");
    printf("用法:\n");
    printf("  图形模式:  %s\n", prog);
    printf("  命令行模式: %s -c <目标IP> [起始端口] [结束端口] [超时ms] [-d 网卡]\n", prog);
    printf("  帮助:      %s -h\n", prog);
    printf("\n示例:\n");
    printf("  %s                             # 启动图形界面\n", prog);
    printf("  %s -c 192.168.1.1              # 扫描1-1024端口\n", prog);
    printf("  %s -c 192.168.1.1 80 443 1000  # 扫描80-443端口，超时1秒\n", prog);
}

int main(int argc, char **argv) {
    /* 检查是否为命令行模式 */
    if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
        /* ===== 命令行模式 ===== */
        const char *target_ip = argv[2];   // 目标IP，必填
        const char *device    = NULL;      // 网卡名，自动检测
        int start_port        = 1;         // 起始端口，默认 1
        int end_port          = 1024;      // 结束端口，默认 1024
        int timeout_ms        = 2000;      // 超时，默认 2000 毫秒
        int arg_idx = 3;                   // 游标，从 argv[3] 开始读

        /* 解析可选参数: -d <网卡> 或 位置参数 */
        while (arg_idx < argc) {
            if (strcmp(argv[arg_idx], "-d") == 0 && arg_idx + 1 < argc) {
                device = argv[++arg_idx];
            } else if (start_port == 1 && arg_idx == 3) {
                start_port = atoi(argv[arg_idx]);
            } else if (end_port == 1024 && arg_idx == 4) {
                end_port = atoi(argv[arg_idx]);
            } else if (timeout_ms == 2000 && arg_idx == 5) {
                timeout_ms = atoi(argv[arg_idx]);
            }
            arg_idx++;
        }

        if (start_port < 1) start_port = 1;
        if (start_port > 65535) start_port = 65535;
        if (end_port < 1) end_port = 1;
        if (end_port > 65535) end_port = 65535;
        if (end_port < start_port) end_port = start_port;
        if (timeout_ms < 100) timeout_ms = 100;

        char errbuf[256];
        /* 初始化扫描器 */
        scan_context_t *ctx = scanner_init(device, errbuf);
        if (!ctx) {
            fprintf(stderr, "初始化失败: %s\n", errbuf);
            return 1;
        }

        int ret = scanner_scan(ctx, target_ip, (uint16_t)start_port, (uint16_t)end_port,
                               timeout_ms, NULL, NULL, NULL);
        scanner_cleanup(ctx);
        return ret;

    } else if (argc >= 2 && strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* ===== 图形模式（默认） ===== */
    printf("启动图形界面...\n");
    return gui_run(argc, argv);
}

