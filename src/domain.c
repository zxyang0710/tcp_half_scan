#include "domain.h"
#include "db.h"
#include <stdio.h>
#include <string.h>

const char *status_label(const char *s) {
    if (!s) return "未知";
    if (strcmp(s, RUN_RUNNING) == 0) return "进行中";
    if (strcmp(s, RUN_COMPLETED) == 0) return "已完成";
    if (strcmp(s, RUN_STOPPED) == 0) return "已停止/未完成";
    if (strcmp(s, RUN_FAILED) == 0) return "失败";
    if (strcmp(s, RUN_PENDING) == 0) return "待执行";
    return s;
}
const char *mode_label(const char *m) {
    if (!m) return "";
    if (strcmp(m, MODE_POLICY) == 0) return "按端口策略";
    if (strcmp(m, MODE_RANGE) == 0) return "完整端口范围";
    return m;
}
const char *actual_label(const char *a) {
    if (!a) return "";
    if (strcmp(a, ST_OPEN) == 0) return "开放";
    if (strcmp(a, ST_CLOSED) == 0) return "关闭";
    if (strcmp(a, ST_FILTERED) == 0) return "无响应/被过滤";
    if (strcmp(a, ST_FILTERED_REACHABLE) == 0) return "无响应/被过滤（主机可达）";
    return a;
}
const char *expected_label(const char *e) {
    if (!e || !*e) return "未设策略";
    if (strcmp(e, EXP_OPEN) == 0) return "开放";
    if (strcmp(e, EXP_CLOSED) == 0) return "关闭";
    return e;
}
int util_valid_ipv4(const char *ip) {
    if (!ip || !*ip) return 0;
    int parts = 0;
    const char *p = ip;
    while (*p) {
        if (*p < '0' || *p > '9') return 0;
        int val = 0, digits = 0;
        while (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p++ - '0');
            if (++digits > 3) return 0;
        }
        if (val > 255) return 0;
        ++parts;
        if (*p == '.') { if (!*++p) return 0; }
        else if (*p) return 0;
    }
    return parts == 4;
}
void domain_compute_verdict(int range_mode, const char *actual,
                            const char *expected, char *out, int outlen) {
    if (!out || outlen <= 0) return;
    if (expected && *expected) {
        if (strcmp(expected, EXP_OPEN) == 0) {
            if (strcmp(actual, ST_OPEN) == 0) snprintf(out, outlen, "符合预期");
            else if (strcmp(actual, ST_CLOSED) == 0) snprintf(out, outlen, "未达到预期");
            else snprintf(out, outlen, "未达到预期（无响应）");
        } else {
            if (strcmp(actual, ST_CLOSED) == 0) snprintf(out, outlen, "符合预期");
            else if (strcmp(actual, ST_OPEN) == 0) snprintf(out, outlen, "不符合预期");
            else snprintf(out, outlen, "无法确认（无响应）");
        }
    } else if (range_mode && strcmp(actual, ST_OPEN) == 0)
        snprintf(out, outlen, "未设策略的开放端口");
    else snprintf(out, outlen, "未设策略");
}
void domain_compare_change(const char *previous, int has_previous,
                           const char *current, char *out, int outlen) {
    if (!out || outlen <= 0) return;
    if (!has_previous) { snprintf(out, outlen, "无法比较（上次未检查）"); return; }
    if (!previous || !current) { snprintf(out, outlen, "状态未变"); return; }
    if (strcmp(previous, current) == 0) { snprintf(out, outlen, "状态未变"); return; }
    if (strcmp(previous, ST_OPEN) == 0 && strcmp(current, ST_CLOSED) == 0)
        { snprintf(out, outlen, "开放变关闭"); return; }
    if (strcmp(previous, ST_CLOSED) == 0 && strcmp(current, ST_OPEN) == 0)
        { snprintf(out, outlen, "关闭变开放"); return; }
    if (strcmp(previous, ST_FILTERED) == 0 && strcmp(current, ST_OPEN) == 0)
        { snprintf(out, outlen, "上次无响应，本次开放"); return; }
    if (strcmp(previous, ST_FILTERED) == 0 && strcmp(current, ST_CLOSED) == 0)
        { snprintf(out, outlen, "上次无响应，本次关闭"); return; }
    if (strcmp(current, ST_FILTERED) == 0)
        { snprintf(out, outlen, "无法确认（本次无响应）"); return; }
    snprintf(out, outlen, "状态未变");
}
