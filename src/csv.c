/*
 * csv.c - CSV 读写与端口策略导入解析
 */

#include "csv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ===== 基本 CSV 工具 ===== */

int csv_write_field(char *out, int outlen, const char *in) {
    if (outlen <= 0) return 0;
    int n = 0;
    if (!in) in = "";
    int need_quote = 0;
    for (const char *p = in; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') { need_quote = 1; break; }
    }
    if (need_quote) {
        if (n < outlen - 1) out[n++] = '"';
        for (const char *p = in; *p; p++) {
            if (*p == '"') { if (n < outlen - 2) { out[n++] = '"'; out[n++] = '"'; } }
            else           { if (n < outlen - 1) out[n++] = *p; }
        }
        if (n < outlen - 1) out[n++] = '"';
    } else {
        for (const char *p = in; *p && n < outlen - 1; p++) out[n++] = *p;
    }
    out[n] = '\0';
    return n;
}

/* 解析一行 CSV，支持引号字段（字段内可含逗号与 "" 转义） */
int csv_split_line(char *line, char **fields, int max_fields) {
    int nf = 0;
    char *p = line;
    if (max_fields <= 0 || !line) return 0;
    while (nf < max_fields) {
        while (*p == ' ' || *p == '\t') p++;
        char *start;
        if (*p == '"') {
            p++;
            start = p;
            char *w = p;
            while (*p) {
                if (*p == '"') {
                    if (*(p + 1) == '"') { *w++ = '"'; p += 2; continue; }
                    p++; break;
                }
                *w++ = *p++;
            }
            *w = '\0';
            fields[nf++] = start;
            while (*p && *p != ',') p++;
        } else {
            start = p;
            while (*p && *p != ',') p++;
            int had_comma = (*p == ',');
            if (had_comma) *p = '\0';
            char *e = start + strlen(start);
            while (e > start && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'))
                *--e = '\0';
            fields[nf++] = start;
            if (!had_comma) break;
            p++;
            continue;
        }
        if (*p == '\0') break;
        p++;
    }
    return nf;
}

char *csv_read_file(const char *path, long *len_out, char *err, int errlen) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        if (err) snprintf(err, errlen, "无法打开文件: %s", path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); if (err) snprintf(err, errlen, "读取失败"); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); if (err) snprintf(err, errlen, "内存不足"); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);
    if (rd >= 3 && (unsigned char)buf[0] == 0xEF &&
        (unsigned char)buf[1] == 0xBB && (unsigned char)buf[2] == 0xBF) {
        memmove(buf, buf + 3, rd - 3 + 1);
        rd -= 3;
    }
    if (len_out) *len_out = (long)rd;
    return buf;
}

/* ===== 端口策略导入解析 ===== */

static void trim(char *s) {
    if (!s) return;
    char *p = s;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\r' || s[n-1] == '\n'))
        s[--n] = '\0';
}

static int normalize_expected(const char *in, char *out, int outlen) {
    if (!in) return 0;
    if (strcmp(in, "开放") == 0 || strcasecmp(in, "open") == 0) {
        snprintf(out, outlen, "open"); return 1;
    }
    if (strcmp(in, "关闭") == 0 || strcasecmp(in, "closed") == 0) {
        snprintf(out, outlen, "closed"); return 1;
    }
    return 0;
}

static int valid_ipv4(const char *ip) {
    if (!ip || !*ip) return 0;
    int parts = 0;
    const char *p = ip;
    while (*p) {
        if (!isdigit((unsigned char)*p)) return 0;
        int val = 0, digits = 0;
        while (isdigit((unsigned char)*p)) {
            val = val * 10 + (*p - '0');
            digits++;
            p++;
            if (digits > 3) return 0;
        }
        if (val > 255) return 0;
        parts++;
        if (*p == '.') { p++; if (!*p) return 0; }
        else if (*p != '\0') return 0;
    }
    return parts == 4;
}

static void set_row_error(csv_policy_row_t *r, const char *msg) {
    if (!r->error[0]) snprintf(r->error, sizeof(r->error), "%s", msg);
}
int csv_parse_policy(const char *path, csv_policy_row_t **out, int *count,
                     char *err, int errlen) {
    *out = NULL; *count = 0;
    long len = 0;
    char *buf = csv_read_file(path, &len, err, errlen);
    if (!buf) return -1;

    int cap = 0, n = 0, lineno = 0;
    csv_policy_row_t *arr = NULL;
    int header_checked = 0;

    char *p = buf;
    while (p && *p) {
        char *nl = strchr(p, '\n');
        if (nl) *nl = '\0';
        char *line = p;
        lineno++;
        p = nl ? nl + 1 : NULL;

        trim(line);
        if (*line == '\0') continue;

        char *fields[10];
        int nf = csv_split_line(line, fields, 10);

        /* 跳过表头行（首行含“设备IP/ip”且第三列非数字） */
        if (!header_checked) {
            header_checked = 1;
            if (nf >= 1) {
                const char *f0 = fields[0];
                int looks_header = 0;
                if (strstr(f0, "设备") || strcasecmp(f0, "ip") == 0 ||
                    strcasecmp(f0, "device") == 0 || strstr(f0, "IP"))
                    looks_header = 1;
                int port_is_num = 0;
                if (nf >= 3 && fields[2][0]) {
                    char *endp = NULL;
                    long v = strtol(fields[2], &endp, 10);
                    if (endp && *endp == '\0' && v > 0) port_is_num = 1;
                }
                if (looks_header && !port_is_num) continue;
            }
        }

        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            csv_policy_row_t *t = realloc(arr, cap * sizeof(csv_policy_row_t));
            if (!t) { free(arr); free(buf); snprintf(err, errlen, "内存不足"); return -1; }
            arr = t;
        }
        csv_policy_row_t *r = &arr[n];
        memset(r, 0, sizeof(*r));
        r->lineno = lineno;

        if (nf < 4) {
            set_row_error(r, "列数不足（需 设备IP,设备名称,端口,预期状态[,用途说明]）");
            n++;
            continue;
        }

        snprintf(r->ip, sizeof(r->ip), "%s", fields[0]);
        snprintf(r->name, sizeof(r->name), "%s", fields[1]);
        snprintf(r->purpose, sizeof(r->purpose), "%s", nf >= 5 ? fields[4] : "");

        /* 端口 */
        char *endp = NULL;
        long port = strtol(fields[2], &endp, 10);
        int port_ok = (endp && *endp == '\0' && port >= 1 && port <= 65535);
        if (!port_ok) set_row_error(r, "端口非法（应为 1-65535 的整数）");
        else r->port = (int)port;

        /* 预期状态 */
        if (!normalize_expected(fields[3], r->expected, sizeof(r->expected)))
            set_row_error(r, "预期状态非法（应为 开放 或 关闭）");

        /* IP */
        if (!valid_ipv4(r->ip)) set_row_error(r, "设备IP 非法（第一阶段仅支持 IPv4）");

        /* 文件内重复（仅比较有效的 (IP,端口) 组合） */
        if (!r->error[0] && r->port > 0) {
            for (int i = 0; i < n; i++) {
                if (!arr[i].error[0] && arr[i].port == r->port &&
                    strcmp(arr[i].ip, r->ip) == 0) {
                    r->dup_in_file = 1;
                    break;
                }
            }
        }

        n++;
    }

    free(buf);
    *out = arr; *count = n;
    return 0;
}