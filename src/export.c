/*
 * export.c - 巡检记录 CSV 导出
 *
 * 输出 UTF-8（带 BOM），标准 CSV 转义，每行对应一个设备的一条已扫描端口结果。
 * 字段：巡检记录ID,巡检时间,设备名称快照,设备IP快照,巡检模式,扫描范围,
 *       端口,协议,服务,实际状态,策略预期,策略判断,与上次状态的变化,任务完成状态
 */

#include "app.h"
#include "db.h"
#include "csv.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 与上次状态的变化（与 page_records.c 保持一致） */
static void compare_change(const char *prev, int has_prev, const char *now,
                           char *out, int outlen) {
    if (!has_prev)              { snprintf(out, outlen, "无法比较（上次未检查）"); return; }
    if (strcmp(prev, now) == 0) { snprintf(out, outlen, "状态未变"); return; }
    if (strcmp(prev, ST_OPEN) == 0 && strcmp(now, ST_CLOSED) == 0)
        { snprintf(out, outlen, "开放变关闭"); return; }
    if (strcmp(prev, ST_CLOSED) == 0 && strcmp(now, ST_OPEN) == 0)
        { snprintf(out, outlen, "关闭变开放"); return; }
    if (strcmp(prev, ST_FILTERED) == 0 && strcmp(now, ST_OPEN) == 0)
        { snprintf(out, outlen, "上次无响应，本次开放"); return; }
    if (strcmp(prev, ST_FILTERED) == 0 && strcmp(now, ST_CLOSED) == 0)
        { snprintf(out, outlen, "上次无响应，本次关闭"); return; }
    if (strcmp(now, ST_FILTERED) == 0)
        { snprintf(out, outlen, "无法确认（本次无响应）"); return; }
    snprintf(out, outlen, "状态未变");
}

static void write_row(FILE *fp, const char **fields, int n) {
    char tmp[1024];
    for (int i = 0; i < n; i++) {
        if (i) fputc(',', fp);
        csv_write_field(tmp, sizeof(tmp), fields[i] ? fields[i] : "");
        fputs(tmp, fp);
    }
    fputs("\r\n", fp);
}

int export_records_csv(GtkWindow *parent, const int *scan_ids, int n_ids) {
    if (!scan_ids || n_ids <= 0) return -1;

    char ts[32];
    app_timestamp_filename(ts, sizeof(ts));
    char defname[128];
    snprintf(defname, sizeof(defname), "巡检记录_%s.csv", ts);

    char *path = ui_choose_save_file(parent, "导出巡检记录 CSV",
                                     defname, "CSV 文件", "*.csv");
    if (!path) return 0;   /* 用户取消 */

    FILE *fp = fopen(path, "wb");
    if (!fp) {
        ui_error(parent, "无法写入文件：\n%s", path);
        g_free(path);
        return -1;
    }

    /* UTF-8 BOM，便于表格软件正确识别中文 */
    fputs("\xEF\xBB\xBF", fp);

    const char *hdr[14] = {
        "巡检记录ID", "巡检时间", "设备名称快照", "设备IP快照",
        "巡检模式", "扫描范围", "端口", "协议", "服务",
        "实际状态", "策略预期", "策略判断", "与上次状态的变化", "任务完成状态"
    };
    write_row(fp, hdr, 14);

    long rows_written = 0;
    for (int i = 0; i < n_ids; i++) {
        scan_summary_t s;
        if (db_scan_get(g_app.db, scan_ids[i], &s) != 1) continue;

        scan_device_t *devs = NULL; int nd = 0;
        if (db_scan_devices(g_app.db, scan_ids[i], &devs, &nd) != 0) continue;

        for (int j = 0; j < nd; j++) {
            scan_device_t *d = &devs[j];

            int prev_sd = 0;
            db_prev_complete_scan_device(g_app.db, s.id, d->device_id, d->ip, &prev_sd);
            scan_result_row_t *prows = NULL; int pn = 0;
            if (prev_sd > 0) db_scan_results(g_app.db, prev_sd, &prows, &pn);

            scan_result_row_t *rows = NULL; int nr = 0;
            db_scan_results(g_app.db, d->id, &rows, &nr);

            char range[64];
            if (d->range_start > 0 || d->range_end > 0)
                snprintf(range, sizeof(range), "%d-%d", d->range_start, d->range_end);
            else
                snprintf(range, sizeof(range), "按策略端口");

            char idbuf[16];
            snprintf(idbuf, sizeof(idbuf), "%d", s.id);

            for (int k = 0; k < nr; k++) {
                scan_result_row_t *rw = &rows[k];
                const char *prev_actual = NULL;
                for (int p = 0; p < pn; p++)
                    if (prows[p].port == rw->port) { prev_actual = prows[p].actual; break; }
                char chg[64];
                compare_change(prev_actual, prev_actual != NULL, rw->actual, chg, sizeof(chg));

                char portbuf[16];
                snprintf(portbuf, sizeof(portbuf), "%d", rw->port);

                const char *f[14] = {
                    idbuf, s.started_at, d->name, d->ip,
                    mode_label(s.mode), range, portbuf, rw->protocol,
                    rw->service, actual_label(rw->actual),
                    expected_label(rw->expected), rw->verdict, chg,
                    status_label(d->status)
                };
                write_row(fp, f, 14);
                rows_written++;
            }

            db_free(rows);
            db_free(prows);
        }
        db_free(devs);
    }

    if (fclose(fp) != 0) {
        ui_error(parent, "写入文件时出错：\n%s", path);
        g_free(path);
        return -1;
    }

    ui_info(parent, "导出完成，共 %ld 条结果行。\n文件：\n%s", rows_written, path);
    app_status("已导出巡检记录 CSV（%ld 行）", rows_written);
    g_free(path);
    return 0;
}