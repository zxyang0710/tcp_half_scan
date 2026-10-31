/* 文件选择和导出反馈；CSV 内容由无 GTK 依赖的导出模块生成。 */
#include "app.h"
#include "records_service.h"
#include <stdio.h>
int export_records_csv(GtkWindow *parent, const int *scan_ids, int n_ids) {
    if (!scan_ids || n_ids <= 0) return -1;

    char ts[32];
    app_timestamp_filename(ts, sizeof(ts));
    char defname[128];
    snprintf(defname, sizeof(defname), "巡检记录_%s.csv", ts);

    char *path = ui_choose_save_file(parent, "导出巡检记录 CSV",
                                     defname, "CSV 文件", "*.csv");
    if (!path) return 0;   /* 用户取消 */

    long written = 0;
    char err[512];
    int rc = records_export_csv(g_app.db, path, scan_ids, n_ids, &written, err, sizeof(err));
    if (rc != 0) ui_error(parent, "%s", err);
    else {
        ui_info(parent, "导出完成，共 %ld 条结果行。\n文件：\n%s", written, path);
        app_status("已导出巡检记录 CSV（%ld 行）", written);
    }
    g_free(path);
    return rc;
}
