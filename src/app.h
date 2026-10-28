/*
 * app.h - 应用外壳与跨页面共享接口
 */

#ifndef APP_H
#define APP_H

#include <gtk/gtk.h>
#include "sqlite3.h"

/* 全局应用状态 */
typedef struct {
    sqlite3   *db;          /* 主线程数据库连接 */
    char       db_path[1024];
    GtkWidget *window;
    GtkWidget *notebook;
    int        scan_active; /* 是否有巡检正在运行 */
    guint      status_ctx;  /* 状态栏 context */
} app_t;

extern app_t g_app;

/* 构建四个页面 */
GtkWidget *page_devices_build(void);
GtkWidget *page_policies_build(void);
GtkWidget *page_scan_build(void);
GtkWidget *page_records_build(void);

/* 跨页面刷新 */
void page_policies_reload_devices(void);
void page_scan_reload_devices(void);
void page_records_reload(void);
void app_notify_devices_changed(void);

/* 巡检状态（用于窗口关闭时收尾） */
int  app_scan_is_active(void);
void app_set_scan_active(int active);
void page_scan_shutdown(void);

/* 状态栏 */
void app_status(const char *fmt, ...);

/* 通用对话框 */
void ui_error(GtkWindow *parent, const char *fmt, ...);
void ui_info(GtkWindow *parent, const char *fmt, ...);
int  ui_confirm(GtkWindow *parent, const char *fmt, ...);
char *ui_choose_open_file(GtkWindow *parent, const char *title, const char *filter_name, const char *pattern);
char *ui_choose_save_file(GtkWindow *parent, const char *title, const char *default_name, const char *filter_name, const char *pattern);

/* 显示文案转换 */
const char *status_label(const char *status);
const char *mode_label(const char *mode);
const char *actual_label(const char *actual);
const char *expected_label(const char *expected);

/* 校验 IPv4 点分十进制 */
int util_valid_ipv4(const char *ip);

/* 文件名用时间戳 */
void app_timestamp_filename(char *buf, int len);

/* CSV 导出（记录列表 / 单次记录） */
int export_records_csv(GtkWindow *parent, const int *scan_ids, int n_ids);

#endif /* APP_H */