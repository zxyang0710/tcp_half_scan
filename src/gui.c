/*
 * gui.c - 授权网络暴露面巡检与变化追踪工具 应用外壳
 *
 * 主界面为四个分页（GtkNotebook）：
 *   设备 / 端口策略 / 巡检 / 记录
 *
 * 本文件只负责：初始化 SQLite、搭建主窗口与导航、提供跨页面通用工具。
 * 各分页实现在 page_*.c。
 */

#include "gui.h"
#include "app.h"
#include "db.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

app_t g_app;
static GtkWidget *g_statusbar;
static guint      g_status_ctx;

/* ===== 显示文案 ===== */

const char *status_label(const char *s) {
    if (!s) return "未知";
    if (strcmp(s, RUN_RUNNING) == 0)   return "进行中";
    if (strcmp(s, RUN_COMPLETED) == 0) return "已完成";
    if (strcmp(s, RUN_STOPPED) == 0)   return "已停止/未完成";
    if (strcmp(s, RUN_FAILED) == 0)    return "失败";
    if (strcmp(s, RUN_PENDING) == 0)   return "待执行";
    return s;
}

const char *mode_label(const char *m) {
    if (!m) return "";
    if (strcmp(m, MODE_POLICY) == 0) return "按端口策略";
    if (strcmp(m, MODE_RANGE) == 0)  return "完整端口范围";
    return m;
}

const char *actual_label(const char *a) {
    if (!a) return "";
    if (strcmp(a, ST_OPEN) == 0)     return "开放";
    if (strcmp(a, ST_CLOSED) == 0)   return "关闭";
    if (strcmp(a, ST_FILTERED) == 0) return "无响应/被过滤";
    if (strncmp(a, "filtered", 8) == 0 && strstr(a, "host") != NULL)
        return "无响应/被过滤（主机可达）";
    if (strcmp(a, ST_FILTERED_REACHABLE) == 0)
        return "无响应/被过滤（主机可达）";
    return a;
}

const char *expected_label(const char *e) {
    if (!e || !*e) return "未设策略";
    if (strcmp(e, EXP_OPEN) == 0)   return "开放";
    if (strcmp(e, EXP_CLOSED) == 0) return "关闭";
    return e;
}

/* ===== 状态栏 ===== */

void app_status(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (!g_statusbar) return;
    gtk_statusbar_pop(GTK_STATUSBAR(g_statusbar), g_status_ctx);
    gtk_statusbar_push(GTK_STATUSBAR(g_statusbar), g_status_ctx, buf);
}

/* ===== 通用对话框 ===== */

static void show_msg(GtkWindow *parent, GtkMessageType type,
                     const char *title, const char *msg) {
    GtkWidget *dlg = gtk_message_dialog_new(parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        type, GTK_BUTTONS_OK, "%s", msg);
    gtk_window_set_title(GTK_WINDOW(dlg), title);
    gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
}

void ui_error(GtkWindow *parent, const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    show_msg(parent, GTK_MESSAGE_ERROR, "错误", buf);
}

void ui_info(GtkWindow *parent, const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    show_msg(parent, GTK_MESSAGE_INFO, "提示", buf);
}

int ui_confirm(GtkWindow *parent, const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    GtkWidget *dlg = gtk_message_dialog_new(parent,
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO, "%s", buf);
    gtk_window_set_title(GTK_WINDOW(dlg), "请确认");
    int resp = gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
    return resp == GTK_RESPONSE_YES;
}

static void add_filter(GtkFileChooser *fc, const char *name, const char *pattern) {
    if (!name) return;
    GtkFileFilter *f = gtk_file_filter_new();
    gtk_file_filter_set_name(f, name);
    if (pattern) gtk_file_filter_add_pattern(f, pattern);
    gtk_file_chooser_add_filter(fc, f);
}

char *ui_choose_open_file(GtkWindow *parent, const char *title,
                          const char *filter_name, const char *pattern) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title, parent,
        GTK_FILE_CHOOSER_ACTION_OPEN,
        "取消", GTK_RESPONSE_CANCEL, "打开", GTK_RESPONSE_ACCEPT, NULL);
    add_filter(GTK_FILE_CHOOSER(dlg), filter_name, pattern);
    char *path = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT)
        path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
    gtk_widget_destroy(dlg);
    return path;
}

char *ui_choose_save_file(GtkWindow *parent, const char *title,
                          const char *default_name,
                          const char *filter_name, const char *pattern) {
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title, parent,
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "取消", GTK_RESPONSE_CANCEL, "保存", GTK_RESPONSE_ACCEPT, NULL);
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    if (default_name) gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), default_name);
    add_filter(GTK_FILE_CHOOSER(dlg), filter_name, pattern);
    char *path = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT)
        path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
    gtk_widget_destroy(dlg);
    return path;
}

void app_timestamp_filename(char *buf, int len) {
    time_t t = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    strftime(buf, len, "%Y%m%d_%H%M%S", &tmv);
}
/* ===== 巡检活动状态 ===== */

int app_scan_is_active(void) { return g_app.scan_active; }
void app_set_scan_active(int active) { g_app.scan_active = active; }

/* 设备发生变化：通知策略页与巡检页刷新设备列表 */
void app_notify_devices_changed(void) {
    page_policies_reload_devices();
    page_scan_reload_devices();
}

/* ===== 主窗口 ===== */

static gboolean on_window_delete(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)widget; (void)event; (void)data;
    if (app_scan_is_active())
        page_scan_shutdown();
    gtk_main_quit();
    return FALSE;
}

static void create_gui(void) {
    g_app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(g_app.window),
                         "授权网络暴露面巡检与变化追踪");
    gtk_window_set_default_size(GTK_WINDOW(g_app.window), 1040, 700);
    g_signal_connect(g_app.window, "delete-event",
                     G_CALLBACK(on_window_delete), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(g_app.window), vbox);

    g_app.notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), g_app.notebook, TRUE, TRUE, 0);

    gtk_notebook_append_page(GTK_NOTEBOOK(g_app.notebook),
        page_devices_build(), gtk_label_new("设备"));
    gtk_notebook_append_page(GTK_NOTEBOOK(g_app.notebook),
        page_policies_build(), gtk_label_new("端口策略"));
    gtk_notebook_append_page(GTK_NOTEBOOK(g_app.notebook),
        page_scan_build(), gtk_label_new("巡检"));
    gtk_notebook_append_page(GTK_NOTEBOOK(g_app.notebook),
        page_records_build(), gtk_label_new("记录"));

    g_statusbar = gtk_statusbar_new();
    g_status_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(g_statusbar), "main");
    gtk_box_pack_end(GTK_BOX(vbox), g_statusbar, FALSE, FALSE, 0);
    app_status("就绪");

    gtk_widget_show_all(g_app.window);
    /* 巡检页初始无扫描，隐藏停止按钮等由各页自理 */
}

/* ===== 入口 ===== */

int gui_run(int argc, char **argv) {
    gtk_init(&argc, &argv);

    char err[256];
    db_default_path(g_app.db_path, sizeof(g_app.db_path));
    if (db_open(g_app.db_path, &g_app.db, err, sizeof(err)) != 0) {
        ui_error(NULL, "无法打开数据库:\n%s\n路径: %s", err, g_app.db_path);
        return 1;
    }
    if (db_init_schema(g_app.db, err, sizeof(err)) != 0) {
        ui_error(NULL, "数据库初始化失败:\n%s", err);
        db_close(g_app.db);
        return 1;
    }

    create_gui();
    gtk_main();

    if (app_scan_is_active())
        page_scan_shutdown();
    db_close(g_app.db);
    return 0;
}
/* 校验 IPv4 点分十进制地址 */
int util_valid_ipv4(const char *ip) {
    if (!ip || !*ip) return 0;
    int parts = 0;
    const char *p = ip;
    while (*p) {
        if (*p < '0' || *p > '9') return 0;
        int val = 0, digits = 0;
        while (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p - '0');
            digits++; p++;
            if (digits > 3) return 0;
        }
        if (val > 255) return 0;
        parts++;
        if (*p == '.') { p++; if (!*p) return 0; }
        else if (*p != '\0') return 0;
    }
    return parts == 4;
}
