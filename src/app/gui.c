/*
 * gui.c - 授权网络暴露面巡检与变化追踪工具 应用外壳
 *
 * 主界面为四个分页：
 *   设备 / 端口策略 / 巡检 / 记录
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
static GtkWidget *g_statusbar;      // 状态栏
static guint      g_status_ctx;     // 状态栏消息的上下文编号

/* ===== 状态栏 ===== */

void app_status(const char *fmt, ...) {
    char buf[512];
    va_list ap;                             // 创建参数读取器ap
    va_start(ap, fmt);                      // 从最后一个固定参数fmt后开始读取
    vsnprintf(buf, sizeof(buf), fmt, ap);   // 按fmt的格式把额外参数组合成文字写入buf
    va_end(ap);                             // 结束读取，清理ap
    if (!g_statusbar) return;
    gtk_statusbar_pop(GTK_STATUSBAR(g_statusbar), g_status_ctx);
    gtk_statusbar_push(GTK_STATUSBAR(g_statusbar), g_status_ctx, buf);
}

/* 
* ===== 通用对话框 ===== 
* parent：消息窗口所属的父窗口
* type：消息类型
* title：提示框标题
* msg：提示框正文
*/
static void show_msg(GtkWindow *parent, GtkMessageType type,
                     const char *title, const char *msg) {
    // 创建一个消息对话框：
    // GTK_DIALOG_MODAL 必须先处理这个对话框，才能操作父窗口
    // GTK_DIALOG_DESTROY_WITH_PARENT 父窗口关闭时，对话框也关闭
    // GTK_BUTTONS_OK 显示“确定”按钮
    GtkWidget *dlg = gtk_message_dialog_new(parent,
            GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
            type, GTK_BUTTONS_OK, "%s", msg);
    // 将对话框窗口标题设为 title
    gtk_window_set_title(GTK_WINDOW(dlg), title);
    // 显示对话框并等待用户响应
    gtk_dialog_run(GTK_DIALOG(dlg));
    // 销毁对话框
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

// 一个“是否”确认框，点击是返回1否返回0
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

/* 
* 给文件选择窗口增加文件类型筛选条件
* fc：要添加筛选条件的文件选择窗口
* name：筛选条件在窗口里的名称
* pattern：文件名匹配规则，比如 "*.csv"
*/
static void add_filter(GtkFileChooser *fc, const char *name, const char *pattern) {
    if (!name) return;
    GtkFileFilter *f = gtk_file_filter_new();               // 创建一个文件筛选器
    gtk_file_filter_set_name(f, name);                      // 设置筛选器在文件选择窗口中显示的名称
    if (pattern) gtk_file_filter_add_pattern(f, pattern);   // 添加匹配规则
    gtk_file_chooser_add_filter(fc, f);                     // 把筛选器添加到文件选择窗口
}

// 弹出文件选择窗口
char *ui_choose_open_file(GtkWindow *parent, const char *title,
                          const char *filter_name, const char *pattern) {
    // 创建一个打开文件窗口，标题是 title
    // 并添加取消和打开两个按钮
    // GTK_FILE_CHOOSER_ACTION_OPEN 选择已有文件
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title, parent, 
                                                GTK_FILE_CHOOSER_ACTION_OPEN,
                                                "取消", GTK_RESPONSE_CANCEL, "打开", GTK_RESPONSE_ACCEPT, NULL);
    add_filter(GTK_FILE_CHOOSER(dlg), filter_name, pattern);    // 把文件类型筛选器加到窗口里
    char *path = NULL;
    // 如果用户点打开，就取得所选文件的路径
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT)
        path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
    gtk_widget_destroy(dlg);
    return path;
}

// 弹出保存文件窗口
char *ui_choose_save_file(GtkWindow *parent, const char *title,
                          const char *default_name,
                          const char *filter_name, const char *pattern) {
    // GTK_FILE_CHOOSER_ACTION_SAVE 表示用户要指定保存位置和文件名
    GtkWidget *dlg = gtk_file_chooser_dialog_new(title, parent,
        GTK_FILE_CHOOSER_ACTION_SAVE,
        "取消", GTK_RESPONSE_CANCEL, "保存", GTK_RESPONSE_ACCEPT, NULL);
    // 如果目标文件已经存在，要求窗口提示用户确认是否覆盖
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dlg), TRUE);
    // 如果提供了默认文件名，就把它预先填入文件名输入框
    if (default_name) gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dlg), default_name);
    // 添加文件类型筛选器
    add_filter(GTK_FILE_CHOOSER(dlg), filter_name, pattern);
    char *path = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dlg)) == GTK_RESPONSE_ACCEPT)
        path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dlg));
    gtk_widget_destroy(dlg);
    return path;
}

// 把当前本地时间格式化写入buf
void app_timestamp_filename(char *buf, int len) {
    time_t t = time(NULL);
    struct tm tmv;
    localtime_r(&t, &tmv);  // 把t转成本地时间写入tmv
    strftime(buf, len, "%Y%m%d_%H%M%S", &tmv);  // 按指定格式生成字符串写入buf
}

/* ===== 巡检活动状态 ===== */

// 读取当前是否正在扫描
int app_scan_is_active(void) { return g_app.scan_active; }
// 修改当前是否正在扫描
void app_set_scan_active(int active) { g_app.scan_active = active; }

// 设备发生变化：通知策略页与巡检页刷新设备列表
void app_notify_devices_changed(void) {
    page_policies_reload_devices();
    page_scan_reload_devices();
}

/* ===== 主窗口 ===== */

// 窗口关闭回调函数
static gboolean on_window_delete(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)widget; (void)event; (void)data;
    if (app_scan_is_active()) page_scan_shutdown(); // 正在扫描就关闭
    gtk_main_quit();
    return FALSE;
}

// 创建应用主窗口
static void create_gui(void) {
    // 创建一个普通顶层窗口，并把地址保存到 g_app.window
    g_app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    // 设置窗口标题和默认大小
    gtk_window_set_title(GTK_WINDOW(g_app.window), "授权网络暴露面巡检与变化追踪");
    gtk_window_set_default_size(GTK_WINDOW(g_app.window), 1040, 700);
    // 窗口关闭事件连接到 on_window_delete
    g_signal_connect(g_app.window, "delete-event", G_CALLBACK(on_window_delete), NULL);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(g_app.window), vbox);   // 把vbox放进主窗口

    // g_app.notebook：要放进去的标签页区域
    // 第一个 TRUE：允许它扩展，占用多余空间
    // 第二个 TRUE：扩展时让它填满分配到的空间
    // 0：控件周围额外不留间距
    g_app.notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), g_app.notebook, TRUE, TRUE, 0);
    // 把页面加进标签控件，具体内容由对应的 page_*_build() 函数创建
    gtk_notebook_append_page(GTK_NOTEBOOK(g_app.notebook),
        page_devices_build(), gtk_label_new("设备"));
    gtk_notebook_append_page(GTK_NOTEBOOK(g_app.notebook),
        page_policies_build(), gtk_label_new("端口策略"));
    gtk_notebook_append_page(GTK_NOTEBOOK(g_app.notebook),
        page_scan_build(), gtk_label_new("巡检"));
    gtk_notebook_append_page(GTK_NOTEBOOK(g_app.notebook),
        page_records_build(), gtk_label_new("记录"));

    // 创建状态栏控件
    g_statusbar = gtk_statusbar_new();
    // 向GTK取得一个编号
    g_status_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(g_statusbar), "main");
    // 把状态栏放在垂直布局底部。两个 FALSE 表示不扩展、不占用额外空间
    gtk_box_pack_end(GTK_BOX(vbox), g_statusbar, FALSE, FALSE, 0);
    app_status("就绪");     // 状态栏显示就绪

    gtk_widget_show_all(g_app.window);  // 显示主窗口和其中所有控件
}

/* ===== 入口 ===== */

int gui_run(int argc, char **argv) {
    gtk_init(&argc, &argv);

    char err[256];
    // 把默认数据库路径写进g_app.db_path
    db_default_path(g_app.db_path, sizeof(g_app.db_path));
    // 打开数据库
    if (db_open(g_app.db_path, &g_app.db, err, sizeof(err)) != 0) {
        ui_error(NULL, "无法打开数据库:\n%s\n路径: %s", err, g_app.db_path);
        return 1;
    }
    // 初始化数据库结构
    if (db_init_schema(g_app.db, err, sizeof(err)) != 0) {
        ui_error(NULL, "数据库初始化失败:\n%s", err);
        db_close(g_app.db);
        return 1;
    }

    create_gui();
    gtk_main();     // 开始GTK的事件循环，调用gtk_main_quit()后这个函数才会结束

    if (app_scan_is_active()) page_scan_shutdown();
    db_close(g_app.db);
    return 0;
}

