/*
 * page_devices.c - 设备页：设备信息增删改查
 */

#include "app.h"
#include "db.h"
#include "device_service.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static GtkWidget    *d_tree;    // 表格控件，负责处理交互
static GtkListStore *d_store;   // 设备表格，用来保存信息
static GtkWidget    *d_search;  // 输入框

// 表格的每一列编号
enum { D_ID, D_NAME, D_IP, D_NOTE, D_UPDATED, D_N };

// 读取搜索框内容
static const char *cur_search(void) {
    const char *q = gtk_entry_get_text(GTK_ENTRY(d_search));
    return (q && *q) ? q : "";
}

// 从数据库重新读取设备列表，按搜索框内容筛选
static void devices_reload(void) {
    gtk_list_store_clear(d_store);      // 清空表格数据
    device_t *arr = NULL; int n = 0;    // 接收数据库结果arr，设备数量n
    if (db_device_list(g_app.db, &arr, &n) != 0) return;
    const char *q = cur_search();
    for (int i = 0; i < n; i++) {
        // 不符合搜索条件就跳过
        if (*q && !strstr(arr[i].name, q) && !strstr(arr[i].ip, q) &&
            !strstr(arr[i].note, q))
            continue;
        // 为表格添加一行
        GtkTreeIter it;
        gtk_list_store_append(d_store, &it);
        gtk_list_store_set(d_store, &it,
                           D_ID, arr[i].id,
                           D_NAME, arr[i].name,
                           D_IP, arr[i].ip,
                           D_NOTE, arr[i].note,
                           D_UPDATED, arr[i].updated_at,
                           -1);
    }
    db_free(arr);
}

// 取得用户在设备表格中选中的那一行的 ID
static int selected_id(void) {
    // 获取当前选中项的对象
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(d_tree));
    // m：表格背后的数据模型
    // it：指向模型中某一行的位置，类似当前行的游标
    GtkTreeModel *m; GtkTreeIter it;
    // 检查是否有选中行。如果有，把数据模型写入m，把选中行的位置写入it
    if (gtk_tree_selection_get_selected(sel, &m, &it)) {
        int id = 0;
        gtk_tree_model_get(m, &it, D_ID, &id, -1);
        return id;
    }
    return 0;
}

/* 新增 / 编辑对话框；edit_id>0 为编辑 */
static void device_dialog(int edit_id) {
    device_t d;
    memset(&d, 0, sizeof(d));
    if (edit_id > 0) {
        if (db_device_get(g_app.db, edit_id, &d) != 1) {
            ui_error(GTK_WINDOW(g_app.window), "找不到该设备（可能已被删除）");
            return;
        }
    }

    // 创建一个“新增、编辑设备”的对话框，设置默认大小
    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        edit_id > 0 ? "编辑设备" : "新增设备",
        GTK_WINDOW(g_app.window),   // 父窗口
        // GTK_DIALOG_MODAL：对话框打开时，先处理它才能操作主窗口
        // GTK_DIALOG_DESTROY_WITH_PARENT：主窗口关闭时，这个对话框也关闭
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "取消", GTK_RESPONSE_CANCEL, "保存", GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 420, -1);

    // 取得对话框 dlg 里专门放内容的区域，保存到 ca
    GtkWidget *ca = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *grid = gtk_grid_new();                           // 创建网格布局控件
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);                // 设置网格不同行之间留8像素
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);             // 设置网格不同列之间留 8 像素
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);    // 设置网格内部边缘的留白为 10 像素
    gtk_container_add(GTK_CONTAINER(ca), grid);                 // 把网格放进对话框的内容区域

    GtkWidget *l1 = gtk_label_new("设备名称*:");            // 创建文字标签
    gtk_widget_set_halign(l1, GTK_ALIGN_END);               // 让标签在分配给它的空间里靠右对齐
    GtkWidget *e_name = gtk_entry_new();                    // 创建单行文本输入框
    gtk_entry_set_text(GTK_ENTRY(e_name), d.name);          // 把 d.name 的内容放进输入框，作为初始值
    gtk_grid_attach(GTK_GRID(grid), l1, 0, 0, 1, 1);        // 把两个控件放进 grid 的第 0 行
    gtk_grid_attach(GTK_GRID(grid), e_name, 1, 0, 1, 1);

    GtkWidget *l2 = gtk_label_new("IP 地址*:");
    gtk_widget_set_halign(l2, GTK_ALIGN_END);
    GtkWidget *e_ip = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(e_ip), "例如: 192.168.1.20");
    gtk_entry_set_text(GTK_ENTRY(e_ip), d.ip);
    gtk_grid_attach(GTK_GRID(grid), l2, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), e_ip, 1, 1, 1, 1);

    GtkWidget *l3 = gtk_label_new("备注:");
    gtk_widget_set_halign(l3, GTK_ALIGN_END);
    GtkWidget *e_note = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(e_note), d.note);
    gtk_grid_attach(GTK_GRID(grid), l3, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), e_note, 1, 2, 1, 1);

    gtk_widget_show_all(dlg);

    (void)e_note;
    for (;;) {
        // 显示对话框并等待操作
        int resp = gtk_dialog_run(GTK_DIALOG(dlg));
        if (resp != GTK_RESPONSE_OK) break;
        // 读取输入框内容
        const char *name = gtk_entry_get_text(GTK_ENTRY(e_name));
        const char *ip   = gtk_entry_get_text(GTK_ENTRY(e_ip));
        const char *note = gtk_entry_get_text(GTK_ENTRY(e_note));
        // 检查输入
        // 组装设备数据
        device_t nd; memset(&nd, 0, sizeof(nd));
        nd.id = edit_id;
        snprintf(nd.name, sizeof(nd.name), "%s", name);
        snprintf(nd.ip, sizeof(nd.ip), "%s", ip);
        snprintf(nd.note, sizeof(nd.note), "%s", note ? note : "");

        char err[256];
        int rc = device_service_save(g_app.db, &nd, err, sizeof(err));
        if (rc != 0) { ui_error(GTK_WINDOW(dlg), "保存失败: %s", err); continue; }

        devices_reload();
        app_notify_devices_changed();
        app_status("已保存设备: %s", nd.name);
        break;
    }
    gtk_widget_destroy(dlg);
}

/* ===== 回调 ===== */

static void on_add(GtkButton *b, gpointer d) { (void)b;(void)d; device_dialog(0); }
static void on_edit(GtkButton *b, gpointer d) {
    (void)b;(void)d;
    int id = selected_id();
    if (!id) { ui_error(GTK_WINDOW(g_app.window), "请先选择要编辑的设备"); return; }
    device_dialog(id);
}
static void on_delete(GtkButton *b, gpointer d) {
    (void)b;(void)d;
    int id = selected_id();
    if (!id) { ui_error(GTK_WINDOW(g_app.window), "请先选择要删除的设备"); return; }
    device_t dev;
    if (db_device_get(g_app.db, id, &dev) != 1) {
        ui_error(GTK_WINDOW(g_app.window), "找不到该设备"); return;
    }
    if (!ui_confirm(GTK_WINDOW(g_app.window),
            "确定删除设备 “%s (%s)” 吗？\n\n"
            "将同时删除该设备的端口策略；\n"
            "已完成的巡检记录与结果明细会保留。",
            dev.name, dev.ip))
        return;
    char err[256];
    if (device_service_delete(g_app.db, id, err, sizeof(err)) != 0) {
        ui_error(GTK_WINDOW(g_app.window), "删除失败: %s", err);
        return;
    }
    devices_reload();
    app_notify_devices_changed();
    app_status("已删除设备: %s", dev.name);
}
static void on_search_changed(GtkEditable *e, gpointer d) { (void)e;(void)d; devices_reload(); }
static void on_row_activated(GtkTreeView *tv, GtkTreePath *path,
                             GtkTreeViewColumn *col, gpointer d) {
    (void)tv;(void)path;(void)col;(void)d;
    int id = selected_id();
    if (id) device_dialog(id);
}

/* ===== 构建页面 ===== */

GtkWidget *page_devices_build(void) {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);         // 创建垂直布局容器，控件间隔6像素
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);             // 容器边缘留白8像素

    /* 工具栏 */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);        // 创建水平布局容器，控件间隔6像素
    gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);            // 把 bar 放进垂直布局 vbox

    // 创建按钮，设置点击函数
    GtkWidget *btn_add = gtk_button_new_with_label("新增设备");
    GtkWidget *btn_edit = gtk_button_new_with_label("编辑");
    GtkWidget *btn_del = gtk_button_new_with_label("删除");
    g_signal_connect(btn_add, "clicked", G_CALLBACK(on_add), NULL);
    g_signal_connect(btn_edit, "clicked", G_CALLBACK(on_edit), NULL);
    g_signal_connect(btn_del, "clicked", G_CALLBACK(on_delete), NULL);
    gtk_box_pack_start(GTK_BOX(bar), btn_add, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), btn_edit, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), btn_del, FALSE, FALSE, 0);

    GtkWidget *spacer = gtk_label_new("   搜索:");
    gtk_box_pack_start(GTK_BOX(bar), spacer, FALSE, FALSE, 0);           // 把标签放进水平布局 bar
    d_search = gtk_entry_new();     // 创建一个单行文本输入框
    gtk_entry_set_placeholder_text(GTK_ENTRY(d_search), "名称 / IP / 备注");    // 设置输入框为空时显示的提示文字
    gtk_widget_set_size_request(d_search, 220, -1);         // 输入框的最小请求宽度为 220 像素
    g_signal_connect(d_search, "changed", G_CALLBACK(on_search_changed), NULL);     // 监听输入框的 changed 事件
    gtk_box_pack_start(GTK_BOX(bar), d_search, FALSE, FALSE, 0);    // 把输入框放进工具栏

    /* 列表 */
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);                                  // 创建一个滚动窗口
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);                 // 设置横向和纵向滚动条都由 GTK 自动决定
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);                                 // 把滚动窗口放进垂直布局 vbox

    d_store = gtk_list_store_new(D_N,                                                           // 创建一个空的数据列表，包含 D_N 列，每列指定数据类型
        G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    d_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(d_store));                             // 创建表格视图，使用 d_store 作为数据来源
    g_object_unref(d_store);                                                                    // 减少创建对 d_store 的引用计数
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(d_tree), GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);   // 显示横向分隔线

    // 准备列的标题、数据编号和宽度
    const char *titles[] = {"设备名称", "IP 地址", "备注", "更新时间"};
    int cols[] = {D_NAME, D_IP, D_NOTE, D_UPDATED};
    int widths[] = {200, 150, 300, 170};
    for (int i = 0; i < 4; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();                          // 创建文本绘制器：负责把单元格里的文字画出来
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(
            titles[i], r, "text", cols[i], NULL);                                   // 创建一列：列标题使用 titles[i]，单元格文字从 d_store 中编号为 cols[i] 的数据列读取
        gtk_tree_view_column_set_resizable(c, TRUE);                                // 允许用户用鼠标拖动表头边缘调整这一列的宽度
        gtk_tree_view_column_set_min_width(c, widths[i]);                           // 设置这一列的最小宽度
        gtk_tree_view_append_column(GTK_TREE_VIEW(d_tree), c);                      // 把新列加到表格 d_tree 的右侧
    }
    g_signal_connect(d_tree, "row-activated", G_CALLBACK(on_row_activated), NULL);  // 双击事件绑定
    gtk_container_add(GTK_CONTAINER(scrolled), d_tree);                             // 放入滚定区域

    devices_reload();
    return vbox;
}