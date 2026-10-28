/*
 * page_devices.c - 设备页：设备信息增删改查
 */

#include "app.h"
#include "db.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static GtkWidget    *d_tree;
static GtkListStore *d_store;
static GtkWidget    *d_search;

enum { D_ID, D_NAME, D_IP, D_NOTE, D_UPDATED, D_N };

/* 读取搜索框内容 */
static const char *cur_search(void) {
    const char *q = gtk_entry_get_text(GTK_ENTRY(d_search));
    return (q && *q) ? q : "";
}

static void devices_reload(void) {
    gtk_list_store_clear(d_store);
    device_t *arr = NULL; int n = 0;
    if (db_device_list(g_app.db, &arr, &n) != 0) return;
    const char *q = cur_search();
    for (int i = 0; i < n; i++) {
        if (*q && !strstr(arr[i].name, q) && !strstr(arr[i].ip, q) &&
            !strstr(arr[i].note, q))
            continue;
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

static int selected_id(void) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(d_tree));
    GtkTreeModel *m; GtkTreeIter it;
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

    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        edit_id > 0 ? "编辑设备" : "新增设备",
        GTK_WINDOW(g_app.window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "取消", GTK_RESPONSE_CANCEL, "保存", GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 420, -1);

    GtkWidget *ca = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
    gtk_container_add(GTK_CONTAINER(ca), grid);

    GtkWidget *l1 = gtk_label_new("设备名称*:");
    gtk_widget_set_halign(l1, GTK_ALIGN_END);
    GtkWidget *e_name = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(e_name), d.name);
    gtk_grid_attach(GTK_GRID(grid), l1, 0, 0, 1, 1);
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
        int resp = gtk_dialog_run(GTK_DIALOG(dlg));
        if (resp != GTK_RESPONSE_OK) break;

        const char *name = gtk_entry_get_text(GTK_ENTRY(e_name));
        const char *ip   = gtk_entry_get_text(GTK_ENTRY(e_ip));
        const char *note = gtk_entry_get_text(GTK_ENTRY(e_note));

        if (!name || !*name) { ui_error(GTK_WINDOW(dlg), "设备名称不能为空"); continue; }
        if (!util_valid_ipv4(ip)) { ui_error(GTK_WINDOW(dlg), "IP 地址格式非法（第一阶段仅支持 IPv4）"); continue; }
        if (db_device_ip_exists(g_app.db, ip, edit_id)) { ui_error(GTK_WINDOW(dlg), "该 IP 已被其它设备登记，请避免重复"); continue; }

        device_t nd; memset(&nd, 0, sizeof(nd));
        nd.id = edit_id;
        snprintf(nd.name, sizeof(nd.name), "%s", name);
        snprintf(nd.ip, sizeof(nd.ip), "%s", ip);
        snprintf(nd.note, sizeof(nd.note), "%s", note ? note : "");

        char err[256];
        int rc;
        if (edit_id > 0) rc = db_device_update(g_app.db, &nd, err, sizeof(err));
        else             rc = db_device_insert(g_app.db, &nd, err, sizeof(err));
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
    if (db_device_delete(g_app.db, id, err, sizeof(err)) != 0) {
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
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);

    /* 工具栏 */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);

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
    gtk_box_pack_start(GTK_BOX(bar), spacer, FALSE, FALSE, 0);
    d_search = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(d_search), "名称 / IP / 备注");
    gtk_widget_set_size_request(d_search, 220, -1);
    g_signal_connect(d_search, "changed", G_CALLBACK(on_search_changed), NULL);
    gtk_box_pack_start(GTK_BOX(bar), d_search, FALSE, FALSE, 0);

    /* 列表 */
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

    d_store = gtk_list_store_new(D_N,
        G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    d_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(d_store));
    g_object_unref(d_store);
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(d_tree), GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

    const char *titles[] = {"设备名称", "IP 地址", "备注", "更新时间"};
    int cols[] = {D_NAME, D_IP, D_NOTE, D_UPDATED};
    int widths[] = {200, 150, 300, 170};
    for (int i = 0; i < 4; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *c = gtk_tree_view_column_new_with_attributes(
            titles[i], r, "text", cols[i], NULL);
        gtk_tree_view_column_set_resizable(c, TRUE);
        gtk_tree_view_column_set_min_width(c, widths[i]);
        gtk_tree_view_append_column(GTK_TREE_VIEW(d_tree), c);
    }
    g_signal_connect(d_tree, "row-activated", G_CALLBACK(on_row_activated), NULL);
    gtk_container_add(GTK_CONTAINER(scrolled), d_tree);

    devices_reload();
    return vbox;
}