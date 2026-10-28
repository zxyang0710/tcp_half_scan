/*
 * page_policies.c - 端口策略页：统一策略表、增删改查、设备筛选、CSV 导入
 */

#include "app.h"
#include "db.h"
#include "csv.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static GtkWidget      *p_tree;
static GtkListStore   *p_store;
static GtkWidget      *p_filter;   /* GtkComboBoxText 设备筛选 */
static GtkWidget      *p_search;

enum { P_ID, P_DEV, P_IP, P_PORT, P_PROTO, P_EXPECT, P_PURPOSE, P_N };

static const char *cur_search(void) {
    const char *q = gtk_entry_get_text(GTK_ENTRY(p_search));
    return (q && *q) ? q : "";
}

static int cur_filter_device(void) {
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(p_filter));
    if (!id || !*id) return -1;
    return atoi(id);
}

static void policies_reload(void) {
    gtk_list_store_clear(p_store);
    policy_t *arr = NULL; int n = 0;
    if (db_policy_list(g_app.db, cur_filter_device(), cur_search(), &arr, &n) != 0)
        return;
    for (int i = 0; i < n; i++) {
        char port[16];
        snprintf(port, sizeof(port), "%d", arr[i].port);
        GtkTreeIter it;
        gtk_list_store_append(p_store, &it);
        gtk_list_store_set(p_store, &it,
                           P_ID, arr[i].id,
                           P_DEV, arr[i].device_name,
                           P_IP, arr[i].device_ip,
                           P_PORT, port,
                           P_PROTO, arr[i].protocol,
                           P_EXPECT, expected_label(arr[i].expected),
                           P_PURPOSE, arr[i].purpose,
                           -1);
    }
    db_free(arr);
}

/* 设备列表变化时刷新筛选下拉框 */
void page_policies_reload_devices(void) {
    const char *prev0 = gtk_combo_box_get_active_id(GTK_COMBO_BOX(p_filter));
    char *prev = prev0 ? g_strdup(prev0) : NULL;

    gtk_combo_box_text_remove_all(GTK_COMBO_BOX_TEXT(p_filter));
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(p_filter), "", "全部设备");

    device_t *arr = NULL; int n = 0;
    if (db_device_list(g_app.db, &arr, &n) == 0) {
        for (int i = 0; i < n; i++) {
            char id[16], label[200];
            snprintf(id, sizeof(id), "%d", arr[i].id);
            snprintf(label, sizeof(label), "%s (%s)", arr[i].name, arr[i].ip);
            gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(p_filter), id, label);
        }
        db_free(arr);
    }
    if (prev) {
        if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(p_filter), prev))
            gtk_combo_box_set_active(GTK_COMBO_BOX(p_filter), 0);
        g_free(prev);
    } else {
        gtk_combo_box_set_active(GTK_COMBO_BOX(p_filter), 0);
    }
    policies_reload();
}

static int policy_selected_id(void) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(p_tree));
    GtkTreeModel *m; GtkTreeIter it;
    if (gtk_tree_selection_get_selected(sel, &m, &it)) {
        int id = 0;
        gtk_tree_model_get(m, &it, P_ID, &id, -1);
        return id;
    }
    return 0;
}
/* ===== 新增 / 编辑策略 ===== */

static void policy_dialog(int edit_id) {
    policy_t p;
    memset(&p, 0, sizeof(p));
    if (edit_id > 0 && db_policy_get(g_app.db, edit_id, &p) != 1) {
        ui_error(GTK_WINDOW(g_app.window), "找不到该策略（可能已被删除）");
        return;
    }

    device_t *devs = NULL; int nd = 0;
    if (db_device_list(g_app.db, &devs, &nd) != 0 || nd == 0) {
        db_free(devs);
        ui_error(GTK_WINDOW(g_app.window), "请先在“设备”页新增设备");
        return;
    }

    GtkWidget *dlg = gtk_dialog_new_with_buttons(
        edit_id > 0 ? "编辑端口策略" : "新增端口策略",
        GTK_WINDOW(g_app.window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "取消", GTK_RESPONSE_CANCEL, "保存", GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 460, -1);

    GtkWidget *ca = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 10);
    gtk_container_add(GTK_CONTAINER(ca), grid);

    GtkWidget *l1 = gtk_label_new("设备*:");
    gtk_widget_set_halign(l1, GTK_ALIGN_END);
    GtkWidget *c_dev = gtk_combo_box_text_new();
    for (int i = 0; i < nd; i++) {
        char id[16], label[200];
        snprintf(id, sizeof(id), "%d", devs[i].id);
        snprintf(label, sizeof(label), "%s (%s)", devs[i].name, devs[i].ip);
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(c_dev), id, label);
    }
    if (edit_id > 0) {
        char id[16]; snprintf(id, sizeof(id), "%d", p.device_id);
        gtk_combo_box_set_active_id(GTK_COMBO_BOX(c_dev), id);
    } else {
        gtk_combo_box_set_active(GTK_COMBO_BOX(c_dev), 0);
    }
    gtk_grid_attach(GTK_GRID(grid), l1, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), c_dev, 1, 0, 1, 1);

    GtkWidget *l2 = gtk_label_new("端口号*:");
    gtk_widget_set_halign(l2, GTK_ALIGN_END);
    GtkWidget *e_port = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(e_port), "1 - 65535");
    if (edit_id > 0) { char b[16]; snprintf(b, sizeof(b), "%d", p.port); gtk_entry_set_text(GTK_ENTRY(e_port), b); }
    gtk_grid_attach(GTK_GRID(grid), l2, 0, 1, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), e_port, 1, 1, 1, 1);

    GtkWidget *l3 = gtk_label_new("协议:");
    gtk_widget_set_halign(l3, GTK_ALIGN_END);
    GtkWidget *l_proto = gtk_label_new("TCP（第一阶段固定）");
    gtk_widget_set_halign(l_proto, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), l3, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), l_proto, 1, 2, 1, 1);

    GtkWidget *l4 = gtk_label_new("预期状态*:");
    gtk_widget_set_halign(l4, GTK_ALIGN_END);
    GtkWidget *c_exp = gtk_combo_box_text_new();
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(c_exp), EXP_OPEN, "开放");
    gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(c_exp), EXP_CLOSED, "关闭");
    if (edit_id > 0 && strcmp(p.expected, EXP_CLOSED) == 0)
        gtk_combo_box_set_active(GTK_COMBO_BOX(c_exp), 1);
    else
        gtk_combo_box_set_active(GTK_COMBO_BOX(c_exp), 0);
    gtk_grid_attach(GTK_GRID(grid), l4, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), c_exp, 1, 3, 1, 1);

    GtkWidget *l5 = gtk_label_new("用途说明:");
    gtk_widget_set_halign(l5, GTK_ALIGN_END);
    GtkWidget *e_purpose = gtk_entry_new();
    if (edit_id > 0) gtk_entry_set_text(GTK_ENTRY(e_purpose), p.purpose);
    gtk_grid_attach(GTK_GRID(grid), l5, 0, 4, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), e_purpose, 1, 4, 1, 1);

    gtk_widget_show_all(dlg);

    for (;;) {
        int resp = gtk_dialog_run(GTK_DIALOG(dlg));
        if (resp != GTK_RESPONSE_OK) break;

        const char *dev_id_s = gtk_combo_box_get_active_id(GTK_COMBO_BOX(c_dev));
        if (!dev_id_s || !*dev_id_s) { ui_error(GTK_WINDOW(dlg), "请选择设备"); continue; }
        int dev_id = atoi(dev_id_s);

        const char *port_s = gtk_entry_get_text(GTK_ENTRY(e_port));
        char *endp = NULL;
        long port = strtol(port_s, &endp, 10);
        if (!port_s || !*port_s || !endp || *endp != '\0' || port < 1 || port > 65535) {
            ui_error(GTK_WINDOW(dlg), "端口号非法（应为 1-65535 的整数）");
            continue;
        }
        const char *exp_s = gtk_combo_box_get_active_id(GTK_COMBO_BOX(c_exp));
        if (!exp_s || !*exp_s) { ui_error(GTK_WINDOW(dlg), "请选择预期状态"); continue; }

        if (db_policy_exists(g_app.db, dev_id, (int)port, edit_id)) {
            ui_error(GTK_WINDOW(dlg), "该设备已存在 TCP 端口 %ld 的策略，请勿重复", port);
            continue;
        }

        policy_t np;
        memset(&np, 0, sizeof(np));
        np.id = edit_id;
        np.device_id = dev_id;
        np.port = (int)port;
        snprintf(np.protocol, sizeof(np.protocol), "TCP");
        snprintf(np.expected, sizeof(np.expected), "%s", exp_s);
        snprintf(np.purpose, sizeof(np.purpose), "%s",
                 gtk_entry_get_text(GTK_ENTRY(e_purpose)));

        char err[256];
        int rc = (edit_id > 0) ? db_policy_update(g_app.db, &np, err, sizeof(err))
                               : db_policy_insert(g_app.db, &np, err, sizeof(err));
        if (rc != 0) { ui_error(GTK_WINDOW(dlg), "保存失败: %s", err); continue; }

        policies_reload();
        app_status("已保存端口策略（端口 %d）", np.port);
        break;
    }
    gtk_widget_destroy(dlg);
    db_free(devs);
}

static void on_add_policy(GtkButton *b, gpointer d) { (void)b;(void)d; policy_dialog(0); }
static void on_edit_policy(GtkButton *b, gpointer d) {
    (void)b;(void)d;
    int id = policy_selected_id();
    if (!id) { ui_error(GTK_WINDOW(g_app.window), "请先选择要编辑的策略"); return; }
    policy_dialog(id);
}

static void on_delete_policy(GtkButton *b, gpointer d) {
    (void)b;(void)d;
    int id = policy_selected_id();
    if (!id) { ui_error(GTK_WINDOW(g_app.window), "请先选择要删除的策略"); return; }
    if (!ui_confirm(GTK_WINDOW(g_app.window),
            "确定删除所选端口策略吗？\n（历史巡检记录中的策略快照不受影响）"))
        return;
    if (db_policy_delete(g_app.db, id) != 0) {
        ui_error(GTK_WINDOW(g_app.window), "删除失败");
        return;
    }
    policies_reload();
    app_status("已删除所选端口策略");
}
static void on_filter_changed(GtkComboBox *w, gpointer d) { (void)w;(void)d; policies_reload(); }

static void on_search_changed(GtkEditable *e, gpointer d) { (void)e;(void)d; policies_reload(); }
static void on_row_activated(GtkTreeView *tv, GtkTreePath *path,
                             GtkTreeViewColumn *col, gpointer d) {
    (void)tv;(void)path;(void)col;(void)d;
    int id = policy_selected_id();
    if (id) policy_dialog(id);
}

/* ===== CSV 导入 ===== */

static void policies_import_csv(void) {
    char *path = ui_choose_open_file(GTK_WINDOW(g_app.window),
                                     "选择端口策略 CSV 文件", "CSV 文件 (*.csv)", "*.csv");
    if (!path) return;

    char err[256];
    csv_policy_row_t *rows = NULL; int n = 0;
    if (csv_parse_policy(path, &rows, &n, err, sizeof(err)) != 0) {
        ui_error(GTK_WINDOW(g_app.window), "读取 CSV 失败: %s", err);
        g_free(path);
        return;
    }

    /* 校验每一行：解析错误 / 设备未登记 / 文件内重复 */
    int n_err = 0, n_dup = 0, n_new = 0, n_upd = 0, n_valid = 0;
    for (int i = 0; i < n; i++) {
        csv_policy_row_t *r = &rows[i];
        r->device_id = 0;
        if (r->error[0]) { n_err++; continue; }
        device_t dev;
        if (!db_device_find_by_ip(g_app.db, r->ip, &dev)) {
            snprintf(r->error, sizeof(r->error),
                     "设备 IP 未在“设备”页登记: %s", r->ip);
            n_err++;
            continue;
        }
        r->device_id = dev.id;
        if (r->dup_in_file) { n_dup++; continue; }
        n_valid++;
        if (db_policy_find_id(g_app.db, dev.id, r->port) > 0) n_upd++;
        else                                                      n_new++;
    }

    /* 生成预览报告 */
    GString *rep = g_string_new(NULL);
    g_string_append_printf(rep,
        "文件: %s\n\n共解析 %d 行：有效 %d，错误 %d，文件内重复(跳过) %d\n"
        "导入后将：新增 %d 条，更新 %d 条\n\n",
        path, n, n_valid, n_err, n_dup, n_new, n_upd);
    if (n_err > 0) {
        g_string_append(rep, "以下行存在问题，本次不会执行导入：\n");
        for (int i = 0; i < n; i++) {
            if (rows[i].error[0])
                g_string_append_printf(rep, "  第 %d 行: %s\n",
                                       rows[i].lineno, rows[i].error);
        }
    } else if (n_dup > 0) {
        g_string_append(rep, "文件内重复的行将被跳过。\n");
    }
    if (n_valid == 0)
        g_string_append(rep, "\n没有可导入的有效行。\n");

    /* 预览对话框 */
    GtkWidget *dlg = gtk_dialog_new_with_buttons("CSV 导入预览",
        GTK_WINDOW(g_app.window),
        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
        "关闭", GTK_RESPONSE_CANCEL, "确认导入", GTK_RESPONSE_OK, NULL);
    gtk_window_set_default_size(GTK_WINDOW(dlg), 600, 420);
    gtk_window_set_position(GTK_WINDOW(dlg), GTK_WIN_POS_CENTER_ON_PARENT);
    GtkWidget *ca = gtk_dialog_get_content_area(GTK_DIALOG(dlg));
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    GtkWidget *tv = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(tv), FALSE);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(tv), FALSE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(tv), 8);
    gtk_text_view_set_top_margin(GTK_TEXT_VIEW(tv), 8);
    GtkTextBuffer *tb = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tv));
    gtk_text_buffer_set_text(tb, rep->str, -1);
    gtk_container_add(GTK_CONTAINER(sw), tv);
    gtk_widget_set_size_request(sw, -1, 220);
    gtk_box_pack_start(GTK_BOX(ca), sw, TRUE, TRUE, 0);
    gtk_widget_show_all(dlg);

    int can_import = (n_err == 0 && n_valid > 0);
    if (!can_import)
        gtk_dialog_set_response_sensitive(GTK_DIALOG(dlg), GTK_RESPONSE_OK, FALSE);

    int resp = gtk_dialog_run(GTK_DIALOG(dlg));
    gtk_widget_destroy(dlg);
    g_string_free(rep, TRUE);

    if (resp != GTK_RESPONSE_OK || !can_import) {
        free(rows);
        g_free(path);
        return;
    }

    /* 单事务提交：以 (设备 + TCP + 端口) 识别策略，相同则更新，否则新增 */
    int applied = 0, failed = 0;
    char *emsg = NULL;
    if (sqlite3_exec(g_app.db, "BEGIN;", NULL, NULL, &emsg) != SQLITE_OK) {
        ui_error(GTK_WINDOW(g_app.window), "无法开始事务: %s", emsg ? emsg : "");
        sqlite3_free(emsg);
        free(rows); g_free(path);
        return;
    }
    for (int i = 0; i < n; i++) {
        csv_policy_row_t *r = &rows[i];
        if (r->error[0] || r->dup_in_file || r->device_id <= 0) continue;
        int pid = db_policy_find_id(g_app.db, r->device_id, r->port);
        policy_t p; memset(&p, 0, sizeof(p));
        p.id = pid;
        p.device_id = r->device_id;
        p.port = r->port;
        snprintf(p.protocol, sizeof(p.protocol), "TCP");
        snprintf(p.expected, sizeof(p.expected), "%s", r->expected);
        snprintf(p.purpose, sizeof(p.purpose), "%s", r->purpose);
        char perr[256];
        int rc = (pid > 0) ? db_policy_update(g_app.db, &p, perr, sizeof(perr))
                           : db_policy_insert(g_app.db, &p, perr, sizeof(perr));
        if (rc == 0) applied++;
        else         failed++;
    }
    (void)applied;
    if (failed > 0) {
        sqlite3_exec(g_app.db, "ROLLBACK;", NULL, NULL, NULL);
        ui_error(GTK_WINDOW(g_app.window),
                 "导入失败：有 %d 条无法写入，已全部回滚。", failed);
    } else {
        sqlite3_exec(g_app.db, "COMMIT;", NULL, NULL, NULL);
        policies_reload();
        app_status("CSV 导入完成：新增 %d 条，更新 %d 条", n_new, n_upd);
        ui_info(GTK_WINDOW(g_app.window),
                "导入完成。\n新增 %d 条，更新 %d 条，跳过重复 %d 条。",
                n_new, n_upd, n_dup);
    }

    free(rows);
    g_free(path);
}

static void on_import_csv(GtkButton *b, gpointer d) { (void)b;(void)d; policies_import_csv(); }

/* ===== 构建页面 ===== */

GtkWidget *page_policies_build(void) {
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 8);

    /* 工具栏 */
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(vbox), bar, FALSE, FALSE, 0);

    GtkWidget *btn_add = gtk_button_new_with_label("新增策略");
    GtkWidget *btn_edit = gtk_button_new_with_label("编辑");
    GtkWidget *btn_del = gtk_button_new_with_label("删除");
    GtkWidget *btn_imp = gtk_button_new_with_label("导入 CSV");
    g_signal_connect(btn_add, "clicked", G_CALLBACK(on_add_policy), NULL);
    g_signal_connect(btn_edit, "clicked", G_CALLBACK(on_edit_policy), NULL);
    g_signal_connect(btn_del, "clicked", G_CALLBACK(on_delete_policy), NULL);
    g_signal_connect(btn_imp, "clicked", G_CALLBACK(on_import_csv), NULL);
    gtk_box_pack_start(GTK_BOX(bar), btn_add, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), btn_edit, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), btn_del, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), gtk_separator_new(GTK_ORIENTATION_VERTICAL),
                       FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(bar), btn_imp, FALSE, FALSE, 0);

    gtk_box_pack_start(GTK_BOX(bar), gtk_label_new("   设备筛选:"), FALSE, FALSE, 0);
    p_filter = gtk_combo_box_text_new();
    gtk_box_pack_start(GTK_BOX(bar), p_filter, FALSE, FALSE, 0);
    g_signal_connect(p_filter, "changed", G_CALLBACK(on_filter_changed), NULL);

    gtk_box_pack_start(GTK_BOX(bar), gtk_label_new("   搜索:"), FALSE, FALSE, 0);
    p_search = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(p_search), "设备 / 端口 / 用途");
    gtk_widget_set_size_request(p_search, 200, -1);
    g_signal_connect(p_search, "changed", G_CALLBACK(on_search_changed), NULL);
    gtk_box_pack_start(GTK_BOX(bar), p_search, FALSE, FALSE, 0);

    /* 列表 */
    GtkWidget *scrolled = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

    p_store = gtk_list_store_new(P_N,
        G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    p_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(p_store));
    g_object_unref(p_store);
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(p_tree), GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

    const char *titles[] = {"设备", "设备 IP", "端口", "协议", "预期状态", "用途说明"};
    int cols[]   = {P_DEV, P_IP, P_PORT, P_PROTO, P_EXPECT, P_PURPOSE};
    int widths[] = {180, 140, 80, 70, 100, 300};
    for (int i = 0; i < 6; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(
            titles[i], r, "text", cols[i], NULL);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_column_set_min_width(col, widths[i]);
        gtk_tree_view_append_column(GTK_TREE_VIEW(p_tree), col);
    }
    g_signal_connect(p_tree, "row-activated", G_CALLBACK(on_row_activated), NULL);
    gtk_container_add(GTK_CONTAINER(scrolled), p_tree);

    page_policies_reload_devices();
    return vbox;
}