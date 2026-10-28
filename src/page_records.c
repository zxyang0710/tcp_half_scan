/*
 * page_records.c - 记录页：历史巡检列表、详情、与上次完整巡检对比、CSV 导出
 *
 * 设计要点（对应需求文档 3.4）:
 *   - 列表按开始时间从新到旧排序，可多选导出。
 *   - 详情展示设备快照、模式、端口范围、逐端口结果与策略判断。
 *   - 与同一设备更早的最近一次“完整完成”的巡检对比，只比较共同检查过的端口。
 *   - 被停止/失败的记录可查看，但不作为比较基准（由数据层保证）。
 */

#include "app.h"
#include "db.h"

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 巡检记录列表列 */
enum { R_ID, R_STARTED, R_DEVS, R_MODE, R_STATUS, R_SUMMARY, R_N };
/* 端口结果列 */
enum { C_PORT, C_PROTO, C_SERVICE, C_ACTUAL, C_EXPECT, C_VERDICT, C_CHANGE, C_N };

static GtkWidget    *r_tree;
static GtkListStore *r_store;
static GtkWidget    *r_detail_box;
static GtkWidget    *r_detail_hdr;
static int           r_cur_scan_id;

static void show_detail(int scan_id);
static void clear_detail(void);

/* 与上次状态的变化 */
static void compare_change(const char *prev, int has_prev, const char *now,
                           char *out, int outlen) {
    if (!has_prev)            { snprintf(out, outlen, "无法比较（上次未检查）"); return; }
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

/* 读取某设备分组的端口范围 */
static int get_sd_range(sqlite3 *db, int sd_id, int *rs, int *re) {
    const char *sql =
        "SELECT COALESCE(range_start,0),COALESCE(range_end,0) "
        "FROM scan_devices WHERE id=?1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(st, 1, sd_id);
    int ok = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        *rs = sqlite3_column_int(st, 0);
        *re = sqlite3_column_int(st, 1);
        ok = 1;
    }
    sqlite3_finalize(st);
    return ok;
}

static void clear_detail(void) {
    r_cur_scan_id = 0;
    if (r_detail_hdr)
        gtk_label_set_text(GTK_LABEL(r_detail_hdr),
                           "请选择左侧的巡检记录查看详情。");
    if (r_detail_box) {
        GList *kids = gtk_container_get_children(GTK_CONTAINER(r_detail_box));
        for (GList *l = kids; l; l = l->next)
            gtk_widget_destroy(GTK_WIDGET(l->data));
        g_list_free(kids);
    }
}

/* ===== 记录列表刷新 ===== */
void page_records_reload(void) {
    if (!r_store) return;
    gtk_list_store_clear(r_store);
    scan_summary_t *arr = NULL; int n = 0;
    if (db_scan_list(g_app.db, &arr, &n) != 0) return;
    for (int i = 0; i < n; i++) {
        scan_summary_t *s = &arr[i];
        char devs[16];
        snprintf(devs, sizeof(devs), "%d", s->device_count);
        char sum[200];
        snprintf(sum, sizeof(sum),
                 "开放 %d / 关闭 %d / 无响应 %d（%d 条结果）",
                 s->open_count, s->closed_count, s->filtered_count,
                 s->open_count + s->closed_count + s->filtered_count);
        GtkTreeIter it;
        gtk_list_store_append(r_store, &it);
        gtk_list_store_set(r_store, &it,
                           R_ID, s->id,
                           R_STARTED, s->started_at,
                           R_DEVS, devs,
                           R_MODE, mode_label(s->mode),
                           R_STATUS, status_label(s->status),
                           R_SUMMARY, sum,
                           -1);
    }
    db_free(arr);

    if (r_cur_scan_id > 0) show_detail(r_cur_scan_id);
    else                   clear_detail();
}
/* ===== 详情展示 ===== */
static void show_detail(int scan_id) {
    if (!r_detail_box) return;
    /* 清空详情视图 */
    GList *kids = gtk_container_get_children(GTK_CONTAINER(r_detail_box));
    for (GList *l = kids; l; l = l->next)
        gtk_widget_destroy(GTK_WIDGET(l->data));
    g_list_free(kids);

    scan_summary_t s;
    if (db_scan_get(g_app.db, scan_id, &s) != 1) { clear_detail(); return; }
    r_cur_scan_id = scan_id;

    char rng[64];
    if (strcmp(s.mode, MODE_RANGE) == 0)
        snprintf(rng, sizeof(rng), "%d - %d", s.range_start, s.range_end);
    else
        snprintf(rng, sizeof(rng), "按端口策略");

    const char *fin = (s.finished_at[0]) ? s.finished_at : "（未完成）";
    char hdr[600];
    snprintf(hdr, sizeof(hdr),
             "巡检记录 #%d\n"
             "模式：%s      范围：%s\n"
             "开始：%s      结束：%s\n"
             "完成状态：%s      设备数：%d",
             s.id, mode_label(s.mode), rng, s.started_at, fin,
             status_label(s.status), s.device_count);
    gtk_label_set_text(GTK_LABEL(r_detail_hdr), hdr);

    scan_device_t *devs = NULL; int nd = 0;
    if (db_scan_devices(g_app.db, scan_id, &devs, &nd) != 0) return;

    for (int i = 0; i < nd; i++) {
        scan_device_t *d = &devs[i];

        GtkWidget *frame = gtk_frame_new(NULL);
        GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
        gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);
        gtk_container_add(GTK_CONTAINER(frame), vbox);

        char h[300];
        snprintf(h, sizeof(h), "%s  (%s)", d->name, d->ip);
        GtkWidget *title = gtk_label_new(h);
        gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
        PangoAttrList *al = pango_attr_list_new();
        pango_attr_list_insert(al, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
        gtk_label_set_attributes(GTK_LABEL(title), al);
        pango_attr_list_unref(al);
        gtk_box_pack_start(GTK_BOX(vbox), title, FALSE, FALSE, 0);

        char drng[64];
        if (d->range_start > 0 || d->range_end > 0)
            snprintf(drng, sizeof(drng), "%d - %d", d->range_start, d->range_end);
        else
            snprintf(drng, sizeof(drng), "按策略端口");
        char st[600];
        snprintf(st, sizeof(st),
                 "状态：%s    %d/%d    开放 %d  关闭 %d  无响应 %d    范围：%s",
                 status_label(d->status), d->open_count + d->closed_count + d->filtered_count,
                 d->total_ports, d->open_count, d->closed_count, d->filtered_count, drng);
        if (d->error[0]) {
            int off = (int)strlen(st);
            snprintf(st + off, sizeof(st) - off, "    错误：%s", d->error);
        }
        GtkWidget *stl = gtk_label_new(st);
        gtk_label_set_xalign(GTK_LABEL(stl), 0.0f);
        gtk_box_pack_start(GTK_BOX(vbox), stl, FALSE, FALSE, 0);

        /* 比较基准 */
        int prev_sd = 0;
        db_prev_complete_scan_device(g_app.db, scan_id, d->device_id, d->ip, &prev_sd);
        scan_result_row_t *prows = NULL; int pn = 0;
        if (prev_sd > 0) {
            db_scan_results(g_app.db, prev_sd, &prows, &pn);
            int prs = 0, pre = 0;
            get_sd_range(g_app.db, prev_sd, &prs, &pre);
            char pl[300];
            snprintf(pl, sizeof(pl), "比较基准：上一次完整巡检    端口范围 %d - %d%s",
                     prs, pre,
                     (prs != d->range_start || pre != d->range_end) ? "（与本次范围不同）" : "");
            GtkWidget *pll = gtk_label_new(pl);
            gtk_label_set_xalign(GTK_LABEL(pll), 0.0f);
            gtk_box_pack_start(GTK_BOX(vbox), pll, FALSE, FALSE, 0);
        } else {
            GtkWidget *pll = gtk_label_new("无可比较的上次完整巡检");
            gtk_label_set_xalign(GTK_LABEL(pll), 0.0f);
            gtk_box_pack_start(GTK_BOX(vbox), pll, FALSE, FALSE, 0);
        }

        scan_result_row_t *rows = NULL; int nr = 0;
        db_scan_results(g_app.db, d->id, &rows, &nr);

        if (nr == 0) {
            GtkWidget *none = gtk_label_new("本次未产生端口结果（设备被停止或失败）。");
            gtk_label_set_xalign(GTK_LABEL(none), 0.0f);
            gtk_box_pack_start(GTK_BOX(vbox), none, FALSE, FALSE, 0);
        } else {
            GtkListStore *store = gtk_list_store_new(C_N,
                G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING,
                G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
            GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
            g_object_unref(store);
            gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(tree),
                                         GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);
            const char *ct[] = {"端口", "协议", "服务", "实际状态",
                                "策略预期", "策略判断", "与上次比较"};
            int cw[] = {70, 60, 130, 100, 90, 150, 170};
            for (int c = 0; c < C_N; c++) {
                GtkCellRenderer *cr = gtk_cell_renderer_text_new();
                GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(
                    ct[c], cr, "text", c, NULL);
                gtk_tree_view_column_set_resizable(col, TRUE);
                gtk_tree_view_column_set_min_width(col, cw[c]);
                gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col);
            }

            int n_newopen = 0, n_toclosed = 0, n_toopen = 0;
            for (int r = 0; r < nr; r++) {
                scan_result_row_t *rw = &rows[r];
                const char *prev_actual = NULL;
                for (int k = 0; k < pn; k++)
                    if (prows[k].port == rw->port) { prev_actual = prows[k].actual; break; }
                char chg[64];
                compare_change(prev_actual, prev_actual != NULL, rw->actual, chg, sizeof(chg));
                if (strcmp(chg, "关闭变开放") == 0 || strcmp(chg, "上次无响应，本次开放") == 0)
                    n_newopen++;
                else if (strcmp(chg, "开放变关闭") == 0)
                    n_toclosed++;
                else if (strcmp(chg, "上次无响应，本次关闭") == 0)
                    n_toopen++;

                GtkTreeIter it;
                gtk_list_store_append(store, &it);
                gtk_list_store_set(store, &it,
                    C_PORT, rw->port,
                    C_PROTO, rw->protocol,
                    C_SERVICE, rw->service,
                    C_ACTUAL, actual_label(rw->actual),
                    C_EXPECT, expected_label(rw->expected),
                    C_VERDICT, rw->verdict,
                    C_CHANGE, chg,
                    -1);
            }
            if (pn > 0) {
                char cs[300];
                snprintf(cs, sizeof(cs),
                         "与上次完整巡检比较：新增/转为开放 %d，开放变关闭 %d，无响应变关闭 %d（仅比较两次共同检查的端口）",
                         n_newopen, n_toclosed, n_toopen);
                GtkWidget *csl = gtk_label_new(cs);
                gtk_label_set_xalign(GTK_LABEL(csl), 0.0f);
                gtk_box_pack_start(GTK_BOX(vbox), csl, FALSE, FALSE, 0);
            }

            GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
            gtk_widget_set_size_request(sw, -1, 160);
            gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
                                           GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
            gtk_container_add(GTK_CONTAINER(sw), tree);
            gtk_box_pack_start(GTK_BOX(vbox), sw, TRUE, TRUE, 0);
        }

        gtk_box_pack_start(GTK_BOX(r_detail_box), frame, FALSE, FALSE, 0);
        gtk_widget_show_all(frame);

        db_free(rows);
        db_free(prows);
    }
    db_free(devs);
}
/* ===== 回调 ===== */
static int first_selected_id(void) {
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(r_tree));
    GList *rows = gtk_tree_selection_get_selected_rows(sel, NULL);
    int id = 0;
    if (rows) {
        GtkTreeIter it;
        if (gtk_tree_model_get_iter(GTK_TREE_MODEL(r_store), &it,
                                    (GtkTreePath *)rows->data))
            gtk_tree_model_get(GTK_TREE_MODEL(r_store), &it, R_ID, &id, -1);
        g_list_free_full(rows, (GDestroyNotify)gtk_tree_path_free);
    }
    return id;
}

static void on_selection_changed(GtkTreeSelection *sel, gpointer d) {
    (void)sel; (void)d;
    int id = first_selected_id();
    if (id > 0) show_detail(id);
}

static void on_row_activated(GtkTreeView *tv, GtkTreePath *path,
                             GtkTreeViewColumn *col, gpointer d) {
    (void)tv; (void)path; (void)col; (void)d;
    int id = first_selected_id();
    if (id > 0) show_detail(id);
}

static void on_refresh(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    page_records_reload();
    app_status("记录列表已刷新");
}

/* 收集所选记录 id；若未选择，则返回当前列表全部记录 id */
static int *gather_ids(int *out_n) {
    *out_n = 0;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(r_tree));
    GList *rows = gtk_tree_selection_get_selected_rows(sel, NULL);
    int n = g_list_length(rows);
    int *ids = NULL; int k = 0;
    GtkTreeModel *m = GTK_TREE_MODEL(r_store);
    if (n > 0) {
        ids = malloc(n * sizeof(int));
        for (GList *l = rows; l; l = l->next) {
            GtkTreeIter it;
            if (gtk_tree_model_get_iter(m, &it, (GtkTreePath *)l->data)) {
                int id = 0;
                gtk_tree_model_get(m, &it, R_ID, &id, -1);
                if (id > 0) ids[k++] = id;
            }
        }
    }
    g_list_free_full(rows, (GDestroyNotify)gtk_tree_path_free);
    if (k == 0) {
        free(ids); ids = NULL;
        int total = gtk_tree_model_iter_n_children(m, NULL);
        if (total > 0) ids = malloc(total * sizeof(int));
        GtkTreeIter it;
        gboolean ok = gtk_tree_model_get_iter_first(m, &it);
        while (ok) {
            int id = 0;
            gtk_tree_model_get(m, &it, R_ID, &id, -1);
            if (id > 0) ids[k++] = id;
            ok = gtk_tree_model_iter_next(m, &it);
        }
    }
    *out_n = k;
    return ids;
}

static void on_export_selected(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    int n = 0;
    int *ids = gather_ids(&n);
    if (n == 0) { free(ids); ui_error(GTK_WINDOW(g_app.window), "没有可导出的巡检记录。"); return; }
    export_records_csv(GTK_WINDOW(g_app.window), ids, n);
    free(ids);
}

static void on_export_detail(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    if (r_cur_scan_id <= 0) {
        ui_error(GTK_WINDOW(g_app.window), "请先在左侧选择一条巡检记录。");
        return;
    }
    int id = r_cur_scan_id;
    export_records_csv(GTK_WINDOW(g_app.window), &id, 1);
}

/* ===== 构建页面 ===== */
GtkWidget *page_records_build(void) {
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(hbox), 8);

    /* 左：记录列表 */
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(hbox), left, FALSE, TRUE, 0);

    GtkWidget *lt = gtk_label_new("巡检记录（按开始时间从新到旧）");
    gtk_label_set_xalign(GTK_LABEL(lt), 0.0f);
    gtk_box_pack_start(GTK_BOX(left), lt, FALSE, FALSE, 0);

    GtkWidget *lsw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(lsw, 470, -1);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(lsw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(left), lsw, TRUE, TRUE, 0);

    r_store = gtk_list_store_new(R_N,
        G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    r_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(r_store));
    g_object_unref(r_store);
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(r_tree), GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

    const char *rt[] = {"开始时间", "设备数", "模式", "状态", "结果摘要"};
    int rc[]   = {R_STARTED, R_DEVS, R_MODE, R_STATUS, R_SUMMARY};
    int rw[]   = {150, 60, 110, 90, 240};
    for (int i = 0; i < 5; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(
            rt[i], r, "text", rc[i], NULL);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_column_set_min_width(col, rw[i]);
        gtk_tree_view_append_column(GTK_TREE_VIEW(r_tree), col);
    }
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(r_tree));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_MULTIPLE);
    g_signal_connect(sel, "changed", G_CALLBACK(on_selection_changed), NULL);
    g_signal_connect(r_tree, "row-activated", G_CALLBACK(on_row_activated), NULL);
    gtk_container_add(GTK_CONTAINER(lsw), r_tree);

    GtkWidget *lbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *b_ref = gtk_button_new_with_label("刷新");
    GtkWidget *b_exp = gtk_button_new_with_label("导出所选记录 CSV");
    g_signal_connect(b_ref, "clicked", G_CALLBACK(on_refresh), NULL);
    g_signal_connect(b_exp, "clicked", G_CALLBACK(on_export_selected), NULL);
    gtk_box_pack_start(GTK_BOX(lbar), b_ref, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(lbar), b_exp, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(left), lbar, FALSE, FALSE, 0);

    /* 右：详情 */
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(hbox), right, TRUE, TRUE, 0);

    r_detail_hdr = gtk_label_new("请选择左侧的巡检记录查看详情。");
    gtk_label_set_xalign(GTK_LABEL(r_detail_hdr), 0.0f);
    gtk_label_set_selectable(GTK_LABEL(r_detail_hdr), TRUE);
    gtk_box_pack_start(GTK_BOX(right), r_detail_hdr, FALSE, FALSE, 0);

    GtkWidget *rbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *b_expd = gtk_button_new_with_label("导出当前记录 CSV");
    g_signal_connect(b_expd, "clicked", G_CALLBACK(on_export_detail), NULL);
    gtk_box_pack_start(GTK_BOX(rbar), b_expd, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(right), rbar, FALSE, FALSE, 0);

    GtkWidget *rsw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(rsw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    r_detail_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(rsw), r_detail_box);
    gtk_box_pack_start(GTK_BOX(right), rsw, TRUE, TRUE, 0);

    page_records_reload();
    return hbox;
}