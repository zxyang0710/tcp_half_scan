/*
 * page_scan.c - 巡检页：多选设备、两种巡检模式、后台扫描与实时分组结果
 *
 * 设计要点（对应需求文档 3.3）:
 *   - 多选设备；未选择设备不能开始。
 *   - 两种模式：按端口策略（默认）/ 完整端口范围。
 *   - 实际扫描在后台线程执行，结果通过空闲回调回到界面线程刷新。
 *   - 停止后保留已完成部分，未扫描端口不写入记录。
 *   - 明确区分“关闭”与“无响应/被过滤”。
 */

#include "app.h"
#include "domain.h"
#include "db.h"
#include "scanner.h"
#include <pcap.h>

#include <gtk/gtk.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "scan_service.h"

/* 设备列表列（L_ID 为隐藏的设备 id） */
enum { L_ID, L_NAME, L_IP, L_POL, L_N };

/* 界面线程内的分组控件 */
typedef struct {
    int          used;
    GtkWidget   *frame;
    GtkWidget   *status_lbl;
    GtkListStore *store;
    int total, scanned, open, closed, filtered;
} uigroup_t;

static uigroup_t g_group[SCAN_MAX_DEV];
static int       g_n_group;

/* 界面控件 */
static GtkWidget    *s_dev_tree;
static GtkListStore *s_dev_store;
static GtkWidget    *s_rb_policy, *s_rb_range;
static GtkWidget    *s_range_start, *s_range_end, *s_timeout;
static GtkWidget    *s_btn_start, *s_btn_stop, *s_btn_refresh;
static GtkWidget    *s_dev_iface;   /* 网卡选择 */
static int           s_updating_combo; /* 防止combo信号递归 */
static GtkWidget    *s_spinner;
static GtkWidget    *s_progress, *s_progress_lbl;
static GtkWidget    *s_results_box;

/* 线程 / 运行状态 */
static pthread_t        s_thread;
static int              s_running;
static int              s_total_ports;
static int              s_done_ports;


/* ===== 空闲回调数据结构 ===== */
/* ===== 前向声明 ===== */
static int  collect_selected(device_t **out, int *out_n);
static void clear_results(void);



/* ===== 界面空闲刷新 ===== */

static gboolean idle_add_device(gpointer data) {
    scan_device_event_t *p = data;
    if (p->idx < 0 || p->idx >= SCAN_MAX_DEV) { free(p); return G_SOURCE_REMOVE; }
    uigroup_t *g = &g_group[p->idx];
    if (g->used) { free(p); return G_SOURCE_REMOVE; }

    GtkWidget *frame = gtk_frame_new(NULL);
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);
    gtk_container_add(GTK_CONTAINER(frame), vbox);

    char hdr[300];
    snprintf(hdr, sizeof(hdr), "%s  (%s)", p->name, p->ip);
    GtkWidget *top = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *title = gtk_label_new(hdr);
    gtk_label_set_xalign(GTK_LABEL(title), 0.0f);
    PangoAttrList *al = pango_attr_list_new();
    pango_attr_list_insert(al, pango_attr_weight_new(PANGO_WEIGHT_BOLD));
    gtk_label_set_attributes(GTK_LABEL(title), al);
    pango_attr_list_unref(al);
    gtk_box_pack_start(GTK_BOX(top), title, FALSE, FALSE, 0);

    char sl[256];
    snprintf(sl, sizeof(sl), "状态：待扫描    共 %d 个端口", p->total);
    GtkWidget *status = gtk_label_new(sl);
    gtk_label_set_xalign(GTK_LABEL(status), 0.0f);
    gtk_box_pack_start(GTK_BOX(top), status, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), top, FALSE, FALSE, 0);

    GtkListStore *store = gtk_list_store_new(6,
        G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING,
        G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    GtkWidget *tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(store));
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(tree), GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);
    const char *titles[] = {"端口", "协议", "服务", "实际状态", "策略预期", "策略判断"};
    for (int i = 0; i < 6; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(
            titles[i], r, "text", i, NULL);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_column_set_min_width(col, i == 2 ? 150 : 90);
        gtk_tree_view_append_column(GTK_TREE_VIEW(tree), col);
    }
    GtkWidget *sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(sw, -1, 130);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(sw), tree);
    gtk_box_pack_start(GTK_BOX(vbox), sw, TRUE, TRUE, 0);

    gtk_box_pack_start(GTK_BOX(s_results_box), frame, FALSE, FALSE, 0);
    gtk_widget_show_all(frame);

    g->used = 1;
    g->frame = frame;
    g->status_lbl = status;
    /* tree 持有模型引用；此处复用创建引用作为我们的一份，clear_results 释放 */
    g->store = store;
    g->total = p->total;
    g->scanned = g->open = g->closed = g->filtered = 0;
    if (p->idx + 1 > g_n_group) g_n_group = p->idx + 1;
    free(p);
    return G_SOURCE_REMOVE;
}

static gboolean idle_add_port(gpointer data) {
    scan_port_event_t *p = data;
    if (p->idx >= 0 && p->idx < SCAN_MAX_DEV && g_group[p->idx].used) {
        uigroup_t *g = &g_group[p->idx];
        GtkTreeIter it;
        gtk_list_store_append(g->store, &it);
        gtk_list_store_set(g->store, &it,
            0, p->port,
            1, "TCP",
            2, p->service,
            3, actual_label(p->actual),
            4, expected_label(p->expected),
            5, p->verdict,
            -1);
        g->scanned++;
        if (strcmp(p->actual, ST_OPEN) == 0)          g->open++;
        else if (strcmp(p->actual, ST_CLOSED) == 0)  g->closed++;
        else                                          g->filtered++;

        char sl[256];
        snprintf(sl, sizeof(sl),
                 "状态：扫描中  %d/%d    开放 %d  关闭 %d  无响应 %d",
                 g->scanned, g->total, g->open, g->closed, g->filtered);
        gtk_label_set_text(GTK_LABEL(g->status_lbl), sl);

        s_done_ports++;
        if (s_total_ports > 0) {
            double f = (double)s_done_ports / (double)s_total_ports;
            if (f > 1.0) f = 1.0;
            gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(s_progress), f);
        }
        char pl[128];
        snprintf(pl, sizeof(pl), "已扫描 %d / %d 端口", s_done_ports, s_total_ports);
        gtk_label_set_text(GTK_LABEL(s_progress_lbl), pl);
    }
    free(p);
    return G_SOURCE_REMOVE;
}


static gboolean idle_mark_reachable(gpointer data) {
    scan_reachable_event_t *p = data;
    if (p->idx >= 0 && p->idx < SCAN_MAX_DEV && g_group[p->idx].used) {
        uigroup_t *g = &g_group[p->idx];
        GtkTreeModel *model = GTK_TREE_MODEL(g->store);
        GtkTreeIter it;
        gboolean valid = gtk_tree_model_get_iter_first(model, &it);
        while (valid) {
            gchar *actual = NULL;
            gtk_tree_model_get(model, &it, 3, &actual, -1);
            if (actual && (strcmp(actual, actual_label(ST_FILTERED)) == 0 ||
                           strcmp(actual, actual_label(ST_FILTERED_REACHABLE)) == 0))
                gtk_list_store_set(g->store, &it, 3, ST_FILTERED_REACHABLE, -1);
            g_free(actual);
            valid = gtk_tree_model_iter_next(model, &it);
        }
    }
    free(p);
    return G_SOURCE_REMOVE;
}

static gboolean idle_device_done(gpointer data) {
    scan_device_done_event_t *p = data;
    if (p->idx >= 0 && p->idx < SCAN_MAX_DEV && g_group[p->idx].used) {
        uigroup_t *g = &g_group[p->idx];
        char sl[300];
        snprintf(sl, sizeof(sl),
                 "状态：%s    %d/%d    开放 %d  关闭 %d  无响应 %d",
                 status_label(p->status), p->scanned, p->total,
                 p->open, p->closed, p->filtered);
        gtk_label_set_text(GTK_LABEL(g->status_lbl), sl);
    }
    free(p);
    return G_SOURCE_REMOVE;
}

static gboolean idle_scan_finish(gpointer data) {
    scan_finish_event_t *p = data;
    pthread_join(s_thread, NULL);
    s_running = 0;

    app_set_scan_active(0);

    gtk_widget_set_sensitive(s_btn_start, TRUE);
    gtk_widget_set_sensitive(s_btn_stop, FALSE);
    if (s_spinner) { gtk_spinner_stop(GTK_SPINNER(s_spinner)); gtk_widget_set_visible(s_spinner, FALSE); }
    if (strcmp(p->status, RUN_COMPLETED) == 0)
        gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(s_progress), 1.0);

    app_status("巡检结束（%s）：开放 %d，关闭 %d，无响应 %d",
               status_label(p->status), p->open, p->closed, p->filtered);
    page_records_reload();
    free(p);
    return G_SOURCE_REMOVE;
}
/* 服务事件只在这里转换为 GTK 主线程任务。各 idle 回调负责释放数据。 */
static void dispatch_scan_event(scan_event_t event, void *data) {
    switch (event) {
    case SCAN_DEVICE: g_idle_add(idle_add_device, data); break;
    case SCAN_PORT: g_idle_add(idle_add_port, data); break;
    case SCAN_REACHABLE: g_idle_add(idle_mark_reachable, data); break;
    case SCAN_DEVICE_DONE: g_idle_add(idle_device_done, data); break;
    case SCAN_FINISH: g_idle_add(idle_scan_finish, data); break;
    }
}

/* ===== 设备列表刷新 ===== */
void page_scan_reload_devices(void) {
    if (!s_dev_store) return;
    gtk_list_store_clear(s_dev_store);
    device_t *arr = NULL; int n = 0;
    if (db_device_list(g_app.db, &arr, &n) != 0) return;
    for (int i = 0; i < n; i++) {
        policy_t *pol = NULL; int np = 0;
        db_policy_list(g_app.db, arr[i].id, "", &pol, &np);
        db_free(pol);
        char pols[32];
        if (np > 0) snprintf(pols, sizeof(pols), "%d", np);
        else        snprintf(pols, sizeof(pols), "0（无策略）");
        GtkTreeIter it;
        gtk_list_store_append(s_dev_store, &it);
        gtk_list_store_set(s_dev_store, &it,
                           L_ID, arr[i].id,
                           L_NAME, arr[i].name,
                           L_IP, arr[i].ip,
                           L_POL, pols,
                           -1);
    }
    db_free(arr);
}

/* ===== 收集所选设备（按隐藏的设备 id 精确获取） ===== */
static int collect_selected(device_t **out, int *out_n) {
    *out = NULL; *out_n = 0;
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(s_dev_tree));
    GList *rows = gtk_tree_selection_get_selected_rows(sel, NULL);
    int cnt = g_list_length(rows);
    if (cnt == 0) {
        g_list_free_full(rows, (GDestroyNotify)gtk_tree_path_free);
        return 0;
    }
    if (cnt > SCAN_MAX_DEV) cnt = SCAN_MAX_DEV;
    device_t *devs = calloc(cnt, sizeof(device_t));
    int k = 0;
    GtkTreeModel *m = GTK_TREE_MODEL(s_dev_store);
    for (GList *l = rows; l && k < cnt; l = l->next) {
        GtkTreeIter it;
        if (gtk_tree_model_get_iter(m, &it, (GtkTreePath *)l->data)) {
            int id = 0;
            gtk_tree_model_get(m, &it, L_ID, &id, -1);
            if (id > 0 && db_device_get(g_app.db, id, &devs[k]) == 1)
                k++;
        }
    }
    g_list_free_full(rows, (GDestroyNotify)gtk_tree_path_free);
    *out = devs; *out_n = k;
    return 0;
}

/* ===== 清空实时结果视图 ===== */
static void clear_results(void) {
    if (s_results_box) {
        GList *kids = gtk_container_get_children(GTK_CONTAINER(s_results_box));
        for (GList *l = kids; l; l = l->next)
            gtk_widget_destroy(GTK_WIDGET(l->data));
        g_list_free(kids);
    }
    for (int i = 0; i < SCAN_MAX_DEV; i++) {
        if (g_group[i].used && g_group[i].store)
            g_object_unref(g_group[i].store);
        memset(&g_group[i], 0, sizeof(g_group[i]));
    }
    g_n_group = 0;
}
/* ===== 模式切换：范围输入仅在完整范围模式可用 ===== */
static void on_mode_toggled(GtkToggleButton *b, gpointer d) {
    (void)b; (void)d;
    int range = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s_rb_range));
    gtk_widget_set_sensitive(s_range_start, range);
    gtk_widget_set_sensitive(s_range_end, range);
}

static void on_refresh_devices(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    page_scan_reload_devices();
    app_status("设备列表已刷新");
}

/* ===== 停止 ===== */
static void on_stop(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    if (!s_running) return;
    scan_service_stop();
    gtk_widget_set_sensitive(s_btn_stop, FALSE);
    app_status("正在停止巡检……（保留已完成部分）");
}

/* 关闭窗口或退出时收尾：请求停止并等待线程结束 */
void page_scan_shutdown(void) {
    if (!s_running) return;
    scan_service_stop();
    pthread_join(s_thread, NULL);
    s_running = 0;
    app_set_scan_active(0);
}
/* ===== 设备选择变化时更新auto网卡显示 ===== */
static void update_auto_label(void) {
    /* 只在auto模式（第0项选中）时有效 */
    if (gtk_combo_box_get_active(GTK_COMBO_BOX(s_dev_iface)) != 0) return;
    if (s_updating_combo) return;

    device_t *devs = NULL; int ndev = 0;
    collect_selected(&devs, &ndev);

    s_updating_combo = 1;
    if (ndev == 0 || !devs[0].ip[0]) {
        /* 无选中设备：恢复默认文字 */
        gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(s_dev_iface), 0);
        gtk_combo_box_text_insert_text(GTK_COMBO_BOX_TEXT(s_dev_iface), 0, "auto（自动）");
    } else {
        char resolved[64];
        if (scanner_resolve_device(devs[0].ip, resolved, sizeof(resolved)) == 0) {
            char label[128];
            snprintf(label, sizeof(label), "auto(%s)", resolved);
            gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(s_dev_iface), 0);
            gtk_combo_box_text_insert_text(GTK_COMBO_BOX_TEXT(s_dev_iface), 0, label);
        }
    }
    gtk_combo_box_set_active(GTK_COMBO_BOX(s_dev_iface), 0);
    s_updating_combo = 0;
    free(devs);
}

static void on_device_selection_changed(GtkTreeSelection *sel, gpointer data) {
    (void)sel; (void)data;
    update_auto_label();
}

static void on_iface_changed(GtkComboBox *cb, gpointer data) {
    (void)cb; (void)data;
    if (s_updating_combo) return;
    if (gtk_combo_box_get_active(GTK_COMBO_BOX(s_dev_iface)) != 0) {
        /* 用户切换到了具体网卡：恢复第0项为默认文字 */
        s_updating_combo = 1;
        gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(s_dev_iface), 0);
        gtk_combo_box_text_insert_text(GTK_COMBO_BOX_TEXT(s_dev_iface), 0, "auto（自动）");
        s_updating_combo = 0;
    }
}

/* ===== 开始巡检 ===== */
static void on_start(GtkButton *b, gpointer d) {
    (void)b; (void)d;
    GtkWindow *win = GTK_WINDOW(g_app.window);
    if (s_running) return;

    device_t *devs = NULL; int ndev = 0;
    collect_selected(&devs, &ndev);
    if (ndev == 0) {
        free(devs);
        ui_error(win, "尚未选择设备。\n请在左侧选择至少一个要巡检的设备。");
        return;
    }

    int mode = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(s_rb_range)) ? 1 : 0;

    int range_start = 1, range_end = 1024;
    if (mode == 1) {
        range_start = atoi(gtk_entry_get_text(GTK_ENTRY(s_range_start)));
        range_end   = atoi(gtk_entry_get_text(GTK_ENTRY(s_range_end)));
        if (range_start < 1 || range_start > 65535 ||
            range_end < 1 || range_end > 65535) {
            free(devs);
            ui_error(win, "端口范围非法：请输入 1 - 65535 之间的端口。");
            return;
        }
        if (range_end < range_start) {
            free(devs);
            ui_error(win, "结束端口不能小于起始端口。");
            return;
        }
    }

    int timeout_ms = atoi(gtk_entry_get_text(GTK_ENTRY(s_timeout)));
    if (timeout_ms < 50)    timeout_ms = 50;

    scan_job_t *job = calloc(1, sizeof(*job));
    if (!job) { free(devs); ui_error(win, "内存不足。"); return; }
    {
        const char *dev = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(s_dev_iface));
        /* 将 "auto（自动）" 归一化为 "auto"，否则会被当成无效网卡名 */
        if (dev && dev[0] && strncmp(dev, "auto", 4) == 0)
            snprintf(job->device, sizeof(job->device), "auto");
        else if (dev && dev[0])
            snprintf(job->device, sizeof(job->device), "%s", dev);
        else
            snprintf(job->device, sizeof(job->device), "auto");
        if (dev) g_free((gpointer)dev);
    }
    job->mode = mode; job->range_start = range_start; job->range_end = range_end;
    job->timeout_ms = timeout_ms;

    char nopol[700];
    int total_ports = 0;
    if (scan_service_prepare(g_app.db, job, devs, ndev, &total_ports, nopol, sizeof(nopol)) != 0) {
        scan_service_free_job(job); free(devs); ui_error(win, "准备巡检任务失败。"); return;
    }
    /* 按策略模式：没有任何策略的设备需提示，不能默认为全端口扫描 */
    if (mode == 0 && nopol[0]) {
        ui_error(win,
            "以下设备尚未配置端口策略，无法按策略巡检：\n\n%s\n"
            "请在“端口策略”页为这些设备添加规则，"
            "或改用“完整端口范围”模式。", nopol);
        scan_service_free_job(job); free(devs);
        return;
    }

    /* 开始前确认 */
    char msg[2048]; int off = 0;
    off += snprintf(msg + off, sizeof(msg) - off, "即将开始巡检：\n\n");
    off += snprintf(msg + off, sizeof(msg) - off, "模式：%s\n",
                    mode == 0 ? "按端口策略" : "完整端口范围");
    if (mode == 1)
        off += snprintf(msg + off, sizeof(msg) - off,
                        "端口范围：%d - %d（含边界）\n", range_start, range_end);
    off += snprintf(msg + off, sizeof(msg) - off,
                    "每端口超时：%d 毫秒\n设备（%d 个）：\n", timeout_ms, ndev);
    for (int i = 0; i < ndev && off < (int)sizeof(msg) - 80; i++)
        off += snprintf(msg + off, sizeof(msg) - off,
                        "  · %s (%s)  共 %d 个端口\n",
                        job->devs[i].name, job->devs[i].ip, job->devs[i].n_ports);
    snprintf(msg + off, sizeof(msg) - off,
             "\n仅对您拥有或已获授权的设备执行巡检。确认开始？");

    if (!ui_confirm(win, "%s", msg)) { scan_service_free_job(job); free(devs); return; }
    free(devs);

    /* 在主连接上创建巡检记录与设备分组 */
    char err[256];
    if (scan_service_create_records(g_app.db, job, err, sizeof(err)) != 0) {
        ui_error(win, "创建巡检记录失败：%s", err);
        scan_service_free_job(job);
        return;
    }
    int scan_id = job->scan_id;
    /* 界面准备 */
    clear_results();
    s_total_ports = total_ports;
    s_done_ports = 0;
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(s_progress), 0.0);
    char pl[128];
    snprintf(pl, sizeof(pl), "已扫描 0 / %d 端口", s_total_ports);
    gtk_label_set_text(GTK_LABEL(s_progress_lbl), pl);

    s_running = 1;

    app_set_scan_active(1);
    gtk_widget_set_sensitive(s_btn_start, FALSE);
    gtk_widget_set_sensitive(s_btn_stop, TRUE);
    gtk_widget_set_visible(s_spinner, TRUE);
    gtk_spinner_start(GTK_SPINNER(s_spinner));
    app_status("巡检进行中……");

    scan_service_reset();
    snprintf(job->db_path, sizeof(job->db_path), "%s", g_app.db_path);
    job->callback = dispatch_scan_event;
    if (pthread_create(&s_thread, NULL, scan_service_run, job) != 0) {
        ui_error(win, "无法启动扫描线程。");
        db_scan_finish(g_app.db, scan_id, RUN_FAILED);
        s_running = 0;
        app_set_scan_active(0);
        gtk_widget_set_sensitive(s_btn_start, TRUE);
        gtk_widget_set_sensitive(s_btn_stop, FALSE);
        gtk_spinner_stop(GTK_SPINNER(s_spinner));
        gtk_widget_set_visible(s_spinner, FALSE);
        scan_service_free_job(job);
        return;
    }
}
/* ===== 构建页面 ===== */
GtkWidget *page_scan_build(void) {
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_container_set_border_width(GTK_CONTAINER(hbox), 8);

    /* 左：设备多选 */
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(hbox), left, FALSE, TRUE, 0);

    GtkWidget *ltitle = gtk_label_new("选择设备（按住 Ctrl / Shift 可多选）");
    gtk_label_set_xalign(GTK_LABEL(ltitle), 0.0f);
    gtk_box_pack_start(GTK_BOX(left), ltitle, FALSE, FALSE, 0);

    GtkWidget *lsw = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(lsw, 330, -1);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(lsw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(left), lsw, TRUE, TRUE, 0);

    s_dev_store = gtk_list_store_new(L_N,
        G_TYPE_INT, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    s_dev_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(s_dev_store));
    g_object_unref(s_dev_store);
    gtk_tree_view_set_grid_lines(GTK_TREE_VIEW(s_dev_tree), GTK_TREE_VIEW_GRID_LINES_HORIZONTAL);

    const char *lt[] = {"设备名称", "IP 地址", "策略端口"};
    int lc[]   = {L_NAME, L_IP, L_POL};
    int lw[]   = {140, 120, 90};
    for (int i = 0; i < 3; i++) {
        GtkCellRenderer *r = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *col = gtk_tree_view_column_new_with_attributes(
            lt[i], r, "text", lc[i], NULL);
        gtk_tree_view_column_set_resizable(col, TRUE);
        gtk_tree_view_column_set_min_width(col, lw[i]);
        gtk_tree_view_append_column(GTK_TREE_VIEW(s_dev_tree), col);
    }
    GtkTreeSelection *sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(s_dev_tree));
    gtk_tree_selection_set_mode(sel, GTK_SELECTION_MULTIPLE);
    g_signal_connect(sel, "changed", G_CALLBACK(on_device_selection_changed), NULL);
    gtk_container_add(GTK_CONTAINER(lsw), s_dev_tree);

    s_btn_refresh = gtk_button_new_with_label("刷新设备");
    g_signal_connect(s_btn_refresh, "clicked", G_CALLBACK(on_refresh_devices), NULL);
    gtk_box_pack_start(GTK_BOX(left), s_btn_refresh, FALSE, FALSE, 0);

    /* 右：设置 + 结果 */
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_box_pack_start(GTK_BOX(hbox), right, TRUE, TRUE, 0);

    GtkWidget *setframe = gtk_frame_new("巡检设置");
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 8);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 8);
    gtk_container_add(GTK_CONTAINER(setframe), grid);

    s_rb_policy = gtk_radio_button_new_with_label(NULL, "按端口策略巡检（默认）");
    s_rb_range  = gtk_radio_button_new_with_label_from_widget(
                      GTK_RADIO_BUTTON(s_rb_policy), "完整端口范围巡检");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(s_rb_policy), TRUE);
    gtk_grid_attach(GTK_GRID(grid), s_rb_policy, 0, 0, 4, 1);
    gtk_grid_attach(GTK_GRID(grid), s_rb_range, 0, 1, 4, 1);
    g_signal_connect(s_rb_range, "toggled", G_CALLBACK(on_mode_toggled), NULL);

    GtkWidget *lrs = gtk_label_new("起始端口:");
    gtk_widget_set_halign(lrs, GTK_ALIGN_END);
    s_range_start = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(s_range_start), "1");
    gtk_widget_set_size_request(s_range_start, 90, -1);
    GtkWidget *lre = gtk_label_new("结束端口:");
    gtk_widget_set_halign(lre, GTK_ALIGN_END);
    s_range_end = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(s_range_end), "1024");
    gtk_widget_set_size_request(s_range_end, 90, -1);
    gtk_grid_attach(GTK_GRID(grid), lrs, 0, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), s_range_start, 1, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), lre, 2, 2, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), s_range_end, 3, 2, 1, 1);

    GtkWidget *lto = gtk_label_new("每端口超时(ms):");
    gtk_widget_set_halign(lto, GTK_ALIGN_END);
    s_timeout = gtk_entry_new();
    char tb[16]; snprintf(tb, sizeof(tb), "%d", DEFAULT_TIMEOUT_MS);
    gtk_entry_set_text(GTK_ENTRY(s_timeout), tb);
    gtk_widget_set_size_request(s_timeout, 90, -1);
    gtk_grid_attach(GTK_GRID(grid), lto, 0, 3, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), s_timeout, 1, 3, 1, 1);

    GtkWidget *btnbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    s_btn_start = gtk_button_new_with_label("开始巡检");
    s_btn_stop  = gtk_button_new_with_label("停止");
    gtk_widget_set_sensitive(s_btn_stop, FALSE);
    s_spinner = gtk_spinner_new();
    gtk_widget_set_visible(s_spinner, FALSE);
    g_signal_connect(s_btn_start, "clicked", G_CALLBACK(on_start), NULL);
    g_signal_connect(s_btn_stop, "clicked", G_CALLBACK(on_stop), NULL);
    gtk_box_pack_start(GTK_BOX(btnbox), s_btn_start, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btnbox), s_btn_stop, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(btnbox), s_spinner, FALSE, FALSE, 0);
    gtk_grid_attach(GTK_GRID(grid), btnbox, 0, 6, 4, 1);

    /* 网卡选择（grid 第 4 行） */
    GtkWidget *ldev = gtk_label_new("网卡:");
    gtk_widget_set_halign(ldev, GTK_ALIGN_END);
    gtk_widget_set_size_request(ldev, 100, -1);
    s_dev_iface = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(s_dev_iface), "auto（自动）");
    gtk_combo_box_set_active(GTK_COMBO_BOX(s_dev_iface), 0);
    g_signal_connect(s_dev_iface, "changed", G_CALLBACK(on_iface_changed), NULL);
    {
        char eb[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs = NULL;
        if (pcap_findalldevs(&alldevs, eb) == 0 && alldevs) {
            for (pcap_if_t *d = alldevs; d; d = d->next)
                gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(s_dev_iface), d->name);
            pcap_freealldevs(alldevs);
        }
    }
    gtk_widget_set_size_request(s_dev_iface, 160, -1);
    gtk_grid_attach(GTK_GRID(grid), ldev, 0, 5, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), s_dev_iface, 1, 5, 3, 1);
    gtk_widget_show_all(grid);
    gtk_box_pack_start(GTK_BOX(right), setframe, FALSE, FALSE, 0);

    s_progress = gtk_progress_bar_new();
    gtk_box_pack_start(GTK_BOX(right), s_progress, FALSE, FALSE, 0);
    s_progress_lbl = gtk_label_new("尚未开始");
    gtk_label_set_xalign(GTK_LABEL(s_progress_lbl), 0.0f);
    gtk_box_pack_start(GTK_BOX(right), s_progress_lbl, FALSE, FALSE, 0);

    GtkWidget *resframe = gtk_frame_new("实时结果（按设备分组）");
    GtkWidget *resvbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_container_set_border_width(GTK_CONTAINER(resvbox), 6);
    gtk_container_add(GTK_CONTAINER(resframe), resvbox);
    GtkWidget *rsw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(rsw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    s_results_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_add(GTK_CONTAINER(rsw), s_results_box);
    gtk_box_pack_start(GTK_BOX(resvbox), rsw, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(right), resframe, TRUE, TRUE, 0);

    on_mode_toggled(NULL, NULL);   /* 初始按策略模式，禁用范围输入 */
    page_scan_reload_devices();
    return hbox;
}
