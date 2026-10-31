/* 巡检执行服务：不依赖 GTK，事件由调用方投递到界面线程。 */
#include "scan_service.h"
#include "scanner.h"
#include "domain.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static atomic_int s_stop_req;
static scan_context_t *s_ctx;
static pthread_mutex_t s_ctx_mtx = PTHREAD_MUTEX_INITIALIZER;
void scan_service_reset(void) { atomic_store(&s_stop_req, 0); }
void scan_service_stop(void) {
    atomic_store(&s_stop_req, 1);
    pthread_mutex_lock(&s_ctx_mtx);
    if (s_ctx) scanner_stop(s_ctx);
    pthread_mutex_unlock(&s_ctx_mtx);
}
/* ===== 后台线程：每端口结果回调 ===== */

typedef struct {
    sqlite3    *conn;
    scan_job_t *job;
    int         idx;
    int         scan_id;
    int         sd_id;
    int         open, closed, filtered;
} dev_run_t;

static void on_port_result(const scan_result_t *r, void *ud) {
    dev_run_t *d = ud;
    const char *base_actual = (r->status == PORT_OPEN) ? ST_OPEN
                       : (r->status == PORT_CLOSED) ? ST_CLOSED : ST_FILTERED;
    if (strcmp(base_actual, ST_FILTERED) == 0 && (d->open + d->closed > 0)) {
        base_actual = ST_FILTERED_REACHABLE;
    } else if (strcmp(base_actual, ST_FILTERED) != 0 && d->open + d->closed == 0) {
        /* 首次收到回应：此前落库的无响应端口也可确认主机可达。 */
        db_scan_mark_reachable(d->conn, d->sd_id);
        scan_reachable_event_t *mark = calloc(1, sizeof(*mark));
        if (mark) { mark->idx = d->idx; d->job->callback(SCAN_REACHABLE, mark); }
    }
    const char *actual = base_actual;

    const char *expected = "";
    for (int i = 0; i < d->job->devs[d->idx].n_pol; i++) {
        if (d->job->devs[d->idx].pol[i].port == r->port) {
            expected = d->job->devs[d->idx].pol[i].exp;
            break;
        }
    }
    char verdict[64];
    domain_compute_verdict(d->job->mode, actual, expected, verdict, sizeof(verdict));
    /* 主机可达推断：只要有任意端口有回应，无响应端口极可能是OS静默关闭而非被过滤 */
    if (strcmp(actual, ST_OPEN) == 0)        d->open++;
    else if (strcmp(actual, ST_CLOSED) == 0) d->closed++;
    else                                     d->filtered++;

    db_scan_result_insert(d->conn, d->scan_id, d->sd_id, r->port,
                          "TCP", r->service, actual, expected, verdict, NULL, 0);

    scan_port_event_t *p = calloc(1, sizeof(*p));
    p->idx = d->idx;
    p->port = r->port;
    snprintf(p->actual, sizeof(p->actual), "%s", actual);
    snprintf(p->service, sizeof(p->service), "%s", r->service);
    snprintf(p->expected, sizeof(p->expected), "%s", expected);
    snprintf(p->verdict, sizeof(p->verdict), "%s", verdict);
    d->job->callback(SCAN_PORT, p);
}

/* ===== 释放作业内存 ===== */
void scan_service_free_job(scan_job_t *job) {
    if (!job) return;
    for (int i = 0; i < job->n_devices; i++) {
        free(job->devs[i].ports);
        free(job->devs[i].pol);
    }
    free(job);
}

/* ===== 后台线程主函数 ===== */
void *scan_service_run(void *arg) {
    scan_job_t *job = arg;
    char dberr[256];
    sqlite3 *conn = NULL;

    if (db_open(job->db_path, &conn, dberr, sizeof(dberr)) != 0) {
        for (int i = 0; i < job->n_devices; i++) {
            scan_device_event_t *a = calloc(1, sizeof(*a));
            a->idx = i;
            snprintf(a->name, sizeof(a->name), "%s", job->devs[i].name);
            snprintf(a->ip, sizeof(a->ip), "%s", job->devs[i].ip);
            a->total = job->devs[i].n_ports;
            job->callback(SCAN_DEVICE, a);
            scan_device_done_event_t *dd = calloc(1, sizeof(*dd));
            dd->idx = i;
            snprintf(dd->status, sizeof(dd->status), "%s", RUN_FAILED);
            dd->total = job->devs[i].n_ports;
            job->callback(SCAN_DEVICE_DONE, dd);
        }
        scan_finish_event_t *p = calloc(1, sizeof(*p));
        p->scan_id = job->scan_id;
        snprintf(p->status, sizeof(p->status), "%s", RUN_FAILED);
        job->callback(SCAN_FINISH, p);
        scan_service_free_job(job);
        return NULL;
    }

    /* 手动指定了网卡 → 所有设备都用这个；否则 auto → 每个设备独立解析 */
    const char *manual_iface = NULL;
    if (job->device[0] && strcmp(job->device, "auto") != 0)
        manual_iface = job->device;

    int total_open = 0, total_closed = 0, total_filtered = 0;
    int any_failed = 0, any_completed = 0;
    int started = 0;

    for (int i = 0; i < job->n_devices; i++) {
        if (s_stop_req) break;
        job_dev_t *d = &job->devs[i];
        started = i + 1;

        /* --- 为本设备解析网卡 --- */
        char errbuf[256];
        char resolved_dev[64] = {0};
        const char *iface = manual_iface;
        if (!iface) {
            /* auto模式：用本设备的IP查路由表，失败则回退到默认检测 */
            if (scanner_resolve_device(d->ip, resolved_dev, sizeof(resolved_dev)) == 0)
                iface = resolved_dev;
        }

        /* --- 为本设备创建扫描上下文 --- */
        scan_context_t *ctx = scanner_init(iface, errbuf);
        if (!ctx) {
            db_scan_device_finish(conn, d->sd_id, RUN_FAILED, errbuf);
            scan_device_event_t *a = calloc(1, sizeof(*a));
            a->idx = i;
            snprintf(a->name, sizeof(a->name), "%s", d->name);
            snprintf(a->ip, sizeof(a->ip), "%s", d->ip);
            a->total = d->n_ports;
            job->callback(SCAN_DEVICE, a);
            scan_device_done_event_t *dd = calloc(1, sizeof(*dd));
            dd->idx = i;
            snprintf(dd->status, sizeof(dd->status), "%s", RUN_FAILED);
            dd->total = d->n_ports;
            job->callback(SCAN_DEVICE_DONE, dd);
            any_failed = 1;
            continue;
        }

        pthread_mutex_lock(&s_ctx_mtx);
        s_ctx = ctx;
        pthread_mutex_unlock(&s_ctx_mtx);

        scan_device_event_t *a = calloc(1, sizeof(*a));
        a->idx = i;
        snprintf(a->name, sizeof(a->name), "%s", d->name);
        snprintf(a->ip, sizeof(a->ip), "%s", d->ip);
        a->total = d->n_ports;
        job->callback(SCAN_DEVICE, a);

        dev_run_t dr;
        memset(&dr, 0, sizeof(dr));
        dr.conn = conn; dr.job = job; dr.idx = i;
        dr.scan_id = job->scan_id; dr.sd_id = d->sd_id;

        scan_stats_t st;
        memset(&st, 0, sizeof(st));
        int rc = scanner_scan_ports(ctx, d->ip, d->ports, d->n_ports,
                                    job->timeout_ms, on_port_result, NULL,
                                    &dr, &st, errbuf);

        const char *dstat;
        char derr[256]; derr[0] = '\0';
        if (rc != 0) {
            dstat = RUN_FAILED;
            snprintf(derr, sizeof(derr), "%s", errbuf);
            any_failed = 1;
        } else if (s_stop_req || !st.completed) {
            dstat = RUN_STOPPED;
        } else {
            dstat = RUN_COMPLETED;
            any_completed = 1;
        }

        db_scan_device_finish(conn, d->sd_id, dstat, derr);
        total_open += dr.open; total_closed += dr.closed; total_filtered += dr.filtered;

        scan_device_done_event_t *dd = calloc(1, sizeof(*dd));
        dd->idx = i;
        snprintf(dd->status, sizeof(dd->status), "%s", dstat);
        dd->scanned = dr.open + dr.closed + dr.filtered;
        dd->open = dr.open; dd->closed = dr.closed; dd->filtered = dr.filtered;
        dd->total = d->n_ports;
        job->callback(SCAN_DEVICE_DONE, dd);

        /* --- 释放本设备的上下文 --- */
        pthread_mutex_lock(&s_ctx_mtx);
        s_ctx = NULL;
        pthread_mutex_unlock(&s_ctx_mtx);
        scanner_cleanup(ctx);
    }

    /* 因停止而未执行的设备：标记为已停止 */
    for (int i = started; i < job->n_devices; i++) {
        db_scan_device_finish(conn, job->devs[i].sd_id, RUN_STOPPED, "");
        scan_device_event_t *a = calloc(1, sizeof(*a));
        a->idx = i;
        snprintf(a->name, sizeof(a->name), "%s", job->devs[i].name);
        snprintf(a->ip, sizeof(a->ip), "%s", job->devs[i].ip);
        a->total = job->devs[i].n_ports;
        job->callback(SCAN_DEVICE, a);
        scan_device_done_event_t *dd = calloc(1, sizeof(*dd));
        dd->idx = i;
        snprintf(dd->status, sizeof(dd->status), "%s", RUN_STOPPED);
        dd->total = job->devs[i].n_ports;
        job->callback(SCAN_DEVICE_DONE, dd);
    }

    const char *overall;
    if (s_stop_req)                          overall = RUN_STOPPED;
    else if (any_completed)                  overall = RUN_COMPLETED;
    else if (any_failed)                     overall = RUN_FAILED;
    else                                     overall = RUN_COMPLETED;

    db_scan_finish(conn, job->scan_id, overall);
    db_close(conn);

    scan_finish_event_t *p = calloc(1, sizeof(*p));
    p->scan_id = job->scan_id;
    snprintf(p->status, sizeof(p->status), "%s", overall);
    p->open = total_open; p->closed = total_closed; p->filtered = total_filtered;
    job->callback(SCAN_FINISH, p);

    scan_service_free_job(job);
    return NULL;
}
/* ===== 策略快照文本 ===== */
void scan_service_snapshot(sqlite3 *db, int dev_id, char *out, int outlen) {
    out[0] = '\0';
    policy_t *arr = NULL; int n = 0;
    if (db_policy_snapshot(db, dev_id, &arr, &n) != 0) return;
    int off = 0;
    for (int i = 0; i < n && off < outlen - 48; i++) {
        off += snprintf(out + off, outlen - off, "端口 %d  预期%s",
                        arr[i].port,
                        strcmp(arr[i].expected, EXP_OPEN) == 0 ? "开放" : "关闭");
        if (arr[i].purpose[0])
            off += snprintf(out + off, outlen - off, "  用途: %s", arr[i].purpose);
        off += snprintf(out + off, outlen - off, "\n");
    }
    db_free(arr);
}


int scan_service_prepare(sqlite3 *db, scan_job_t *job, const device_t *devs, int ndev,
                         int *total_ports, char *missing, int missing_len) {
    if (ndev < 1 || ndev > SCAN_MAX_DEV) return -1;
    int mode = job->mode, range_start = job->range_start, range_end = job->range_end;
    job->n_devices = ndev;
    *total_ports = 0; missing[0] = '\0';
    for (int i = 0; i < ndev; i++) {
        job_dev_t *jd = &job->devs[i];
        jd->id = devs[i].id;
        snprintf(jd->name, sizeof(jd->name), "%s", devs[i].name);
        snprintf(jd->ip, sizeof(jd->ip), "%s", devs[i].ip);
        scan_service_snapshot(db, devs[i].id, jd->snapshot, sizeof(jd->snapshot));

        policy_t *pol = NULL; int npol = 0;
        db_policy_snapshot(db, devs[i].id, &pol, &npol);
        jd->n_pol = 0;
        jd->pol = calloc(npol > 0 ? npol : 1, sizeof(pol_ent_t));
        if (!jd->pol) { db_free(pol); return -1; }
        for (int j = 0; j < npol; j++) {
            jd->pol[jd->n_pol].port = (uint16_t)pol[j].port;
            snprintf(jd->pol[jd->n_pol].exp, sizeof(jd->pol[jd->n_pol].exp),
                     "%s", pol[j].expected);
            jd->n_pol++;
        }
        if (pol) db_free(pol);

        if (mode == 0) {
            if (jd->n_pol == 0) {
                int off = (int)strlen(missing);
                snprintf(missing + off, missing_len - off, "  · %s (%s)\n",
                         devs[i].name, devs[i].ip);
            }
            jd->n_ports = jd->n_pol;
            jd->ports = calloc(jd->n_ports > 0 ? jd->n_ports : 1, sizeof(uint16_t));
            if (!jd->ports) return -1;
            for (int j = 0; j < jd->n_ports; j++) jd->ports[j] = jd->pol[j].port;
        } else {
            int cnt = range_end - range_start + 1;
            jd->n_ports = cnt;
            jd->ports = calloc(cnt, sizeof(uint16_t));
            if (!jd->ports) return -1;
            for (int j = 0; j < cnt; j++) jd->ports[j] = (uint16_t)(range_start + j);
        }
        *total_ports += jd->n_ports;
    }


    return 0;
}

int scan_service_create_records(sqlite3 *db, scan_job_t *job, char *err, int errlen) {
    int mode = job->mode, range_start = job->range_start, range_end = job->range_end;
    int scan_id = db_scan_create(db, mode == 1 ? MODE_RANGE : MODE_POLICY,
                                 range_start, range_end, err, errlen);
    if (scan_id <= 0) return -1;
    job->scan_id = scan_id;

    int ok = 1;
    for (int i = 0; i < job->n_devices; i++) {
        job_dev_t *jd = &job->devs[i];
        int rs = 0, re = 0;
        if (mode == 1) { rs = range_start; re = range_end; }
        else if (jd->n_ports > 0) { rs = jd->ports[0]; re = jd->ports[jd->n_ports - 1]; }
        int sd_id = db_scan_device_create(db, scan_id, jd->id,
                                          jd->name, jd->ip, jd->n_ports,
                                          rs, re, jd->snapshot, err, errlen);
        if (sd_id <= 0) { ok = 0; break; }
        jd->sd_id = sd_id;
    }
    if (!ok) {
        db_scan_finish(db, scan_id, RUN_FAILED);
        return -1;
    }

    return 0;
}
