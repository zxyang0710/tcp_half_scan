/* 巡检执行服务：不依赖 GTK，事件由调用方投递到界面线程。 */
#include "scan_service.h"
#include "scanner.h"
#include "domain.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 原子停止标志：停止请求可由其他线程设置，扫描线程读取。 */
static atomic_int s_stop_req;

/* 当前扫描上下文；通过互斥锁保护其发布、停止和清空操作。 */
static scan_context_t *s_ctx;
static pthread_mutex_t s_ctx_mtx = PTHREAD_MUTEX_INITIALIZER;

/* 开始新一轮巡检前清除停止标志。 */
void scan_service_reset(void) { atomic_store(&s_stop_req, 0); }

/* 请求停止整轮巡检，同时通知当前扫描器停止；本函数不等待线程退出。 */
void scan_service_stop(void) {
    atomic_store(&s_stop_req, 1);
    pthread_mutex_lock(&s_ctx_mtx);
    if (s_ctx) scanner_stop(s_ctx);
    pthread_mutex_unlock(&s_ctx_mtx);
}

/* ===== 后台线程：每端口结果回调 ===== */

/* 单台设备的运行数据，作为端口结果回调的用户参数。 */
typedef struct {
    sqlite3    *conn;     // 数据库连接，用于保存端口结果、更新设备可达状态
    scan_job_t *job;      // 指向整个扫描作业，可获取设备策略、扫描模式及事件回调
    int         idx;      // 当前设备在 job->devs 数组中的下标，从 0 开始
    int         scan_id;  // 本轮巡检在数据库中的记录 ID
    int         sd_id;    // 当前设备在本轮巡检中的设备记录 ID
    int         open;     // 当前设备已得到结果的开放端口数
    int         closed;   // 当前设备已得到结果的关闭端口数
    int         filtered; // 当前设备的无响应/过滤状态端口数
} dev_run_t;

/* 处理单个端口结果：匹配策略、计算判定、写入数据库并发送事件。 */
static void on_port_result(const scan_result_t *r, void *ud) {
    dev_run_t *d = ud;
    /* 将扫描器状态转换为业务状态字符串。 */
    const char *base_actual = (r->status == PORT_OPEN) ? ST_OPEN : (r->status == PORT_CLOSED) ? ST_CLOSED : ST_FILTERED;
    /* 任意端口有回应即可确认主机可达，但不能据此确认无响应端口已关闭。 */
    if (strcmp(base_actual, ST_FILTERED) == 0 && (d->open + d->closed > 0))  base_actual = ST_FILTERED_REACHABLE;
    else if (strcmp(base_actual, ST_FILTERED) != 0 && d->open + d->closed == 0) {
        /* 首次收到回应：此前落库的无响应端口也可确认主机可达。 */
        db_scan_mark_reachable(d->conn, d->sd_id);
        scan_reachable_event_t *mark = calloc(1, sizeof(*mark));
        if (mark) { mark->idx = d->idx; d->job->callback(SCAN_REACHABLE, mark); }
    }
    const char *actual = base_actual;

    /* 根据端口号查找本次作业保存的策略；未匹配时保持空字符串。 */
    const char *expected = "";
    for (int i = 0; i < d->job->devs[d->idx].n_pol; i++) {
        if (d->job->devs[d->idx].pol[i].port == r->port) {
            expected = d->job->devs[d->idx].pol[i].exp;
            break;
        }
    }
    /* 将实际状态与预期策略交给领域函数，生成中文判定。 */
    char verdict[64];
    domain_compute_verdict(d->job->mode, actual, expected, verdict, sizeof(verdict));
    /* 统计开放、关闭和无响应端口；无响应仍不能确定端口是否关闭。 */
    if (strcmp(actual, ST_OPEN) == 0)        d->open++;
    else if (strcmp(actual, ST_CLOSED) == 0) d->closed++;
    else                                     d->filtered++;

    /* 保存端口明细；此处没有检查数据库插入的返回结果。 */
    db_scan_result_insert(d->conn, d->scan_id, d->sd_id, r->port,
                          "TCP", r->service, actual, expected, verdict, NULL, 0);

    /* 事件对象在堆上分配，调用方需按约定处理其生命周期。 */
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
/* 释放各设备的动态端口数组、策略数组以及作业本身。 */
void scan_service_free_job(scan_job_t *job) {
    if (!job) return;
    for (int i = 0; i < job->n_devices; i++) {
        free(job->devs[i].ports);
        free(job->devs[i].pol);
    }
    free(job);
}

/* ===== 后台线程主函数 ===== */
/* 后台线程入口：依次扫描各设备，汇总结果并释放作业。 */
void *scan_service_run(void *arg) {
    scan_job_t *job = arg;
    char dberr[256];
    sqlite3 *conn = NULL;

    /* 为后台工作打开数据库连接；失败时发送设备失败及整轮失败事件。 */
    if (db_open(job->db_path, &conn, dberr, sizeof(dberr)) != 0) {
        /* 对每台设备：先添加设备，再标记失败 */
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

    /* 整轮端口计数，以及用于选择最终状态的设备完成/失败标志。 */
    int total_open = 0, total_closed = 0, total_filtered = 0;
    int any_failed = 0, any_completed = 0;
    int started = 0;

    for (int i = 0; i < job->n_devices; i++) {
        if (s_stop_req) break;
        job_dev_t *d = &job->devs[i];
        /* 记录已进入处理流程的设备数，用于后续补记未执行设备。 */
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

        /* 发布当前上下文，使其他线程能通过停止接口通知扫描器。 */
        pthread_mutex_lock(&s_ctx_mtx);
        s_ctx = ctx;
        pthread_mutex_unlock(&s_ctx_mtx);

        /* 通知调用方本设备进入处理流程，携带名称、IP 和计划端口数。 */
        scan_device_event_t *a = calloc(1, sizeof(*a));
        a->idx = i;
        snprintf(a->name, sizeof(a->name), "%s", d->name);
        snprintf(a->ip, sizeof(a->ip), "%s", d->ip);
        a->total = d->n_ports;
        job->callback(SCAN_DEVICE, a);

        /* 初始化本设备的回调数据和端口统计。 */
        dev_run_t dr;
        memset(&dr, 0, sizeof(dr));
        dr.conn = conn; dr.job = job; dr.idx = i;
        dr.scan_id = job->scan_id; dr.sd_id = d->sd_id;

        scan_stats_t st;
        memset(&st, 0, sizeof(st));
        /* 执行端口扫描，每个端口的结果由 on_port_result 处理。 */
        int rc = scanner_scan_ports(ctx, d->ip, d->ports, d->n_ports,
                                    job->timeout_ms, on_port_result, NULL,
                                    &dr, &st, errbuf);

        /* 设备状态优先级：扫描出错、停止或未完成、正常完成。 */
        const char *dstat;  // 该设备最终状态
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

        /* 持久化设备最终状态，并累加已得到结果的端口数。 */
        db_scan_device_finish(conn, d->sd_id, dstat, derr);
        total_open += dr.open; total_closed += dr.closed; total_filtered += dr.filtered;

        scan_device_done_event_t *dd = calloc(1, sizeof(*dd));
        dd->idx = i;
        snprintf(dd->status, sizeof(dd->status), "%s", dstat);
        /* 已扫描数按已收到结果的端口统计，停止时可能小于计划数。 */
        dd->scanned = dr.open + dr.closed + dr.filtered;
        dd->open = dr.open; dd->closed = dr.closed; dd->filtered = dr.filtered;
        dd->total = d->n_ports;
        job->callback(SCAN_DEVICE_DONE, dd);

        /* --- 释放本设备的上下文 --- */
        /* 发布当前上下文，使其他线程能通过停止接口通知扫描器。 */
        pthread_mutex_lock(&s_ctx_mtx);
        s_ctx = NULL;
        pthread_mutex_unlock(&s_ctx_mtx);
        scanner_cleanup(ctx);
    }

    /* 因停止而未执行的设备：标记为已停止 */
    for (int i = started; i < job->n_devices; i++) {
        db_scan_device_finish(conn, job->devs[i].sd_id, RUN_STOPPED, "");
        /* 通知调用方本设备进入处理流程，携带名称、IP 和计划端口数。 */
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

    /* 整轮状态：停止优先；否则只要有设备完成即记完成，即使其他设备失败。 */
    const char *overall;
    if (s_stop_req)                          overall = RUN_STOPPED;
    else if (any_completed)                  overall = RUN_COMPLETED;
    else if (any_failed)                     overall = RUN_FAILED;
    else                                     overall = RUN_COMPLETED;

    /* 保存整轮状态，关闭后台连接，然后发送汇总事件。 */
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
/* 将设备策略格式化为快照文本；调用方须提供有效且容量大于 0 的缓冲区。 */
void scan_service_snapshot(sqlite3 *db, int dev_id, char *out, int outlen) {
    out[0] = '\0';
    policy_t *arr = NULL; int n = 0;
    /* 读取策略数组，使用后通过 db_free 释放。 */
    if (db_policy_snapshot(db, dev_id, &arr, &n) != 0) return;
    int off = 0;
    /* 按剩余空间尝试追加端口、预期及用途；snprintf 返回的是所需长度。 */
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


/*
 * 准备作业：复制设备信息和策略，构建各设备待扫描端口数组。
 * mode == 0 按策略扫描，否则按给定范围构建端口。
 * total_ports 返回计划端口总数，missing 收集没有策略的设备。
 * 返回 0 表示准备完成，-1 表示设备数非法或内存分配失败。
 * 调用方应预先初始化作业、校验端口范围，并在失败后清理已分配资源。
 */
int scan_service_prepare(sqlite3 *db, scan_job_t *job, const device_t *devs, int ndev,
                         int *total_ports, char *missing, int missing_len) {
    /* 限制设备数量，防止超出作业支持的容量。 */
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

        /* 复制策略到作业中，供后台回调按端口查找预期状态。 */
        policy_t *pol = NULL; int npol = 0;
        db_policy_snapshot(db, devs[i].id, &pol, &npol);
        jd->n_pol = 0;  // 已经保存的端口数
        jd->pol = calloc(npol > 0 ? npol : 1, sizeof(pol_ent_t));
        if (!jd->pol) { db_free(pol); return -1; }
        for (int j = 0; j < npol; j++) {
            jd->pol[jd->n_pol].port = (uint16_t)pol[j].port;
            snprintf(jd->pol[jd->n_pol].exp, sizeof(jd->pol[jd->n_pol].exp),
                     "%s", pol[j].expected);
            jd->n_pol++;
        }
        if (pol) db_free(pol);

        /* 策略模式只扫描已配置策略的端口；范围模式包含起止端口。 */
        if (mode == 0) {
            if (jd->n_pol == 0) {       // 当前设备没有配置策略
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
        /* 累计所有设备的计划扫描端口数。 */
        *total_ports += jd->n_ports;
    }


    return 0;
}

/*
 * 创建整轮巡检记录以及各设备巡检记录，将生成的 ID 保存到作业。
 * 返回 0 表示成功，-1 表示创建失败。
 * 此函数自身未开启事务：设备记录创建失败时，将整轮标为失败，保留已有记录。
 */
int scan_service_create_records(sqlite3 *db, scan_job_t *job, char *err, int errlen) {
    int mode = job->mode, range_start = job->range_start, range_end = job->range_end;
    /* 先创建整轮记录，获得后续设备记录引用的 scan_id。 */
    int scan_id = db_scan_create(db, mode == 1 ? MODE_RANGE : MODE_POLICY,
                                 range_start, range_end, err, errlen);
    if (scan_id <= 0) return -1;
    job->scan_id = scan_id;

    int ok = 1;
    for (int i = 0; i < job->n_devices; i++) {
        job_dev_t *jd = &job->devs[i];
        /* 范围模式记录指定边界；策略模式记录端口数组的首尾值。 */
        int rs = 0, re = 0;
        if (mode == 1) { rs = range_start; re = range_end; }
        else if (jd->n_ports > 0) { rs = jd->ports[0]; re = jd->ports[jd->n_ports - 1]; }
        /* 保存设备身份、计划端口数、端口边界及当时的策略快照。 */
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
