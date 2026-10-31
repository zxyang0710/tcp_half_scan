/*
 * db.c - 授权暴露面巡检工具 数据层实现
 */

#include "db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#if defined(_WIN32)
#include <direct.h>
#endif

/* ===== 通用工具 ===== */

void db_free(void *p) { free(p); }

/* 生成 "YYYY-MM-DD HH:MM:SS" 本地时间戳 */
static void now_str(char *buf, int len) {
    time_t t = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tmv);
}

static void set_err(char *err, int errlen, const char *fmt, const char *arg) {
    if (err && errlen > 0) {
        if (arg) snprintf(err, errlen, fmt, arg);
        else     snprintf(err, errlen, "%s", fmt);
    }
}

/* 复制字符串到定长缓冲区 */
static void cpy(char *dst, size_t n, const char *src) {
    if (!n) return;
    if (!src) { dst[0] = '\0'; return; }
    snprintf(dst, n, "%s", src);
}

/* 从结果集的第 col 列取字符串（NULL 安全） */
static const char *col_text(sqlite3_stmt *st, int col) {
    const unsigned char *t = sqlite3_column_text(st, col);
    return t ? (const char *)t : "";
}

static void cpy_col(char *dst, size_t n, sqlite3_stmt *st, int col) {
    cpy(dst, n, col_text(st, col));
}

/* 递归创建目录（类似 mkdir -p） */
static int mkdir_p(const char *path) {
    char tmp[1024];
    size_t len;
    cpy(tmp, sizeof(tmp), path);
    len = strlen(tmp);
    if (len == 0) return -1;
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char save = *p;
            *p = '\0';
#if defined(_WIN32)
            _mkdir(tmp);
#else
            mkdir(tmp, 0755);
#endif
            *p = save;
        }
    }
#if defined(_WIN32)
    _mkdir(tmp);
#else
    mkdir(tmp, 0755);
#endif
    return 0;
}

/* 默认数据库路径：用户数据目录，避免写进源码目录 */
int db_default_path(char *buf, int len) {
    const char *env = getenv("SCANNER_DB");
    if (env && *env) {
        cpy(buf, len, env);
        return 0;
    }
    const char *home = getenv("HOME");
#if defined(_WIN32)
    if (!home || !*home) home = getenv("USERPROFILE");
#endif
    if (!home || !*home) home = ".";
    const char *xdg = getenv("XDG_DATA_HOME");
    char dir[1024];
    if (xdg && *xdg) {
        snprintf(dir, sizeof(dir), "%s/cyber_exposure", xdg);
    } else {
        snprintf(dir, sizeof(dir), "%s/.local/share/cyber_exposure", home);
    }
    mkdir_p(dir);
    snprintf(buf, len, "%s/audit.db", dir);
    return 0;
}

/* 打开数据库并设置基本 PRAGMA */
int db_open(const char *path, sqlite3 **out_db, char *err, int errlen) {
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(path, &db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
                             SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        set_err(err, errlen, sqlite3_errmsg(db ? db : NULL), NULL);
        if (db) sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 8000);
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(db, "PRAGMA foreign_keys=ON;", NULL, NULL, NULL);
    *out_db = db;
    return 0;
}

void db_close(sqlite3 *db) {
    if (db) sqlite3_close(db);
}

/* 建表（首次启动自动初始化） */
int db_init_schema(sqlite3 *db, char *err, int errlen) {
    static const char *sql =
        "CREATE TABLE IF NOT EXISTS devices ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  name TEXT NOT NULL,"
        "  ip TEXT NOT NULL,"
        "  note TEXT DEFAULT '',"
        "  created_at TEXT NOT NULL,"
        "  updated_at TEXT NOT NULL"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip);"
        "CREATE TABLE IF NOT EXISTS port_policies ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,"
        "  port INTEGER NOT NULL,"
        "  protocol TEXT NOT NULL DEFAULT 'TCP',"
        "  expected TEXT NOT NULL,"
        "  purpose TEXT DEFAULT '',"
        "  created_at TEXT NOT NULL,"
        "  updated_at TEXT NOT NULL"
        ");"
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_policy_uniq "
        "  ON port_policies(device_id, protocol, port);"
        "CREATE TABLE IF NOT EXISTS scans ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  mode TEXT NOT NULL,"
        "  range_start INTEGER,"
        "  range_end INTEGER,"
        "  started_at TEXT NOT NULL,"
        "  finished_at TEXT DEFAULT '',"
        "  status TEXT NOT NULL,"
        "  note TEXT DEFAULT ''"
        ");"
        "CREATE TABLE IF NOT EXISTS scan_devices ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  scan_id INTEGER NOT NULL,"
        "  device_id INTEGER,"
        "  name_snapshot TEXT NOT NULL,"
        "  ip_snapshot TEXT NOT NULL,"
        "  status TEXT NOT NULL,"
        "  error TEXT DEFAULT '',"
        "  total_ports INTEGER DEFAULT 0,"
        "  range_start INTEGER DEFAULT 0,"
        "  range_end INTEGER DEFAULT 0,"
        "  policy_snapshot TEXT DEFAULT ''"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_sd_scan ON scan_devices(scan_id);"
        "CREATE TABLE IF NOT EXISTS scan_results ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  scan_id INTEGER NOT NULL,"
        "  scan_device_id INTEGER NOT NULL,"
        "  port INTEGER NOT NULL,"
        "  protocol TEXT NOT NULL DEFAULT 'TCP',"
        "  service TEXT DEFAULT '',"
        "  actual_status TEXT NOT NULL,"
        "  policy_expected TEXT DEFAULT '',"
        "  policy_verdict TEXT DEFAULT ''"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_sr_sd ON scan_results(scan_device_id);";
    char *emsg = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &emsg) != SQLITE_OK) {
        set_err(err, errlen, emsg ? emsg : "建表失败", NULL);
        sqlite3_free(emsg);
        return -1;
    }
    return 0;
}
/* ===== 设备 ===== */

int db_device_list(sqlite3 *db, device_t **out, int *count) {
    const char *sql = "SELECT id,name,ip,COALESCE(note,''),created_at,updated_at "
                      "FROM devices ORDER BY id;";
    sqlite3_stmt *st = NULL;
    *out = NULL; *count = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    int cap = 0, n = 0;
    device_t *arr = NULL;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            device_t *t = realloc(arr, cap * sizeof(device_t));
            if (!t) { free(arr); sqlite3_finalize(st); return -1; }
            arr = t;
        }
        device_t *d = &arr[n];
        memset(d, 0, sizeof(*d));
        d->id = sqlite3_column_int(st, 0);
        cpy_col(d->name, sizeof(d->name), st, 1);
        cpy_col(d->ip, sizeof(d->ip), st, 2);
        cpy_col(d->note, sizeof(d->note), st, 3);
        cpy_col(d->created_at, sizeof(d->created_at), st, 4);
        cpy_col(d->updated_at, sizeof(d->updated_at), st, 5);
        n++;
    }
    sqlite3_finalize(st);
    *out = arr; *count = n;
    return 0;
}

int db_device_get(sqlite3 *db, int id, device_t *out) {
    const char *sql = "SELECT id,name,ip,COALESCE(note,''),created_at,updated_at "
                      "FROM devices WHERE id=?1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(st, 1, id);
    int rc = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        memset(out, 0, sizeof(*out));
        out->id = sqlite3_column_int(st, 0);
        cpy_col(out->name, sizeof(out->name), st, 1);
        cpy_col(out->ip, sizeof(out->ip), st, 2);
        cpy_col(out->note, sizeof(out->note), st, 3);
        cpy_col(out->created_at, sizeof(out->created_at), st, 4);
        cpy_col(out->updated_at, sizeof(out->updated_at), st, 5);
        rc = 1;
    }
    sqlite3_finalize(st);
    return rc;
}

int db_device_ip_exists(sqlite3 *db, const char *ip, int exclude_id) {
    const char *sql = "SELECT 1 FROM devices WHERE ip=?1 AND id<>?2 LIMIT 1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, exclude_id);
    int exists = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return exists;
}

int db_device_find_by_ip(sqlite3 *db, const char *ip, device_t *out) {
    const char *sql = "SELECT id FROM devices WHERE ip=?1 LIMIT 1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(st, 1, ip, -1, SQLITE_TRANSIENT);
    int found = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        int id = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        found = db_device_get(db, id, out) == 1;
    } else {
        sqlite3_finalize(st);
    }
    return found;
}

int db_device_insert(sqlite3 *db, const device_t *d, char *err, int errlen) {
    char ts[32]; now_str(ts, sizeof(ts));
    const char *sql = "INSERT INTO devices(name,ip,note,created_at,updated_at) "
                      "VALUES(?1,?2,?3,?4,?4);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        set_err(err, errlen, "SQL 预编译失败", NULL); return -1;
    }
    sqlite3_bind_text(st, 1, d->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, d->ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, d->note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ts, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, errlen, sqlite3_errmsg(db), NULL);
        sqlite3_finalize(st); return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

int db_device_update(sqlite3 *db, const device_t *d, char *err, int errlen) {
    char ts[32]; now_str(ts, sizeof(ts));
    const char *sql = "UPDATE devices SET name=?1,ip=?2,note=?3,updated_at=?4 "
                      "WHERE id=?5;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        set_err(err, errlen, "SQL 预编译失败", NULL); return -1;
    }
    sqlite3_bind_text(st, 1, d->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, d->ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 3, d->note, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ts, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, d->id);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, errlen, sqlite3_errmsg(db), NULL);
        sqlite3_finalize(st); return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

/* 删除设备：级联删除其当前策略，历史记录保留（历史表无外键约束） */
int db_device_delete(sqlite3 *db, int id, char *err, int errlen) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM devices WHERE id=?1;", -1, &st, NULL)
        != SQLITE_OK) {
        set_err(err, errlen, "SQL 预编译失败", NULL); return -1;
    }
    sqlite3_bind_int(st, 1, id);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, errlen, sqlite3_errmsg(db), NULL);
        sqlite3_finalize(st); return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

/* ===== 端口策略 ===== */

/* 共用：把一行策略读取到 policy_t */
static void policy_from_row(sqlite3_stmt *st, policy_t *p) {
    memset(p, 0, sizeof(*p));
    p->id = sqlite3_column_int(st, 0);
    p->device_id = sqlite3_column_int(st, 1);
    cpy_col(p->device_name, sizeof(p->device_name), st, 2);
    cpy_col(p->device_ip, sizeof(p->device_ip), st, 3);
    p->port = sqlite3_column_int(st, 4);
    cpy_col(p->protocol, sizeof(p->protocol), st, 5);
    cpy_col(p->expected, sizeof(p->expected), st, 6);
    cpy_col(p->purpose, sizeof(p->purpose), st, 7);
}

int db_policy_list(sqlite3 *db, int device_id_filter, const char *search,
                   policy_t **out, int *count) {
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT p.id,p.device_id,COALESCE(d.name,'(已删除)'),"
             "COALESCE(d.ip,''),p.port,p.protocol,p.expected,COALESCE(p.purpose,'') "
             "FROM port_policies p LEFT JOIN devices d ON d.id=p.device_id "
             "WHERE (%d<0 OR p.device_id=%d) "
             "AND (?1='' OR COALESCE(d.name,'') LIKE ?2 OR COALESCE(d.ip,'') LIKE ?2 "
             "OR CAST(p.port AS TEXT) LIKE ?2 OR COALESCE(p.purpose,'') LIKE ?2) "
             "ORDER BY p.device_id, p.port;",
             device_id_filter, device_id_filter);
    sqlite3_stmt *st = NULL;
    *out = NULL; *count = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;

    char like[300];
    snprintf(like, sizeof(like), "%%%s%%", search ? search : "");
    sqlite3_bind_text(st, 1, search ? search : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, like, -1, SQLITE_TRANSIENT);

    int cap = 0, n = 0;
    policy_t *arr = NULL;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            policy_t *t = realloc(arr, cap * sizeof(policy_t));
            if (!t) { free(arr); sqlite3_finalize(st); return -1; }
            arr = t;
        }
        policy_from_row(st, &arr[n]);
        n++;
    }
    sqlite3_finalize(st);
    *out = arr; *count = n;
    return 0;
}

int db_policy_snapshot(sqlite3 *db, int device_id, policy_t **out, int *count) {
    return db_policy_list(db, device_id, "", out, count);
}

int db_policy_get(sqlite3 *db, int id, policy_t *out) {
    const char *sql =
        "SELECT p.id,p.device_id,COALESCE(d.name,'(已删除)'),COALESCE(d.ip,''),"
        "p.port,p.protocol,p.expected,COALESCE(p.purpose,'') "
        "FROM port_policies p LEFT JOIN devices d ON d.id=p.device_id WHERE p.id=?1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(st, 1, id);
    int rc = 0;
    if (sqlite3_step(st) == SQLITE_ROW) { policy_from_row(st, out); rc = 1; }
    sqlite3_finalize(st);
    return rc;
}

int db_policy_exists(sqlite3 *db, int device_id, int port, int exclude_id) {
    const char *sql = "SELECT 1 FROM port_policies "
                      "WHERE device_id=?1 AND protocol='TCP' AND port=?2 AND id<>?3 LIMIT 1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(st, 1, device_id);
    sqlite3_bind_int(st, 2, port);
    sqlite3_bind_int(st, 3, exclude_id);
    int exists = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return exists;
}

int db_policy_insert(sqlite3 *db, const policy_t *p, char *err, int errlen) {
    char ts[32]; now_str(ts, sizeof(ts));
    const char *sql = "INSERT INTO port_policies"
                      "(device_id,port,protocol,expected,purpose,created_at,updated_at) "
                      "VALUES(?1,?2,'TCP',?3,?4,?5,?5);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        set_err(err, errlen, "SQL 预编译失败", NULL); return -1;
    }
    sqlite3_bind_int(st, 1, p->device_id);
    sqlite3_bind_int(st, 2, p->port);
    sqlite3_bind_text(st, 3, p->expected, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, p->purpose, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, ts, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, errlen, sqlite3_errmsg(db), NULL);
        sqlite3_finalize(st); return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

int db_policy_update(sqlite3 *db, const policy_t *p, char *err, int errlen) {
    char ts[32]; now_str(ts, sizeof(ts));
    const char *sql = "UPDATE port_policies SET device_id=?1,port=?2,expected=?3,"
                      "purpose=?4,updated_at=?5 WHERE id=?6;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        set_err(err, errlen, "SQL 预编译失败", NULL); return -1;
    }
    sqlite3_bind_int(st, 1, p->device_id);
    sqlite3_bind_int(st, 2, p->port);
    sqlite3_bind_text(st, 3, p->expected, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, p->purpose, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, ts, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 6, p->id);
    int rc = sqlite3_step(st);
    if (rc != SQLITE_DONE) {
        set_err(err, errlen, sqlite3_errmsg(db), NULL);
        sqlite3_finalize(st); return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

int db_policy_delete(sqlite3 *db, int id) {
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM port_policies WHERE id=?1;", -1, &st, NULL)
        != SQLITE_OK) return -1;
    sqlite3_bind_int(st, 1, id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}
/* ===== 巡检 ===== */

int db_scan_create(sqlite3 *db, const char *mode, int range_start, int range_end,
                   char *err, int errlen) {
    char ts[32]; now_str(ts, sizeof(ts));
    const char *sql = "INSERT INTO scans(mode,range_start,range_end,started_at,"
                      "finished_at,status) VALUES(?1,?2,?3,?4,'','running');";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        set_err(err, errlen, "SQL 预编译失败", NULL); return -1;
    }
    sqlite3_bind_text(st, 1, mode, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 2, range_start);
    sqlite3_bind_int(st, 3, range_end);
    sqlite3_bind_text(st, 4, ts, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        set_err(err, errlen, sqlite3_errmsg(db), NULL);
        sqlite3_finalize(st); return -1;
    }
    sqlite3_finalize(st);
    return (int)sqlite3_last_insert_rowid(db);
}

int db_scan_device_create(sqlite3 *db, int scan_id, int device_id,
                          const char *name, const char *ip, int total_ports,
                          int range_start, int range_end,
                          const char *policy_snapshot, char *err, int errlen) {
    const char *sql =
        "INSERT INTO scan_devices(scan_id,device_id,name_snapshot,ip_snapshot,"
        "status,error,total_ports,range_start,range_end,policy_snapshot) "
        "VALUES(?1,?2,?3,?4,'pending','',?5,?6,?7,?8);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        set_err(err, errlen, "SQL 预编译失败", NULL); return -1;
    }
    sqlite3_bind_int(st, 1, scan_id);
    if (device_id > 0) sqlite3_bind_int(st, 2, device_id);
    else               sqlite3_bind_null(st, 2);
    sqlite3_bind_text(st, 3, name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 4, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 5, total_ports);
    sqlite3_bind_int(st, 6, range_start);
    sqlite3_bind_int(st, 7, range_end);
    sqlite3_bind_text(st, 8, policy_snapshot ? policy_snapshot : "",
                      -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        set_err(err, errlen, sqlite3_errmsg(db), NULL);
        sqlite3_finalize(st); return -1;
    }
    sqlite3_finalize(st);
    return (int)sqlite3_last_insert_rowid(db);
}

int db_scan_result_insert(sqlite3 *db, int scan_id, int sd_id, int port,
                          const char *proto, const char *service,
                          const char *actual, const char *expected,
                          const char *verdict, char *err, int errlen) {
    const char *sql =
        "INSERT INTO scan_results(scan_id,scan_device_id,port,protocol,service,"
        "actual_status,policy_expected,policy_verdict) VALUES(?1,?2,?3,?4,?5,?6,?7,?8);";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        set_err(err, errlen, "SQL 预编译失败", NULL); return -1;
    }
    sqlite3_bind_int(st, 1, scan_id);
    sqlite3_bind_int(st, 2, sd_id);
    sqlite3_bind_int(st, 3, port);
    sqlite3_bind_text(st, 4, proto ? proto : "TCP", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, service ? service : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 6, actual, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 7, expected ? expected : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 8, verdict ? verdict : "", -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) {
        set_err(err, errlen, sqlite3_errmsg(db), NULL);
        sqlite3_finalize(st); return -1;
    }
    sqlite3_finalize(st);
    return 0;
}

int db_scan_device_finish(sqlite3 *db, int sd_id, const char *status,
                          const char *error) {
    const char *sql = "UPDATE scan_devices SET status=?1,error=?2 WHERE id=?3;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, error ? error : "", -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, sd_id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

int db_scan_finish(sqlite3 *db, int scan_id, const char *status) {
    char ts[32]; now_str(ts, sizeof(ts));
    const char *sql = "UPDATE scans SET status=?1,finished_at=?2 WHERE id=?3;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(st, 1, status, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ts, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, scan_id);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* 读取一条巡检摘要 */
static void scan_summary_from_row(sqlite3_stmt *st, scan_summary_t *s) {
    memset(s, 0, sizeof(*s));
    s->id = sqlite3_column_int(st, 0);
    cpy_col(s->mode, sizeof(s->mode), st, 1);
    s->range_start = sqlite3_column_int(st, 2);
    s->range_end = sqlite3_column_int(st, 3);
    cpy_col(s->started_at, sizeof(s->started_at), st, 4);
    cpy_col(s->finished_at, sizeof(s->finished_at), st, 5);
    cpy_col(s->status, sizeof(s->status), st, 6);
    s->device_count = sqlite3_column_int(st, 7);
    s->open_count = sqlite3_column_int(st, 8);
    s->closed_count = sqlite3_column_int(st, 9);
    s->filtered_count = sqlite3_column_int(st, 10);
}

static const char *SCAN_SUMMARY_SQL =
    "SELECT s.id,s.mode,COALESCE(s.range_start,0),COALESCE(s.range_end,0),"
    "s.started_at,COALESCE(s.finished_at,''),s.status,"
    "(SELECT COUNT(*) FROM scan_devices sd WHERE sd.scan_id=s.id),"
    "(SELECT COUNT(*) FROM scan_results r WHERE r.scan_id=s.id AND r.actual_status='open'),"
    "(SELECT COUNT(*) FROM scan_results r WHERE r.scan_id=s.id AND r.actual_status='closed'),"
    "(SELECT COUNT(*) FROM scan_results r WHERE r.scan_id=s.id AND r.actual_status LIKE 'filtered%') "
    "FROM scans s ";

int db_scan_list(sqlite3 *db, scan_summary_t **out, int *count) {
    char sql[1024];
    snprintf(sql, sizeof(sql), "%s ORDER BY s.started_at DESC, s.id DESC;",
             SCAN_SUMMARY_SQL);
    sqlite3_stmt *st = NULL;
    *out = NULL; *count = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    int cap = 0, n = 0; scan_summary_t *arr = NULL;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n == cap) {
            cap = cap ? cap * 2 : 16;
            scan_summary_t *t = realloc(arr, cap * sizeof(scan_summary_t));
            if (!t) { free(arr); sqlite3_finalize(st); return -1; }
            arr = t;
        }
        scan_summary_from_row(st, &arr[n]);
        n++;
    }
    sqlite3_finalize(st);
    *out = arr; *count = n;
    return 0;
}

int db_scan_get(sqlite3 *db, int scan_id, scan_summary_t *out) {
    char sql[1024];
    snprintf(sql, sizeof(sql), "%s WHERE s.id=?1;", SCAN_SUMMARY_SQL);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(st, 1, scan_id);
    int rc = 0;
    if (sqlite3_step(st) == SQLITE_ROW) { scan_summary_from_row(st, out); rc = 1; }
    sqlite3_finalize(st);
    return rc;
}

int db_scan_devices(sqlite3 *db, int scan_id, scan_device_t **out, int *count) {
    const char *sql =
        "SELECT sd.id,COALESCE(sd.device_id,0),sd.name_snapshot,sd.ip_snapshot,"
        "sd.status,COALESCE(sd.error,''),COALESCE(sd.total_ports,0),"
        "COALESCE(sd.range_start,0),COALESCE(sd.range_end,0),"
        "(SELECT COUNT(*) FROM scan_results r WHERE r.scan_device_id=sd.id AND r.actual_status='open'),"
        "(SELECT COUNT(*) FROM scan_results r WHERE r.scan_device_id=sd.id AND r.actual_status='closed'),"
        "(SELECT COUNT(*) FROM scan_results r WHERE r.scan_device_id=sd.id AND r.actual_status LIKE 'filtered%'),"
        "COALESCE(sd.policy_snapshot,'') "
        "FROM scan_devices sd WHERE sd.scan_id=?1 ORDER BY sd.id;";
    sqlite3_stmt *st = NULL;
    *out = NULL; *count = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(st, 1, scan_id);
    int cap = 0, n = 0; scan_device_t *arr = NULL;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n == cap) {
            cap = cap ? cap * 2 : 8;
            scan_device_t *t = realloc(arr, cap * sizeof(scan_device_t));
            if (!t) { free(arr); sqlite3_finalize(st); return -1; }
            arr = t;
        }
        scan_device_t *d = &arr[n];
        memset(d, 0, sizeof(*d));
        d->id = sqlite3_column_int(st, 0);
        d->device_id = sqlite3_column_int(st, 1);
        cpy_col(d->name, sizeof(d->name), st, 2);
        cpy_col(d->ip, sizeof(d->ip), st, 3);
        cpy_col(d->status, sizeof(d->status), st, 4);
        cpy_col(d->error, sizeof(d->error), st, 5);
        d->total_ports = sqlite3_column_int(st, 6);
        d->range_start = sqlite3_column_int(st, 7);
        d->range_end = sqlite3_column_int(st, 8);
        d->open_count = sqlite3_column_int(st, 9);
        d->closed_count = sqlite3_column_int(st, 10);
        d->filtered_count = sqlite3_column_int(st, 11);
        cpy_col(d->policy_snapshot, sizeof(d->policy_snapshot), st, 12);
        n++;
    }
    sqlite3_finalize(st);
    *out = arr; *count = n;
    return 0;
}

int db_scan_results(sqlite3 *db, int sd_id, scan_result_row_t **out, int *count) {
    const char *sql =
        "SELECT id,port,protocol,COALESCE(service,''),actual_status,"
        "COALESCE(policy_expected,''),COALESCE(policy_verdict,'') "
        "FROM scan_results WHERE scan_device_id=?1 ORDER BY port;";
    sqlite3_stmt *st = NULL;
    *out = NULL; *count = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(st, 1, sd_id);
    int cap = 0, n = 0; scan_result_row_t *arr = NULL;
    while (sqlite3_step(st) == SQLITE_ROW) {
        if (n == cap) {
            cap = cap ? cap * 2 : 32;
            scan_result_row_t *t = realloc(arr, cap * sizeof(scan_result_row_t));
            if (!t) { free(arr); sqlite3_finalize(st); return -1; }
            arr = t;
        }
        scan_result_row_t *r = &arr[n];
        memset(r, 0, sizeof(*r));
        r->id = sqlite3_column_int(st, 0);
        r->port = sqlite3_column_int(st, 1);
        cpy_col(r->protocol, sizeof(r->protocol), st, 2);
        cpy_col(r->service, sizeof(r->service), st, 3);
        cpy_col(r->actual, sizeof(r->actual), st, 4);
        cpy_col(r->expected, sizeof(r->expected), st, 5);
        cpy_col(r->verdict, sizeof(r->verdict), st, 6);
        n++;
    }
    sqlite3_finalize(st);
    *out = arr; *count = n;
    return 0;
}

int db_prev_complete_scan_device(sqlite3 *db, int current_scan_id, int device_id,
                                 const char *ip, int *out_sd_id) {
    const char *sql =
        "SELECT sd.id FROM scan_devices sd JOIN scans s ON s.id=sd.scan_id "
        "WHERE s.id < ?1 AND s.status='completed' AND sd.status='completed' "
        "AND ( (?2>0 AND sd.device_id=?2) OR (?2=0 AND sd.ip_snapshot=?3) ) "
        "ORDER BY s.id DESC LIMIT 1;";
    sqlite3_stmt *st = NULL;
    *out_sd_id = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(st, 1, current_scan_id);
    sqlite3_bind_int(st, 2, device_id);
    sqlite3_bind_text(st, 3, ip ? ip : "", -1, SQLITE_TRANSIENT);
    int rc = 0;
    if (sqlite3_step(st) == SQLITE_ROW) { *out_sd_id = sqlite3_column_int(st, 0); rc = 1; }
    sqlite3_finalize(st);
    return rc;
}
/* 按 (设备, 端口) 查策略 id，找不到返回 0 */
int db_policy_find_id(sqlite3 *db, int device_id, int port) {
    const char *sql = "SELECT id FROM port_policies "
                      "WHERE device_id=?1 AND protocol='TCP' AND port=?2 LIMIT 1;";
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int(st, 1, device_id);
    sqlite3_bind_int(st, 2, port);
    int id = 0;
    if (sqlite3_step(st) == SQLITE_ROW) id = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return id;
}

void db_scan_mark_reachable(sqlite3 *db, int sd_id) {
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(db,
                "UPDATE scan_results SET actual_status=?1 WHERE scan_device_id=?2 AND actual_status=?3",
                -1, &st, NULL) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, ST_FILTERED_REACHABLE, -1, SQLITE_STATIC);
            sqlite3_bind_int(st, 2, sd_id);
            sqlite3_bind_text(st, 3, ST_FILTERED, -1, SQLITE_STATIC);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
}

int db_scan_device_range(sqlite3 *db, int sd_id, int *rs, int *re) {
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
