/*
 * db.h - 授权暴露面巡检工具 数据层 (SQLite)
 *
 * 实体:
 *   devices        当前设备清单
 *   port_policies  端口策略（预期状态 + 用途）
 *   scans          一次巡检任务
 *   scan_devices   巡检中每个设备的名称/IP 快照与执行状态
 *   scan_results   每个端口的实际状态、策略快照判断
 *
 * 设计要点（对应需求文档第 4 节）:
 *   - 历史表不通过外键级联删除设备/策略快照，历史记录永久保留。
 *   - 删除设备时仅删除当前设备与其当前策略（port_policies 级联）。
 */

#ifndef DB_H
#define DB_H

#include "sqlite3.h"

/* 端口实际状态 */
#define ST_OPEN      "open"
#define ST_CLOSED    "closed"
#define ST_FILTERED  "filtered"
#define ST_FILTERED_REACHABLE "无响应/被过滤（主机可达）"
/* 策略预期状态 */
#define EXP_OPEN     "open"
#define EXP_CLOSED   "closed"

/* 巡检模式 */
#define MODE_POLICY  "policy"
#define MODE_RANGE   "range"

/* 巡检 / 设备执行状态 */
#define RUN_RUNNING    "running"
#define RUN_COMPLETED  "completed"
#define RUN_STOPPED    "stopped"
#define RUN_FAILED     "failed"
#define RUN_PENDING    "pending"

#define DB_SNAP_MAX  4096

/* ---- 设备 ---- */
typedef struct {
    int  id;
    char name[128];
    char ip[64];
    char note[256];
    char created_at[32];
    char updated_at[32];
} device_t;

/* ---- 端口策略 ---- */
typedef struct {
    int  id;
    int  device_id;
    char device_name[128];
    char device_ip[64];
    int  port;
    char protocol[8];    /* 第一阶段固定 TCP */
    char expected[8];    /* open / closed */
    char purpose[256];
} policy_t;

/* ---- 巡检记录摘要（记录列表用） ---- */
typedef struct {
    int  id;
    char mode[16];
    int  range_start;
    int  range_end;
    char started_at[32];
    char finished_at[32];
    char status[16];
    int  device_count;
    int  open_count;
    int  closed_count;
    int  filtered_count;
} scan_summary_t;

/* ---- 巡检中的设备分组 ---- */
typedef struct {
    int  id;             /* scan_devices.id */
    int  device_id;      /* 设备可能已被删除，此时为 0 */
    char name[128];
    char ip[64];
    char status[16];
    char error[256];
    int  total_ports;
    int  range_start;
    int  range_end;
    int  open_count;
    int  closed_count;
    int  filtered_count;
    char policy_snapshot[DB_SNAP_MAX];
} scan_device_t;

/* ---- 巡检结果行 ---- */
typedef struct {
    int  id;
    int  port;
    char protocol[8];
    char service[64];
    char actual[96];     /* 实际状态，包含主机可达标记 */
    char expected[8];    /* open / closed / "" */
    char verdict[64];
} scan_result_row_t;

/* 打开 / 初始化 */
int  db_open(const char *path, sqlite3 **out_db, char *err, int errlen);
void db_close(sqlite3 *db);
int  db_init_schema(sqlite3 *db, char *err, int errlen);
int  db_default_path(char *buf, int len);

/* 设备 */
int  db_device_list(sqlite3 *db, device_t **out, int *count);
int  db_device_get(sqlite3 *db, int id, device_t *out);
int  db_device_insert(sqlite3 *db, const device_t *d, char *err, int errlen);
int  db_device_update(sqlite3 *db, const device_t *d, char *err, int errlen);
int  db_device_delete(sqlite3 *db, int id, char *err, int errlen);
int  db_device_ip_exists(sqlite3 *db, const char *ip, int exclude_id);
int  db_device_find_by_ip(sqlite3 *db, const char *ip, device_t *out);

/* 端口策略 */
int  db_policy_list(sqlite3 *db, int device_id_filter, const char *search,
                    policy_t **out, int *count);
int  db_policy_snapshot(sqlite3 *db, int device_id, policy_t **out, int *count);
int  db_policy_get(sqlite3 *db, int id, policy_t *out);
int  db_policy_insert(sqlite3 *db, const policy_t *p, char *err, int errlen);
int  db_policy_update(sqlite3 *db, const policy_t *p, char *err, int errlen);
int  db_policy_delete(sqlite3 *db, int id);
int  db_policy_exists(sqlite3 *db, int device_id, int port, int exclude_id);
int  db_policy_find_id(sqlite3 *db, int device_id, int port);

/* 巡检 */
int  db_scan_create(sqlite3 *db, const char *mode, int range_start, int range_end,
                    char *err, int errlen);
int  db_scan_device_create(sqlite3 *db, int scan_id, int device_id,
                           const char *name, const char *ip, int total_ports,
                           int range_start, int range_end,
                           const char *policy_snapshot, char *err, int errlen);
int  db_scan_result_insert(sqlite3 *db, int scan_id, int sd_id, int port,
                           const char *proto, const char *service,
                           const char *actual, const char *expected,
                           const char *verdict, char *err, int errlen);
int  db_scan_device_finish(sqlite3 *db, int sd_id, const char *status,
                           const char *error);
int  db_scan_finish(sqlite3 *db, int scan_id, const char *status);

int  db_scan_list(sqlite3 *db, scan_summary_t **out, int *count);
int  db_scan_get(sqlite3 *db, int scan_id, scan_summary_t *out);
int  db_scan_devices(sqlite3 *db, int scan_id, scan_device_t **out, int *count);
int  db_scan_results(sqlite3 *db, int sd_id, scan_result_row_t **out, int *count);

/* 同一设备上一次完整完成的巡检分组 */
int  db_prev_complete_scan_device(sqlite3 *db, int current_scan_id, int device_id,
                                  const char *ip, int *out_sd_id);

int db_scan_device_range(sqlite3 *db, int sd_id, int *rs, int *re);
void db_scan_mark_reachable(sqlite3 *db, int sd_id);
void db_free(void *p);

#endif /* DB_H */
