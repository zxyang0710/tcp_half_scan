#ifndef SCAN_SERVICE_H
#define SCAN_SERVICE_H
#include "db.h"
#include <stdint.h>
#define SCAN_MAX_DEV 256
typedef struct { int idx; char name[128]; char ip[64]; int total; } scan_device_event_t;
typedef struct {
    int  idx; int port; char actual[64]; char service[64];
    char expected[8]; char verdict[64];
} scan_port_event_t;
typedef struct { int idx; char status[16]; int scanned, open, closed, filtered, total; } scan_device_done_event_t;
typedef struct { int scan_id; char status[16]; int open, closed, filtered; } scan_finish_event_t;

typedef struct { int idx; } scan_reachable_event_t;
typedef enum { SCAN_DEVICE, SCAN_PORT, SCAN_REACHABLE, SCAN_DEVICE_DONE, SCAN_FINISH } scan_event_t;
/* 回调在工作线程执行；data 为堆内存，所有权交给接收方，接收方必须 free。 */
typedef void (*scan_event_callback_t)(scan_event_t event, void *data);
/* 策略端口条目 */
typedef struct {
    uint16_t port;
    char     exp[8];   /* open / closed */
} pol_ent_t;

/* 单个巡检设备作业 */
typedef struct {
    int      id;                 /* 设备 id */
    int      sd_id;              /* scan_devices.id */
    char     name[128];
    char     ip[64];
    uint16_t *ports;  int n_ports;
    pol_ent_t *pol;   int n_pol;
    char     snapshot[DB_SNAP_MAX];
} job_dev_t;

/* 一次巡检作业 */
typedef struct {
    int scan_id;
    char db_path[1024];
    scan_event_callback_t callback;
    int mode;                    /* 0=按策略, 1=完整范围 */
    int range_start, range_end;
    int timeout_ms;
    char device[64];          /* 网卡名，"auto" = 自动 */
    int n_devices;
    job_dev_t devs[SCAN_MAX_DEV];
} scan_job_t;


void scan_service_free_job(scan_job_t *job);
void *scan_service_run(void *job);
void scan_service_reset(void);
void scan_service_stop(void);
void scan_service_snapshot(sqlite3 *db, int dev_id, char *out, int outlen);
int scan_service_prepare(sqlite3 *db, scan_job_t *job, const device_t *devs, int ndev,
                         int *total_ports, char *missing, int missing_len);
int scan_service_create_records(sqlite3 *db, scan_job_t *job, char *err, int errlen);
#endif
