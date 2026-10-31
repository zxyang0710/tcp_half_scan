#include "policy_service.h"
#include <stdio.h>

int policy_service_save(sqlite3 *db, const policy_t *p, char *err, int errlen) {
    if (db_policy_exists(db, p->device_id, p->port, p->id)) {
        if (err && errlen > 0)
            snprintf(err, errlen, "该设备已存在 TCP 端口 %d 的策略，请勿重复", p->port);
        return -1;
    }
    return p->id > 0 ? db_policy_update(db, p, err, errlen)
                     : db_policy_insert(db, p, err, errlen);
}
int policy_service_delete(sqlite3 *db, int id) {
    return db_policy_delete(db, id);
}

void policy_service_preview_import(sqlite3 *db, csv_policy_row_t *rows, int n,
                                  int *errors, int *duplicates, int *added, int *updated, int *valid) {
    int n_err=0, n_dup=0, n_new=0, n_upd=0, n_valid=0;
    for (int i = 0; i < n; i++) {
        csv_policy_row_t *r = &rows[i];
        r->device_id = 0;
        if (r->error[0]) { n_err++; continue; }
        device_t dev;
        if (!db_device_find_by_ip(db, r->ip, &dev)) {
            snprintf(r->error, sizeof(r->error),
                     "设备 IP 未在“设备”页登记: %s", r->ip);
            n_err++;
            continue;
        }
        r->device_id = dev.id;
        if (r->dup_in_file) { n_dup++; continue; }
        n_valid++;
        if (db_policy_find_id(db, dev.id, r->port) > 0) n_upd++;
        else                                                      n_new++;
    }

    *errors=n_err; *duplicates=n_dup; *added=n_new; *updated=n_upd; *valid=n_valid;
}
int policy_service_import(sqlite3 *db, const csv_policy_row_t *rows, int n, char *err, int errlen) {
    if (sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(err, errlen, "无法开始事务: %s", sqlite3_errmsg(db)); return -1;
    }
    for (int i=0; i<n; i++) {
        const csv_policy_row_t *r=&rows[i];
        if (r->error[0] || r->dup_in_file || r->device_id<=0) continue;
        policy_t p={0};
        p.id=db_policy_find_id(db,r->device_id,r->port);
        p.device_id=r->device_id; p.port=r->port;
        snprintf(p.protocol,sizeof(p.protocol), "TCP");
        snprintf(p.expected,sizeof(p.expected), "%s",r->expected);
        snprintf(p.purpose,sizeof(p.purpose), "%s",r->purpose);
        if (policy_service_save(db,&p,err,errlen)!=0) {
            sqlite3_exec(db,"ROLLBACK;",NULL,NULL,NULL); return -1;
        }
    }
    if (sqlite3_exec(db,"COMMIT;",NULL,NULL,NULL)!=SQLITE_OK) {
        snprintf(err,errlen,"提交导入失败: %s",sqlite3_errmsg(db));
        sqlite3_exec(db,"ROLLBACK;",NULL,NULL,NULL); return -1;
    }
    return 0;
}
