#include "device_service.h"
#include "domain.h"
#include <stdio.h>
#include <string.h>

int device_service_save(sqlite3 *db, const device_t *d, char *err, int errlen) {
    if (!d->name[0]) { snprintf(err, errlen, "设备名称不能为空"); return -1; }
    if (!util_valid_ipv4(d->ip)) { snprintf(err, errlen, "IP 地址格式非法（仅支持 IPv4）"); return -1; }
    if (db_device_ip_exists(db, d->ip, d->id)) {
        snprintf(err, errlen, "该 IP 已被其它设备登记"); return -1;
    }
    return d->id > 0 ? db_device_update(db, d, err, errlen)
                     : db_device_insert(db, d, err, errlen);
}
int device_service_delete(sqlite3 *db, int id, char *err, int errlen) {
    return db_device_delete(db, id, err, errlen);
}
