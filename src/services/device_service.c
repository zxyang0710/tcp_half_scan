#include "device_service.h"
#include "domain.h"
#include <stdio.h>
#include <string.h>

/*
 * 保存设备信息：先校验设备名称、IPv4 地址和 IP 唯一性，
 * 再根据设备 ID 判断执行新增还是更新。
 * 校验失败返回 -1，并将错误信息写入 err；
 * 校验通过后返回数据库操作结果。
 * errlen 为错误信息缓冲区的容量（字节）。
 */
int device_service_save(sqlite3 *db, const device_t *d,
                        char *err, int errlen) {
    // 字符串首字符为 '\0' 表示设备名称为空。
    if (!d->name[0]) {
        snprintf(err, errlen, "设备名称不能为空");
        return -1;
    }

    // 校验 IP 地址格式，目前仅支持 IPv4。
    if (!util_valid_ipv4(d->ip)) {
        snprintf(err, errlen, "IP 地址格式非法（仅支持 IPv4）");
        return -1;
    }

    // 检查 IP 是否被其他设备使用；更新时通过当前 ID 排除自身。
    if (db_device_ip_exists(db, d->ip, d->id)) {
        snprintf(err, errlen, "该 IP 已被其它设备登记");
        return -1;
    }

    // ID 大于 0 时更新已有设备，否则新增设备。
    return d->id > 0 ? db_device_update(db, d, err, errlen)
                     : db_device_insert(db, d, err, errlen);
}

/*
 * 根据设备 ID 删除设备。
 * 直接返回数据库层的执行结果，错误信息由数据库层写入 err。
 */
int device_service_delete(sqlite3 *db, int id, char *err, int errlen) {
    return db_device_delete(db, id, err, errlen);
}