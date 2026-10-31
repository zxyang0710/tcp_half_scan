#include "policy_service.h"
#include <stdio.h>

/*
 * 保存一条策略。
 * p->id > 0 时更新已有策略，否则新增策略。
 * 返回：成功时返回数据库操作结果；策略重复时返回 -1。
 * err 和 errlen 用于接收错误信息。
 */
int policy_service_save(sqlite3 *db, const policy_t *p,
                        char *err, int errlen) {
    /*
     * 检查同一设备是否已存在相同 TCP 端口的策略。
     * 传入当前策略 ID，以便更新时排除自身。
     */
    if (db_policy_exists(db, p->device_id, p->port, p->id)) {
        if (err && errlen > 0) snprintf(err, errlen, "该设备已存在 TCP 端口 %d 的策略，请勿重复", p->port);
        return -1;
    }

    // 有有效 ID 则更新，否则插入新策略。
    return p->id > 0 ? db_policy_update(db, p, err, errlen) : db_policy_insert(db, p, err, errlen);
}

/* 根据策略 ID 删除策略，直接返回数据库层的执行结果。 */
int policy_service_delete(sqlite3 *db, int id) {
    return db_policy_delete(db, id);
}

/*
 * 预览 CSV 策略导入结果，不写入策略数据。
 * 为每行匹配设备 ID，并统计：
 * errors     ：错误行数；
 * duplicates ：文件内重复行数（不含已判为错误的行）；
 * added      ：预计新增的策略数；
 * updated    ：预计更新的策略数；
 * valid      ：有效且未重复的行数，即 added + updated。
 *
 * rows 中的 device_id 和 error 可能被修改。
 * 各统计输出指针必须有效。
 */
void policy_service_preview_import(sqlite3 *db,
                                   csv_policy_row_t *rows, int n,
                                   int *errors, int *duplicates,
                                   int *added, int *updated, int *valid) {
    int n_err = 0, n_dup = 0, n_new = 0, n_upd = 0, n_valid = 0;

    for (int i = 0; i < n; i++) {
        csv_policy_row_t *r = &rows[i];

        // 清除旧的设备匹配结果，后续根据 IP 重新查找。
        r->device_id = 0;

        // 已有错误信息的行直接计入错误，不再继续检查。
        if (r->error[0]) {
            n_err++;
            continue;
        }

        // 根据 CSV 中的 IP 查找已登记的设备。
        device_t dev;
        if (!db_device_find_by_ip(db, r->ip, &dev)) {
            snprintf(r->error, sizeof(r->error), "设备 IP 未在“设备”页登记: %s", r->ip);
            n_err++; continue;
        }

        // 保存匹配到的设备 ID，供实际导入时使用。
        r->device_id = dev.id;

        // 文件内重复的行不参与新增或更新统计。
        if (r->dup_in_file) {
            n_dup++;
            continue;
        }

        n_valid++;

        // 同一设备、同一端口已有策略则预计更新，否则预计新增。
        if (db_policy_find_id(db, dev.id, r->port) > 0) n_upd++;
        else n_new++;
    }

    // 通过输出参数返回统计结果。
    *errors = n_err;
    *duplicates = n_dup;
    *added = n_new;
    *updated = n_upd;
    *valid = n_valid;
}

/*
 * 将已完成校验和设备匹配的 CSV 行导入数据库。
 * 跳过错误行、文件内重复行和未匹配设备的行。
 * 所有有效行在同一事务中保存，失败时回滚。
 * 返回：0 表示成功，-1 表示失败。
 */
int policy_service_import(sqlite3 *db,
                          const csv_policy_row_t *rows, int n,
                          char *err, int errlen) {
    // 开启事务，使本次批量导入能够统一提交或回滚。
    if (sqlite3_exec(db, "BEGIN;", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(err, errlen, "无法开始事务: %s", sqlite3_errmsg(db));
        return -1;
    }

    for (int i = 0; i < n; i++) {
        const csv_policy_row_t *r = &rows[i];

        // 跳过不满足导入条件的行。
        if (r->error[0] || r->dup_in_file || r->device_id <= 0)
            continue;

        // 初始化策略，并查询是否存在可更新的策略 ID。
        policy_t p = {0};
        p.id = db_policy_find_id(db, r->device_id, r->port);
        p.device_id = r->device_id;
        p.port = r->port;

        // 当前导入的策略统一使用 TCP 协议。
        snprintf(p.protocol, sizeof(p.protocol), "TCP");
        snprintf(p.expected, sizeof(p.expected), "%s", r->expected);
        snprintf(p.purpose, sizeof(p.purpose), "%s", r->purpose);

        // 保存失败时回滚本次事务，撤销此前已导入的修改。
        if (policy_service_save(db, &p, err, errlen) != 0) {
            sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
            return -1;
        }
    }

    // 所有有效行保存完成后，统一提交事务。
    if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
        snprintf(err, errlen, "提交导入失败: %s", sqlite3_errmsg(db));
        sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    return 0;
}