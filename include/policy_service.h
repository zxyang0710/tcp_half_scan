#ifndef POLICY_SERVICE_H
#define POLICY_SERVICE_H
#include "db.h"
#include "csv.h"
int policy_service_save(sqlite3 *db, const policy_t *policy, char *err, int errlen);
int policy_service_delete(sqlite3 *db, int id);
void policy_service_preview_import(sqlite3 *db, csv_policy_row_t *rows, int n,
                                  int *errors, int *duplicates, int *added, int *updated, int *valid);
int policy_service_import(sqlite3 *db, const csv_policy_row_t *rows, int n, char *err, int errlen);
#endif
