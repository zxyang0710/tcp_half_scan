#ifndef RECORDS_SERVICE_H
#define RECORDS_SERVICE_H
#include "db.h"
int records_export_csv(sqlite3 *db, const char *path, const int *scan_ids, int n_ids,
                       long *written, char *err, int errlen);
#endif
