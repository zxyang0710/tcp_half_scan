#ifndef DEVICE_SERVICE_H
#define DEVICE_SERVICE_H
#include "db.h"
int device_service_save(sqlite3 *db, const device_t *device, char *err, int errlen);
int device_service_delete(sqlite3 *db, int id, char *err, int errlen);
#endif
