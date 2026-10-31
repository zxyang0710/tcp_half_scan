#ifndef DOMAIN_H
#define DOMAIN_H

/* 纯业务规则：不依赖 GTK、数据库或扫描器。 */
const char *status_label(const char *status);
const char *mode_label(const char *mode);
const char *actual_label(const char *actual);
const char *expected_label(const char *expected);
int util_valid_ipv4(const char *ip);
void domain_compute_verdict(int range_mode, const char *actual,
                            const char *expected, char *out, int outlen);
void domain_compare_change(const char *previous, int has_previous,
                           const char *current, char *out, int outlen);

#endif
