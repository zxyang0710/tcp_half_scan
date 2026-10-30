/*
 * csv.h - CSV 读写与端口策略导入解析
 */

#ifndef CSV_H
#define CSV_H

/* 按标准 CSV 规则写一个字段到 out（必要时加引号，内部引号翻倍）。
 * 返回写入的字符数（不含结尾 '\0'）。 */
int csv_write_field(char *out, int outlen, const char *in);

/* 就地解析一行 CSV（可含引号字段），返回字段数（最多 max_fields）。
 * line 会被就地修改：字段以 '\0' 分隔，fields[i] 指向各字段起点。 */
int csv_split_line(char *line, char **fields, int max_fields);

/* 读取整个文件（自动跳过 UTF-8 BOM），返回 malloc 的缓冲区（需 free），
 * 失败返回 NULL 并写入 err。 */
char *csv_read_file(const char *path, long *len_out, char *err, int errlen);

/* ---- 端口策略导入 ---- */
typedef struct {
    int  lineno;            /* 源文件行号（1 起） */
    char ip[64];
    char name[128];
    int  port;
    char expected[8];       /* open / closed */
    char purpose[256];
    char error[160];        /* 非空=该行有错误 */
    int  dup_in_file;       /* 与文件内前面有效行重复 */
    int  device_id;         /* 解析后回填：匹配到的设备 id（>0 有效） */
} csv_policy_row_t;

/* 解析策略导入文件；成功返回 0 并填充 out/count（包含错误行，用 error 标记）。 */
int csv_parse_policy(const char *path, csv_policy_row_t **out, int *count,
                     char *err, int errlen);

#endif /* CSV_H */