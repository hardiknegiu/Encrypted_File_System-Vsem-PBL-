#ifndef FILE_OPS_H
#define FILE_OPS_H

#include <stdbool.h>

bool ensure_storage_dir();
bool create_file_record(const char *filename, const char *owner);
bool delete_file_record(const char *filename);

bool create_file(const char *owner, const char *filename);
bool write_file(const char *owner, const char *filename, const char *data);
bool read_file(const char *username, const char *filename);
bool delete_file_cli(const char *username, const char *filename);

#endif