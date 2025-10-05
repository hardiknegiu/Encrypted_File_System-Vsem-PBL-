#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include <stdbool.h>

bool request_read_access(const char *requester, const char *filename);
bool show_and_approve_requests(const char *owner);

#endif