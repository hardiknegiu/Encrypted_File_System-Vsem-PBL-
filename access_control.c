#include "access_control.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

bool request_read_access(const char *requester, const char *filename) {
    FILE *f = fopen("access_requests.txt", "a+");
    if (!f) return false;
    fseek(f, 0, SEEK_SET);
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char fn[256], req[256], status[64];
        if (sscanf(line, "%255[^:]:%255[^:]:%63[^\n]", fn, req, status) == 3) {
            if (strcmp(fn, filename) == 0 && strcmp(req, requester) == 0) {
                fclose(f);
                return false; 
            }
        }
    }
    fprintf(f, "%s:%s:PENDING\n", filename, requester);
    fclose(f);
    return true;
}

bool show_and_approve_requests(const char *owner) {
    FILE *meta = fopen("metadata.txt", "r");
    if (!meta) {
        printf("[INFO] No files in system yet.\n");
        return true;
    }
    typedef struct { char filename[256]; char owner[256]; } map_t;
    map_t *map = NULL; size_t map_n = 0;
    char line[512];
    while (fgets(line, sizeof(line), meta)) {
        char fn[256], own[256];
        if (sscanf(line, "%255[^:]:%255[^\n]", fn, own) == 2) {
            map = realloc(map, sizeof(map_t)*(map_n+1));
            strcpy(map[map_n].filename, fn);
            strcpy(map[map_n].owner, own);
            map_n++;
        }
    }
    fclose(meta);

    FILE *ar = fopen("access_requests.txt", "r");
    if (!ar) {
        printf("[INFO] No access requests.\n");
        free(map);
        return true;
    }
    typedef struct { char filename[256]; char requester[256]; char status[64]; } req_t;
    req_t *reqs = NULL; size_t req_n = 0;
    while (fgets(line, sizeof(line), ar)) {
        char fn[256], reqr[256], status[64];
        if (sscanf(line, "%255[^:]:%255[^:]:%63[^\n]", fn, reqr, status) == 3) {
            /* find owner of fn */
            for (size_t i = 0; i < map_n; ++i) {
                if (strcmp(map[i].filename, fn) == 0 && strcmp(map[i].owner, owner) == 0) {
                    reqs = realloc(reqs, sizeof(req_t)*(req_n+1));
                    strcpy(reqs[req_n].filename, fn);
                    strcpy(reqs[req_n].requester, reqr);
                    strcpy(reqs[req_n].status, status);
                    req_n++;
                    break;
                }
            }
        }
    }
    fclose(ar);

    if (req_n == 0) {
        printf("[INFO] No requests for your files.\n");
        free(map); free(reqs);
        return true;
    }

    printf("Pending/All requests for files you own:\n");
    for (size_t i = 0; i < req_n; ++i) {
        printf("[%zu] File: %s, Requester: %s, Status: %s\n", i+1, reqs[i].filename, reqs[i].requester, reqs[i].status);
    }

    printf("Enter number to toggle APPROVE/REJECT or 0 to exit: ");
    int choice = 0;
    if (scanf("%d", &choice) != 1) {int c; while ((c=getchar())!='\n' && c!=EOF); choice = 0; }
    if (choice <= 0 || choice > (int)req_n) {
        printf("No changes made.\n");
        free(map); free(reqs);
        return true;
    }

    printf("Approve (A) or Reject (R) request [%d]? ", choice);
    char act = ' ';
    int c = getchar();
    while (c=='\n' || c==' ') c = getchar();
    act = (char)c;
    FILE *orig = fopen("access_requests.txt", "r");
    FILE *tmp = fopen("access.tmp", "w");
    if (!orig || !tmp) {
        if (orig) fclose(orig);
        if (tmp) fclose(tmp);
        free(map); free(reqs);
        return false;
    }
    while (fgets(line, sizeof(line), orig)) {
        char fn[256], reqr[256], status[64];
        if (sscanf(line, "%255[^:]:%255[^:]:%63[^\n]", fn, reqr, status) == 3) {
            if (strcmp(fn, reqs[choice-1].filename) == 0 && strcmp(reqr, reqs[choice-1].requester) == 0) {
                if (act == 'A' || act == 'a') {
                    fprintf(tmp, "%s:%s:APPROVED\n", fn, reqr);
                    continue;
                } else {
                    fprintf(tmp, "%s:%s:REJECTED\n", fn, reqr);
                    continue;
                }
            }
        }
        fputs(line, tmp);
    }
    fclose(orig);
    fclose(tmp);
    remove("access_requests.txt");
    rename("access.tmp", "access_requests.txt");
    printf("Updated request.\n");
    free(map); free(reqs);
    return true;
}