#define _CRT_SECURE_NO_WARNINGS
#include "file_ops.h"
#include "encryption.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

#ifdef _WIN32
  #include <direct.h>
#endif

#define STORAGE_DIR "encrypted_files"
#define METADATA_FILE "metadata.txt"

static int make_dir(const char *path) {
#ifdef _WIN32
    return _mkdir(path);
#else
    return mkdir(path, 0700);
#endif
}

bool ensure_storage_dir() {
    struct stat st;
    if (stat(STORAGE_DIR, &st) == 0 && (st.st_mode & S_IFDIR)) return true;
    if (make_dir(STORAGE_DIR) == 0) return true;
    return false;
}

bool create_file_record(const char *filename, const char *owner) {
    FILE *f = fopen(METADATA_FILE, "a");
    if (!f) return false;
    fprintf(f, "%s:%s\n", filename, owner);
    fclose(f);
    return true;
}

bool delete_file_record(const char *filename) {
    FILE *f = fopen(METADATA_FILE, "r");
    if (!f) return false;
    FILE *temp = fopen("metadata.tmp", "w");
    if (!temp) { fclose(f); return false; }
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        char fn[256], owner[256];
        if (sscanf(line, "%255[^:]:%255[^\n]", fn, owner) == 2) {
            if (strcmp(fn, filename) == 0) { found = true; continue; }
        }
        fputs(line, temp);
    }
    fclose(f);
    fclose(temp);
    if (remove(METADATA_FILE) != 0 && errno != ENOENT) { remove("metadata.tmp"); return false; }
    rename("metadata.tmp", METADATA_FILE);
    return found;
}

bool create_file(const char *owner, const char *filename) {
    if (!ensure_storage_dir()) return false;
    /* Check if already exists */
    FILE *meta = fopen(METADATA_FILE, "r");
    if (meta) {
        char line[512];
        while (fgets(line, sizeof(line), meta)) {
            char fn[256], own[256];
            if (sscanf(line, "%255[^:]:%255[^\n]", fn, own) == 2) {
                if (strcmp(fn, filename) == 0) {
                    fclose(meta);
                    return false; 
                }
            }
        }
        fclose(meta);
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.enc", STORAGE_DIR, filename);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    fclose(f);
    /* add metadata */
    if (!create_file_record(filename, owner)) return false;
    return true;
}

bool write_file(const char *owner, const char *filename, const char *data) {
    FILE *meta = fopen(METADATA_FILE, "r");
    if (!meta) return false;
    char line[512];
    bool is_owner = false;
    bool found = false;
    while (fgets(line, sizeof(line), meta)) {
        char fn[256], own[256];
        if (sscanf(line, "%255[^:]:%255[^\n]", fn, own) == 2) {
            if (strcmp(fn, filename) == 0) { found = true; if (strcmp(own, owner) == 0) is_owner = true; break; }
        }
    }
    fclose(meta);
    if (!found) return false;
    if (!is_owner) return false;

    if (!ensure_storage_dir()) return false;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.enc", STORAGE_DIR, filename);
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t len = strlen(data);
    unsigned char *buf = (unsigned char*) malloc(len);
    if (!buf) { fclose(f); return false; }
    memcpy(buf, data, len);
    xor_encrypt_buffer(buf, len);
    size_t written = fwrite(buf, 1, len, f);
    free(buf);
    fclose(f);
    return written == len;
}

bool read_file(const char *username, const char *filename) {
    /* find owner from metadata */
    FILE *meta = fopen(METADATA_FILE, "r");
    if (!meta) return false;
    char line[512];
    char owner[256] = {0};
    bool found = false;
    while (fgets(line, sizeof(line), meta)) {
        char fn[256], own[256];
        if (sscanf(line, "%255[^:]:%255[^\n]", fn, own) == 2) {
            if (strcmp(fn, filename) == 0) { found = true; strncpy(owner, own, sizeof(owner)-1); break; }
        }
    }
    fclose(meta);
    if (!found) return false;

    bool allowed = false;
    if (strcmp(owner, username) == 0) allowed = true;
    else {
        FILE *ar = fopen("access_requests.txt", "r");
        if (ar) {
            char rline[512];
            while (fgets(rline, sizeof(rline), ar)) {
                char fn[256], requester[256], status[64];
                if (sscanf(rline, "%255[^:]:%255[^:]:%63[^\n]", fn, requester, status) == 3) {
                    if (strcmp(fn, filename) == 0 && strcmp(requester, username) == 0 && strcmp(status, "APPROVED") == 0) {
                        allowed = true; break;
                    }
                }
            }
            fclose(ar);
        }
    }
    if (!allowed) return false;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s.enc", STORAGE_DIR, filename);
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) {
        printf("[INFO] File is empty.\n");
        fclose(f);
        return true;
    }
    unsigned char *buf = (unsigned char*) malloc(sz + 1);
    if (!buf) { fclose(f); return false; }
    size_t got = fread(buf, 1, sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return false; }
    xor_decrypt_buffer(buf, got);
    buf[got] = '\0';
    printf("----- Decrypted content of '%s' -----\n", filename);
    printf("%s\n", (char*)buf);
    printf("----- End of file -----\n");
    free(buf);
    return true;
}

bool delete_file_cli(const char *username, const char *filename) {
    /* check owner */
    FILE *meta = fopen(METADATA_FILE, "r");
    if (!meta) return false;
    char line[512];
    char owner[256] = {0};
    bool found = false;
    while (fgets(line, sizeof(line), meta)) {
        char fn[256], own[256];
        if (sscanf(line, "%255[^:]:%255[^\n]", fn, own) == 2) {
            if (strcmp(fn, filename) == 0) { found = true; strncpy(owner, own, sizeof(owner)-1); break; }
        }
    }
    fclose(meta);
    if (!found) return false;
    if (strcmp(owner, username) != 0) return false;
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.enc", STORAGE_DIR, filename);
    if (remove(path) != 0) {
    }
    
    if (!delete_file_record(filename)) {
    }
    
    FILE *ar = fopen("access_requests.txt", "r");
    if (ar) {
        FILE *tmp = fopen("access.tmp", "w");
        if (tmp) {
            char rline[512];
            while (fgets(rline, sizeof(rline), ar)) {
                char fn[256];
                if (sscanf(rline, "%255[^:]:%*[^:]:%*s", fn) == 1) {
                    if (strcmp(fn, filename) == 0) continue; 
                }
                fputs(rline, tmp);
            }
            fclose(tmp);
        }
        fclose(ar);
        remove("access_requests.txt");
        rename("access.tmp", "access_requests.txt");
    }
    return true;
}