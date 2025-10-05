#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "file_ops.h"
#include "access_control.h"

void clear_stdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int main() {
    char username[128];
    printf("=== Encrypted File System (Mini Project) ===\n");
    printf("Enter your username to login: ");
    if (!fgets(username, sizeof(username), stdin)) return 0;
    username[strcspn(username, "\r\n")] = 0; 
    if (strlen(username) == 0) {
        printf("Username required.\n");
        return 0;
    }

    printf("Welcome, %s!\n", username);

    while (1) {
        printf("\n--- Menu ---\n");
        printf("1. Create File\n");
        printf("2. Write File (owner only)\n");
        printf("3. Read File\n");
        printf("4. Delete File (owner only)\n");
        printf("5. Request Read Access\n");
        printf("6. Approve/Reject Requests (owners)\n");
        printf("7. Exit\n");
        printf("Select option: ");

        int opt = 0;
        if (scanf("%d", &opt) != 1) {
            clear_stdin();
            opt = 0;
        }
        clear_stdin();
        if (opt == 1) {
            char fname[256];
            printf("Enter new filename (stored in 'encrypted_files'): ");
            if (!fgets(fname, sizeof(fname), stdin)) continue;
            fname[strcspn(fname, "\r\n")] = 0;
            if (strlen(fname) == 0) {
                printf("Filename required.\n");
                continue;
            }
            if (create_file(username, fname))
                printf("File '%s' created successfully (owned by %s).\n", fname, username);
            else
                printf("Failed to create file (maybe already exists).\n");
        }
        else if (opt == 2) {
            char fname[256];
            printf("Enter filename to write/edit: ");
            if (!fgets(fname, sizeof(fname), stdin)) continue;
            fname[strcspn(fname, "\r\n")] = 0;

            printf("Do you want to (A)ppend or (O)verwrite existing content? [A/O]: ");
            char choice;
            scanf(" %c", &choice);
            clear_stdin();
            int appendMode = (choice == 'A' || choice == 'a');

            printf("Enter your text (multi-line). Type '~' alone on a new line to finish:\n");

            char data[8192] = "";
            char line[512];
            while (1) {
                if (!fgets(line, sizeof(line), stdin)) break;
                if (strcmp(line, "~\n") == 0 || strcmp(line, "~\r\n") == 0) break;
                strcat(data, line);
            }
            if (appendMode) {
                FILE *meta = fopen("metadata.txt", "r");
                bool found = false;
                char owner[256] = {0};
                if (meta) {
                    char lineMeta[512];
                    while (fgets(lineMeta, sizeof(lineMeta), meta)) {
                        char fn[256], own[256];
                        if (sscanf(lineMeta, "%255[^:]:%255[^\n]", fn, own) == 2) {
                            if (strcmp(fn, fname) == 0) {
                                found = true;
                                strcpy(owner, own);
                                break;
                            }
                        }
                    }
                    fclose(meta);
                }

                if (found && strcmp(owner, username) != 0) {
                    printf("You are not the owner, cannot append to this file.\n");
                    continue;
                }

                char path[512];
                snprintf(path, sizeof(path), "encrypted_files/%s.enc", fname);
                FILE *fr = fopen(path, "rb");
                if (fr) {
                    fseek(fr, 0, SEEK_END);
                    long sz = ftell(fr);
                    fseek(fr, 0, SEEK_SET);
                    if (sz > 0 && sz < sizeof(data) - 1) {
                        unsigned char *buf = (unsigned char *)malloc(sz + 1);
                        fread(buf, 1, sz, fr);
                        extern void xor_decrypt_buffer(unsigned char *buf, size_t len);
                        xor_decrypt_buffer(buf, sz);
                        buf[sz] = '\0';
                        strcat(data, (char *)buf);
                        free(buf);
                    }
                    fclose(fr);
                }
            }

            if (write_file(username, fname, data))
                printf("File content saved & encrypted successfully.\n");
            else
                printf("Write failed (check ownership or filename).\n");
        }
        else if (opt == 3) {
            char fname[256];
            printf("Enter filename to read: ");
            if (!fgets(fname, sizeof(fname), stdin)) continue;
            fname[strcspn(fname, "\r\n")] = 0;
            if (!read_file(username, fname))
                printf("Read failed (not owner / not approved / file missing).\n");
        }
        else if (opt == 4) {
            char fname[256];
            printf("Enter filename to delete: ");
            if (!fgets(fname, sizeof(fname), stdin)) continue;
            fname[strcspn(fname, "\r\n")] = 0;
            if (delete_file_cli(username, fname))
                printf("File deleted (and metadata removed).\n");
            else
                printf("Delete failed (maybe not owner or file missing).\n");
        }
        else if (opt == 5) {
            char fname[256];
            printf("Enter filename to request read access: ");
            if (!fgets(fname, sizeof(fname), stdin)) continue;
            fname[strcspn(fname, "\r\n")] = 0;
            if (request_read_access(username, fname))
                printf("Access request submitted (owner will approve).\n");
            else
                printf("Request failed (maybe already requested or file missing).\n");
        }
        else if (opt == 6) {
            if (!show_and_approve_requests(username))
                printf("Approve/Reject routine failed.\n");
        }
        else if (opt == 7) {
            printf("Goodbye.\n");
            break;
        }

        else {
            printf("Invalid option.\n");
        }
    }

    return 0;
}