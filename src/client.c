/**
 * @file client.c
 * @brief 客户端实现
 */

#include "../include/client.h"
#include "../include/vfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

/*============================================================================
 * 客户端连接管理
 *============================================================================*/

/**
 * 初始化客户端
 */
int client_init(ClientContext *ctx) {
    if (!ctx) return -1;
    
    memset(ctx, 0, sizeof(ClientContext));
    ctx->sockfd = -1;
    strcpy(ctx->cwd, "/");
    
    return 0;
}

/**
 * 连接到服务器
 */
int client_connect(ClientContext *ctx, const char *host, uint16_t port) {
    if (!ctx || !host) return -1;
    
    // 解析主机名
    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "Failed to resolve host: %s\n", host);
        return -1;
    }
    
    // 创建套接字
    ctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->sockfd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }
    
    // 连接服务器
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    
    if (connect(ctx->sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect: %s\n", strerror(errno));
        close(ctx->sockfd);
        ctx->sockfd = -1;
        return -1;
    }
    
    strncpy(ctx->server_host, host, sizeof(ctx->server_host) - 1);
    ctx->server_port = port;
    ctx->connected = true;
    
    printf("Connected to %s:%u\n", host, port);
    return 0;
}

/**
 * 断开连接
 */
void client_disconnect(ClientContext *ctx) {
    if (!ctx) return;
    
    if (ctx->sockfd >= 0) {
        close(ctx->sockfd);
        ctx->sockfd = -1;
    }
    
    ctx->connected = false;
    ctx->authenticated = false;
    
    printf("Disconnected\n");
}

/**
 * 销毁客户端
 */
void client_destroy(ClientContext *ctx) {
    if (!ctx) return;
    
    client_disconnect(ctx);
}

/*============================================================================
 * 认证
 *============================================================================*/

/**
 * 登录
 */
int client_login(ClientContext *ctx, const char *username, const char *password, UserRole role) {
    if (!ctx || !ctx->connected) return -1;
    
    RequestHeader header;
    protocol_init_request(&header, CMD_LOGIN);
    header.payload_size = sizeof(LoginPayload);
    
    LoginPayload payload;
    memset(&payload, 0, sizeof(payload));
    strncpy(payload.username, username, sizeof(payload.username) - 1);
    strncpy(payload.password, password, sizeof(payload.password) - 1);
    payload.role = role;
    
    if (protocol_send_request(ctx->sockfd, &header, &payload) != ERR_SUCCESS) {
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        return -1;
    }
    
    if (response.status_code == STATUS_OK) {
        strncpy(ctx->username, username, sizeof(ctx->username) - 1);
        ctx->role = role;
        ctx->authenticated = true;
        printf("Login successful: %s\n", response.message);
        return 0;
    } else {
        printf("Login failed: %s\n", response.message);
        return -1;
    }
}

/**
 * 登出
 */
int client_logout(ClientContext *ctx) {
    if (!ctx || !ctx->connected) return -1;
    
    RequestHeader header;
    protocol_init_request(&header, CMD_LOGOUT);
    
    protocol_send_request(ctx->sockfd, &header, NULL);
    
    ServerResponse response;
    protocol_recv_response(ctx->sockfd, &response, NULL, 0);
    
    ctx->authenticated = false;
    printf("Logged out\n");
    
    return 0;
}

/*============================================================================
 * 文件操作
 *============================================================================*/

/**
 * 列出目录
 */
int client_ls(ClientContext *ctx, const char *path) {
    if (!ctx || !ctx->connected) return -1;
    
    RequestHeader header;
    protocol_init_request(&header, CMD_LS);
    if (path) {
        strncpy(header.filename, path, sizeof(header.filename) - 1);
    }
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        return -1;
    }
    
    ServerResponse response;
    uint8_t payload[8192];
    
    if (protocol_recv_response(ctx->sockfd, &response, payload, sizeof(payload)) != ERR_SUCCESS) {
        return -1;
    }
    
    if (response.status_code != STATUS_OK) {
        printf("Error: %s\n", response.message);
        return -1;
    }
    
    // 解析文件列表
    uint32_t count = *(uint32_t *)payload;
    FileInfoPayload *files = (FileInfoPayload *)(payload + sizeof(uint32_t));
    
    printf("\n%-30s %10s %20s %s\n", "Name", "Size", "Modified", "Type");
    printf("--------------------------------------------------------------------------------\n");
    
    for (uint32_t i = 0; i < count; i++) {
        char time_str[32];
        time_t mtime = files[i].mtime;
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&mtime));
        
        const char *type = files[i].file_type == FILE_TYPE_DIRECTORY ? "DIR" : "FILE";
        
        printf("%-30s %10u %20s %s\n", 
               files[i].filename, 
               files[i].size,
               time_str,
               type);
    }
    
    printf("\nTotal: %u entries\n", count);
    
    return 0;
}

/**
 * 上传文件
 */
int client_upload(ClientContext *ctx, const char *local_path, const char *remote_path) {
    if (!ctx || !ctx->connected) return -1;
    
    // 打开本地文件
    int fd = open(local_path, O_RDONLY);
    if (fd < 0) {
        printf("Failed to open file: %s\n", strerror(errno));
        return -1;
    }
    
    // 获取文件大小
    struct stat st;
    fstat(fd, &st);
    uint32_t file_size = st.st_size;
    
    // 发送上传请求
    RequestHeader header;
    protocol_init_request(&header, CMD_UPLOAD);
    strncpy(header.filename, remote_path, sizeof(header.filename) - 1);
    header.file_size = file_size;
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        close(fd);
        return -1;
    }
    
    // 等待服务器响应
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        close(fd);
        return -1;
    }
    
    if (response.status_code != STATUS_OK) {
        printf("Error: %s\n", response.message);
        close(fd);
        return -1;
    }
    
    // 发送文件数据
    uint8_t buffer[BUFFER_SIZE];
    uint32_t total_sent = 0;
    
    printf("Uploading %s (%u bytes)...\n", local_path, file_size);
    
    while (total_sent < file_size) {
        ssize_t bytes = read(fd, buffer, sizeof(buffer));
        if (bytes <= 0) break;
        
        if (protocol_send_file_data(ctx->sockfd, buffer, bytes) != ERR_SUCCESS) {
            close(fd);
            return -1;
        }
        
        total_sent += bytes;
        
        // 显示进度
        printf("\rProgress: %u/%u bytes (%.1f%%)", 
               total_sent, file_size, (100.0 * total_sent) / file_size);
        fflush(stdout);
    }
    
    printf("\n");
    close(fd);
    
    // 等待确认
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        return -1;
    }
    
    if (response.status_code == STATUS_CREATED) {
        printf("Upload complete: %s\n", response.message);
        return 0;
    } else {
        printf("Upload failed: %s\n", response.message);
        return -1;
    }
}

/**
 * 下载文件
 */
int client_download(ClientContext *ctx, const char *remote_path, const char *local_path) {
    if (!ctx || !ctx->connected) return -1;
    
    // 发送下载请求
    RequestHeader header;
    protocol_init_request(&header, CMD_DOWNLOAD);
    strncpy(header.filename, remote_path, sizeof(header.filename) - 1);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        return -1;
    }
    
    // 接收响应
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        return -1;
    }
    
    if (response.status_code != STATUS_OK) {
        printf("Error: %s\n", response.message);
        return -1;
    }
    
    uint32_t file_size = response.payload_size;
    
    // 创建本地文件
    int fd = open(local_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("Failed to create file: %s\n", strerror(errno));
        return -1;
    }
    
    // 接收文件数据
    uint8_t buffer[BUFFER_SIZE];
    uint32_t total_recv = 0;
    
    printf("Downloading %s (%u bytes)...\n", remote_path, file_size);
    
    while (total_recv < file_size) {
        uint32_t to_recv = MIN(sizeof(buffer), file_size - total_recv);
        
        if (protocol_recv_file_data(ctx->sockfd, buffer, to_recv) != ERR_SUCCESS) {
            close(fd);
            return -1;
        }
        
        write(fd, buffer, to_recv);
        total_recv += to_recv;
        
        // 显示进度
        printf("\rProgress: %u/%u bytes (%.1f%%)",
               total_recv, file_size, (100.0 * total_recv) / file_size);
        fflush(stdout);
    }
    
    printf("\nDownload complete: %s\n", local_path);
    close(fd);
    
    return 0;
}

/**
 * 删除文件
 */
int client_delete(ClientContext *ctx, const char *path) {
    if (!ctx || !ctx->connected) return -1;
    
    RequestHeader header;
    protocol_init_request(&header, CMD_DELETE);
    strncpy(header.filename, path, sizeof(header.filename) - 1);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        return -1;
    }
    
    printf("%s: %s\n", 
           response.status_code == STATUS_OK ? "Deleted" : "Error",
           response.message);
    
    return response.status_code == STATUS_OK ? 0 : -1;
}

/**
 * 获取文件信息
 */
int client_stat(ClientContext *ctx, const char *path) {
    if (!ctx || !ctx->connected) return -1;
    
    RequestHeader header;
    protocol_init_request(&header, CMD_STAT);
    strncpy(header.filename, path, sizeof(header.filename) - 1);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        return -1;
    }
    
    ServerResponse response;
    FileInfoPayload info;
    
    if (protocol_recv_response(ctx->sockfd, &response, &info, sizeof(info)) != ERR_SUCCESS) {
        return -1;
    }
    
    if (response.status_code != STATUS_OK) {
        printf("Error: %s\n", response.message);
        return -1;
    }
    
    printf("File: %s\n", path);
    printf("  Type: %s\n", info.file_type == FILE_TYPE_DIRECTORY ? "Directory" : "Regular file");
    printf("  Size: %u bytes\n", info.size);
    printf("  Inode: %u\n", info.inode_id);
    
    return 0;
}

/*============================================================================
 * 目录操作
 *============================================================================*/

/**
 * 创建目录
 */
int client_mkdir(ClientContext *ctx, const char *path) {
    if (!ctx || !ctx->connected) return -1;
    
    RequestHeader header;
    protocol_init_request(&header, CMD_MKDIR);
    strncpy(header.filename, path, sizeof(header.filename) - 1);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        return -1;
    }
    
    printf("%s: %s\n",
           response.status_code == STATUS_CREATED ? "Created" : "Error",
           response.message);
    
    return response.status_code == STATUS_CREATED ? 0 : -1;
}

/**
 * 删除目录
 */
int client_rmdir(ClientContext *ctx, const char *path) {
    if (!ctx || !ctx->connected) return -1;
    
    RequestHeader header;
    protocol_init_request(&header, CMD_RMDIR);
    strncpy(header.filename, path, sizeof(header.filename) - 1);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        return -1;
    }
    
    printf("%s: %s\n",
           response.status_code == STATUS_OK ? "Removed" : "Error",
           response.message);
    
    return response.status_code == STATUS_OK ? 0 : -1;
}

/**
 * 切换目录
 */
int client_cd(ClientContext *ctx, const char *path) {
    if (!ctx) return -1;
    
    // 本地切换(客户端状态)
    if (path[0] == '/') {
        strncpy(ctx->cwd, path, sizeof(ctx->cwd) - 1);
    } else if (strcmp(path, "..") == 0) {
        char *last_slash = strrchr(ctx->cwd, '/');
        if (last_slash != ctx->cwd) {
            *last_slash = '\0';
        }
    } else {
        size_t len = strlen(ctx->cwd);
        if (len > 1) {
            strncat(ctx->cwd, "/", sizeof(ctx->cwd) - len - 1);
        }
        strncat(ctx->cwd, path, sizeof(ctx->cwd) - strlen(ctx->cwd) - 1);
    }
    
    printf("Current directory: %s\n", ctx->cwd);
    return 0;
}

/**
 * 显示当前目录
 */
int client_pwd(ClientContext *ctx) {
    if (!ctx) return -1;
    
    printf("%s\n", ctx->cwd);
    return 0;
}

/*============================================================================
 * 论文操作
 *============================================================================*/

/**
 * 提交论文
 */
int client_submit_paper(ClientContext *ctx, const char *local_path,
                        const char *title, const char *author, const char *abstract) {
    if (!ctx || !ctx->connected) return -1;
    
    // 打开本地文件
    int fd = open(local_path, O_RDONLY);
    if (fd < 0) {
        printf("Failed to open file: %s\n", strerror(errno));
        return -1;
    }
    
    struct stat st;
    fstat(fd, &st);
    
    // 准备载荷
    PaperSubmitPayload payload;
    memset(&payload, 0, sizeof(payload));
    strncpy(payload.title, title, sizeof(payload.title) - 1);
    strncpy(payload.author, author, sizeof(payload.author) - 1);
    if (abstract) {
        strncpy(payload.abstract, abstract, sizeof(payload.abstract) - 1);
    }
    
    // 提取文件名
    const char *filename = strrchr(local_path, '/');
    filename = filename ? filename + 1 : local_path;
    strncpy(payload.filename, filename, sizeof(payload.filename) - 1);
    payload.file_size = st.st_size;
    
    // 发送请求
    RequestHeader header;
    protocol_init_request(&header, CMD_SUBMIT_PAPER);
    header.payload_size = sizeof(payload);
    
    if (protocol_send_request(ctx->sockfd, &header, &payload) != ERR_SUCCESS) {
        close(fd);
        return -1;
    }
    
    // 等待响应
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        close(fd);
        return -1;
    }
    
    if (response.status_code != STATUS_OK) {
        printf("Error: %s\n", response.message);
        close(fd);
        return -1;
    }
    
    // 发送文件数据
    uint8_t buffer[BUFFER_SIZE];
    uint32_t total_sent = 0;
    
    printf("Submitting paper: %s\n", title);
    
    while (total_sent < payload.file_size) {
        ssize_t bytes = read(fd, buffer, sizeof(buffer));
        if (bytes <= 0) break;
        
        if (protocol_send_file_data(ctx->sockfd, buffer, bytes) != ERR_SUCCESS) {
            close(fd);
            return -1;
        }
        
        total_sent += bytes;
    }
    
    close(fd);
    
    // 等待确认
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        return -1;
    }
    
    printf("%s\n", response.message);
    return response.status_code == STATUS_CREATED ? 0 : -1;
}

/**
 * 查询论文状态
 */
int client_query_paper(ClientContext *ctx, uint32_t paper_id) {
    if (!ctx || !ctx->connected) return -1;
    
    RequestHeader header;
    protocol_init_request(&header, CMD_QUERY_STATUS);
    snprintf(header.filename, sizeof(header.filename), "/papers/paper_%u.pdf", paper_id);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        return -1;
    }
    
    ServerResponse response;
    PaperStatusPayload status;
    
    if (protocol_recv_response(ctx->sockfd, &response, &status, sizeof(status)) != ERR_SUCCESS) {
        return -1;
    }
    
    if (response.status_code != STATUS_OK) {
        printf("Error: %s\n", response.message);
        return -1;
    }
    
    const char *status_str[] = {"Submitted", "Under Review", "Revision Required", "Accepted", "Rejected"};
    
    printf("Paper ID: %u\n", status.paper_id);
    printf("Status: %s\n", status_str[status.status]);
    
    return 0;
}

/*============================================================================
 * 交互式命令行
 *============================================================================*/

/**
 * 打印帮助信息
 */
void client_print_help(void) {
    printf("\n");
    printf("Available commands:\n");
    printf("\n--- Connection ---\n");
    printf("  connect <host> <port>     - Connect to server\n");
    printf("  disconnect                - Disconnect from server\n");
    printf("  login <username> <role>   - Login (role: 0=guest, 1=author, 2=reviewer, 3=editor, 4=admin)\n");
    printf("  logout                    - Logout\n");
    printf("  status                    - Show connection status\n");
    printf("\n--- File Operations ---\n");
    printf("  ls [path]                 - List directory contents\n");
    printf("  cd <path>                 - Change directory\n");
    printf("  pwd                       - Print working directory\n");
    printf("  mkdir <path>              - Create directory (admin only)\n");
    printf("  rmdir <path>              - Remove directory (admin only)\n");
    printf("  upload <local> <remote>   - Upload file\n");
    printf("  download <remote> <local> - Download file\n");
    printf("  delete <path>             - Delete file\n");
    printf("  stat <path>               - Show file info\n");
    printf("\n--- Paper Submission ---\n");
    printf("  submit <file> <title> <author> - Submit paper\n");
    printf("\n--- Review Management (Reviewer/Editor) ---\n");
    printf("  review <paper_id> <score> <decision> <comments> - Upload review\n");
    printf("  getreview <paper_id>      - Query reviews for paper\n");
    printf("  assign <paper_id> <reviewer> - Assign reviewer (editor)\n");
    printf("  decide <paper_id> <accept|reject|revision> - Make decision (editor)\n");
    printf("\n--- Backup Management (Admin) ---\n");
    printf("  backup create [desc]      - Create backup\n");
    printf("  backup list               - List all backups\n");
    printf("  backup restore <id>       - Restore backup\n");
    printf("\n--- User Management (Admin) ---\n");
    printf("  useradd <username> <password> <role> - Add user\n");
    printf("  userdel <username>        - Delete user\n");
    printf("  userlist                  - List all users\n");
    printf("\n--- System (Admin) ---\n");
    printf("  sysinfo                   - Show system status\n");
    printf("\n--- General ---\n");
    printf("  help                      - Show this help\n");
    printf("  quit                      - Exit\n");
    printf("\n");
}

/**
 * 打印状态
 */
void client_print_status(ClientContext *ctx) {
    printf("\n");
    printf("Connection Status:\n");
    printf("  Connected:     %s\n", ctx->connected ? "Yes" : "No");
    if (ctx->connected) {
        printf("  Server:        %s:%u\n", ctx->server_host, ctx->server_port);
        printf("  Authenticated: %s\n", ctx->authenticated ? "Yes" : "No");
        if (ctx->authenticated) {
            printf("  Username:      %s\n", ctx->username);
            printf("  Role:          %d\n", ctx->role);
        }
        printf("  Working Dir:   %s\n", ctx->cwd);
    }
    printf("\n");
}

/**
 * 解析并执行命令
 */
int client_parse_command(ClientContext *ctx, const char *cmdline) {
    char cmd[64] = {0};
    char arg1[256] = {0};
    char arg2[256] = {0};
    char arg3[256] = {0};
    
    int argc = sscanf(cmdline, "%63s %255s %255s %255s", cmd, arg1, arg2, arg3);
    
    if (argc < 1 || strlen(cmd) == 0) {
        return 0;
    }
    
    if (strcmp(cmd, "connect") == 0) {
        if (argc < 3) {
            printf("Usage: connect <host> <port>\n");
            return 0;
        }
        return client_connect(ctx, arg1, atoi(arg2));
    }
    else if (strcmp(cmd, "disconnect") == 0) {
        client_disconnect(ctx);
        return 0;
    }
    else if (strcmp(cmd, "login") == 0) {
        if (argc < 3) {
            printf("Usage: login <username> <password> [role]\n");
            printf("  For admin bootstrap: login admin 4\n");
            return 0;
        }
        // 支持两种格式：
        // login admin 4          (admin bootstrap，无密码)
        // login user password 1  (普通用户，有密码)
        if (argc == 3 && atoi(arg2) >= 0 && atoi(arg2) <= 4) {
            // 旧格式兼容: login <username> <role>
            return client_login(ctx, arg1, "", atoi(arg2));
        } else if (argc >= 4) {
            // 新格式: login <username> <password> <role>
            return client_login(ctx, arg1, arg2, atoi(arg3));
        } else {
            return client_login(ctx, arg1, arg2, ROLE_GUEST);
        }
    }
    else if (strcmp(cmd, "logout") == 0) {
        return client_logout(ctx);
    }
    else if (strcmp(cmd, "ls") == 0) {
        return client_ls(ctx, argc >= 2 ? arg1 : NULL);
    }
    else if (strcmp(cmd, "cd") == 0) {
        if (argc < 2) {
            printf("Usage: cd <path>\n");
            return 0;
        }
        return client_cd(ctx, arg1);
    }
    else if (strcmp(cmd, "pwd") == 0) {
        return client_pwd(ctx);
    }
    else if (strcmp(cmd, "mkdir") == 0) {
        if (argc < 2) {
            printf("Usage: mkdir <path>\n");
            return 0;
        }
        return client_mkdir(ctx, arg1);
    }
    else if (strcmp(cmd, "rmdir") == 0) {
        if (argc < 2) {
            printf("Usage: rmdir <path>\n");
            return 0;
        }
        return client_rmdir(ctx, arg1);
    }
    else if (strcmp(cmd, "upload") == 0) {
        if (argc < 3) {
            printf("Usage: upload <local> <remote>\n");
            return 0;
        }
        return client_upload(ctx, arg1, arg2);
    }
    else if (strcmp(cmd, "download") == 0) {
        if (argc < 3) {
            printf("Usage: download <remote> <local>\n");
            return 0;
        }
        return client_download(ctx, arg1, arg2);
    }
    else if (strcmp(cmd, "delete") == 0) {
        if (argc < 2) {
            printf("Usage: delete <path>\n");
            return 0;
        }
        return client_delete(ctx, arg1);
    }
    else if (strcmp(cmd, "stat") == 0) {
        if (argc < 2) {
            printf("Usage: stat <path>\n");
            return 0;
        }
        return client_stat(ctx, arg1);
    }
    else if (strcmp(cmd, "submit") == 0) {
        if (argc < 4) {
            printf("Usage: submit <file> <title> <author>\n");
            return 0;
        }
        return client_submit_paper(ctx, arg1, arg2, arg3, NULL);
    }
    else if (strcmp(cmd, "status") == 0) {
        client_print_status(ctx);
        return 0;
    }
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
        client_print_help();
        return 0;
    }
    else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        return -1;  // 退出信号
    }
    // ===== 新增命令 =====
    else if (strcmp(cmd, "backup") == 0) {
        if (argc < 2) {
            printf("Usage: backup <create|list|restore> [args]\n");
            return 0;
        }
        if (strcmp(arg1, "create") == 0) {
            return client_backup_create(ctx, argc >= 3 ? arg2 : NULL);
        } else if (strcmp(arg1, "list") == 0) {
            return client_backup_list(ctx);
        } else if (strcmp(arg1, "restore") == 0) {
            if (argc < 3) {
                printf("Usage: backup restore <backup_id>\n");
                return 0;
            }
            return client_backup_restore(ctx, atoi(arg2));
        } else {
            printf("Unknown backup command: %s\n", arg1);
            return 0;
        }
    }
    else if (strcmp(cmd, "useradd") == 0) {
        if (argc < 4) {
            printf("Usage: useradd <username> <password> <role>\n");
            return 0;
        }
        return client_user_add(ctx, arg1, arg2, atoi(arg3));
    }
    else if (strcmp(cmd, "userdel") == 0) {
        if (argc < 2) {
            printf("Usage: userdel <username>\n");
            return 0;
        }
        return client_user_delete(ctx, arg1);
    }
    else if (strcmp(cmd, "userlist") == 0) {
        return client_user_list(ctx);
    }
    else if (strcmp(cmd, "review") == 0) {
        if (argc < 4) {
            printf("Usage: review <paper_id> <score> <decision> \n");
            printf("       decision: accept, reject, or revision\n");
            return 0;
        }
        return client_upload_review(ctx, atoi(arg1), atoi(arg2), arg3, "");
    }
    else if (strcmp(cmd, "getreview") == 0) {
        if (argc < 2) {
            printf("Usage: getreview <paper_id>\n");
            return 0;
        }
        return client_query_review(ctx, atoi(arg1));
    }
    else if (strcmp(cmd, "assign") == 0) {
        if (argc < 3) {
            printf("Usage: assign <paper_id> <reviewer_username>\n");
            return 0;
        }
        return client_assign_reviewer(ctx, atoi(arg1), arg2);
    }
    else if (strcmp(cmd, "decide") == 0) {
        if (argc < 3) {
            printf("Usage: decide <paper_id> <accept|reject|revision>\n");
            return 0;
        }
        return client_make_decision(ctx, atoi(arg1), arg2);
    }
    else if (strcmp(cmd, "sysinfo") == 0) {
        return client_system_status(ctx);
    }
    else {
        printf("Unknown command: %s\n", cmd);
        printf("Type 'help' for available commands.\n");
        return 0;
    }
}

/**
 * 交互式命令行
 */
int client_interactive(ClientContext *ctx) {
    char line[512];
    
    printf("\n");
    printf("Paper Review File System Client\n");
    printf("================================\n");
    printf("Type 'help' for available commands.\n\n");
    
    while (1) {
        printf("prfs> ");
        fflush(stdout);
        
        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }
        
        // 移除换行符
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        if (client_parse_command(ctx, line) < 0) {
            break;
        }
    }
    
    return 0;
}

/*============================================================================
 * 新增命令实现 - 备份、用户管理、评审、系统状态
 *============================================================================*/

/**
 * 创建备份
 */
int client_backup_create(ClientContext *ctx, const char *description) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_BACKUP_CREATE);
    if (description) {
        strncpy(header.filename, description, sizeof(header.filename) - 1);
    }
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) != ERR_SUCCESS) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    printf("%s\n", response.message);
    return (response.status_code == STATUS_CREATED) ? 0 : -1;
}

/**
 * 列出备份
 */
int client_backup_list(ClientContext *ctx) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_BACKUP_LIST);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    if (response.status_code == STATUS_OK && response.payload_size > 0) {
        char *data = malloc(response.payload_size + 1);
        if (data) {
            if (protocol_recv_file_data(ctx->sockfd, data, response.payload_size) == 0) {
                data[response.payload_size] = '\0';
                printf("%s", data);
            }
            free(data);
        }
    } else {
        printf("%s\n", response.message);
    }
    
    return 0;
}

/**
 * 恢复备份
 */
int client_backup_restore(ClientContext *ctx, uint32_t backup_id) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_BACKUP_RESTORE);
    header.file_size = backup_id;  // 使用 file_size 传递 backup_id
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    printf("%s\n", response.message);
    return (response.status_code == STATUS_OK) ? 0 : -1;
}

/**
 * 添加用户
 */
int client_user_add(ClientContext *ctx, const char *username, const char *password, int role) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_USER_ADD);
    header.payload_size = sizeof(UserInfoPayload);
    
    UserInfoPayload payload;
    memset(&payload, 0, sizeof(payload));
    strncpy(payload.username, username, sizeof(payload.username) - 1);
    strncpy(payload.password, password, sizeof(payload.password) - 1);
    payload.role = role;
    
    if (protocol_send_request(ctx->sockfd, &header, &payload) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    printf("%s\n", response.message);
    return (response.status_code == STATUS_CREATED) ? 0 : -1;
}

/**
 * 删除用户
 */
int client_user_delete(ClientContext *ctx, const char *username) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_USER_DELETE);
    strncpy(header.filename, username, sizeof(header.filename) - 1);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    printf("%s\n", response.message);
    return (response.status_code == STATUS_OK) ? 0 : -1;
}

/**
 * 列出用户
 */
int client_user_list(ClientContext *ctx) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_USER_LIST);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    if (response.status_code == STATUS_OK && response.payload_size > 0) {
        char *data = malloc(response.payload_size + 1);
        if (data) {
            if (protocol_recv_file_data(ctx->sockfd, data, response.payload_size) == 0) {
                data[response.payload_size] = '\0';
                printf("%s", data);
            }
            free(data);
        }
    } else {
        printf("%s\n", response.message);
    }
    
    return 0;
}

/**
 * 上传评审意见
 */
int client_upload_review(ClientContext *ctx, uint32_t paper_id, int score, 
                         const char *decision, const char *comments) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_UPLOAD_REVIEW);
    header.payload_size = sizeof(ReviewPayload);
    
    ReviewPayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.paper_id = paper_id;
    payload.score = score;
    strncpy(payload.decision, decision, sizeof(payload.decision) - 1);
    strncpy(payload.comments, comments, sizeof(payload.comments) - 1);
    
    if (protocol_send_request(ctx->sockfd, &header, &payload) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    printf("%s\n", response.message);
    return (response.status_code == STATUS_CREATED) ? 0 : -1;
}

/**
 * 查询评审意见
 */
int client_query_review(ClientContext *ctx, uint32_t paper_id) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_QUERY_REVIEW);
    header.file_size = paper_id;  // 用 file_size 传递 paper_id
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    if (response.status_code == STATUS_OK && response.payload_size > 0) {
        char *data = malloc(response.payload_size + 1);
        if (data) {
            if (protocol_recv_file_data(ctx->sockfd, data, response.payload_size) == 0) {
                data[response.payload_size] = '\0';
                printf("%s", data);
            }
            free(data);
        }
    } else {
        printf("%s\n", response.message);
    }
    
    return 0;
}

/**
 * 分配审稿人
 */
int client_assign_reviewer(ClientContext *ctx, uint32_t paper_id, const char *reviewer) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_ASSIGN_REVIEWER);
    header.payload_size = sizeof(AssignReviewerPayload);
    
    AssignReviewerPayload payload;
    memset(&payload, 0, sizeof(payload));
    payload.paper_id = paper_id;
    strncpy(payload.reviewer, reviewer, sizeof(payload.reviewer) - 1);
    
    if (protocol_send_request(ctx->sockfd, &header, &payload) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    printf("%s\n", response.message);
    return (response.status_code == STATUS_OK) ? 0 : -1;
}

/**
 * 做出决定
 */
int client_make_decision(ClientContext *ctx, uint32_t paper_id, const char *decision) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_MAKE_DECISION);
    snprintf(header.filename, sizeof(header.filename), "%u:%s", paper_id, decision);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    printf("%s\n", response.message);
    return (response.status_code == STATUS_OK) ? 0 : -1;
}

/**
 * 查看系统状态
 */
int client_system_status(ClientContext *ctx) {
    if (!ctx || !ctx->connected) {
        printf("Not connected\n");
        return -1;
    }
    
    RequestHeader header;
    protocol_init_request(&header, CMD_SYSTEM_STATUS);
    
    if (protocol_send_request(ctx->sockfd, &header, NULL) < 0) {
        printf("Failed to send request\n");
        return -1;
    }
    
    ServerResponse response;
    if (protocol_recv_response(ctx->sockfd, &response, NULL, 0) != ERR_SUCCESS) {
        printf("Failed to receive response\n");
        return -1;
    }
    
    if (response.status_code == STATUS_OK && response.payload_size > 0) {
        char *data = malloc(response.payload_size + 1);
        if (data) {
            if (protocol_recv_file_data(ctx->sockfd, data, response.payload_size) == 0) {
                data[response.payload_size] = '\0';
                printf("%s", data);
            }
            free(data);
        }
    } else {
        printf("%s\n", response.message);
    }
    
    return 0;
}
