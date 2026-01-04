/**
 * @file client.h
 * @brief 客户端头文件
 */

#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include "protocol.h"

/*============================================================================
 * 客户端上下文结构
 *============================================================================*/

typedef struct {
    int sockfd;                         // 服务器连接套接字
    char server_host[256];              // 服务器地址
    uint16_t server_port;               // 服务器端口
    
    bool connected;                     // 连接状态
    bool authenticated;                 // 认证状态
    uint32_t session_id;                // 会话ID
    
    char username[64];                  // 用户名
    UserRole role;                      // 用户角色
    char cwd[MAX_PATH];                 // 当前工作目录
} ClientContext;

/*============================================================================
 * 客户端函数声明
 *============================================================================*/

// 连接管理
int client_init(ClientContext *ctx);
int client_connect(ClientContext *ctx, const char *host, uint16_t port);
void client_disconnect(ClientContext *ctx);
void client_destroy(ClientContext *ctx);

// 认证
int client_login(ClientContext *ctx, const char *username, const char *password, UserRole role);
int client_logout(ClientContext *ctx);

// 文件操作
int client_ls(ClientContext *ctx, const char *path);
int client_upload(ClientContext *ctx, const char *local_path, const char *remote_path);
int client_download(ClientContext *ctx, const char *remote_path, const char *local_path);
int client_delete(ClientContext *ctx, const char *path);
int client_stat(ClientContext *ctx, const char *path);

// 目录操作
int client_mkdir(ClientContext *ctx, const char *path);
int client_rmdir(ClientContext *ctx, const char *path);
int client_cd(ClientContext *ctx, const char *path);
int client_pwd(ClientContext *ctx);

// 论文操作
int client_submit_paper(ClientContext *ctx, const char *local_path, 
                        const char *title, const char *author, const char *abstract);
int client_query_paper(ClientContext *ctx, uint32_t paper_id);

// 交互式命令行
int client_interactive(ClientContext *ctx);
int client_parse_command(ClientContext *ctx, const char *cmdline);

// 工具函数
void client_print_help(void);
void client_print_status(ClientContext *ctx);


/*============================================================================
 * 新增命令函数声明
 *============================================================================*/

// 备份管理 (管理员)
int client_backup_create(ClientContext *ctx, const char *description);
int client_backup_list(ClientContext *ctx);
int client_backup_restore(ClientContext *ctx, uint32_t backup_id);

// 用户管理 (管理员)
int client_user_add(ClientContext *ctx, const char *username, const char *password, int role);
int client_user_delete(ClientContext *ctx, const char *username);
int client_user_list(ClientContext *ctx);

// 评审管理 (审稿人/编辑)
int client_upload_review(ClientContext *ctx, uint32_t paper_id, int score, 
                         const char *decision, const char *comments);
int client_query_review(ClientContext *ctx, uint32_t paper_id);
int client_assign_reviewer(ClientContext *ctx, uint32_t paper_id, const char *reviewer);
int client_make_decision(ClientContext *ctx, uint32_t paper_id, const char *decision);

// 系统状态
int client_system_status(ClientContext *ctx);

#endif /* CLIENT_H */
