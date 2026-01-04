/**
 * @file server.h
 * @brief 服务器框架头文件
 */

#ifndef SERVER_H
#define SERVER_H

#include "common.h"
#include "vfs.h"
#include "protocol.h"
#include <netinet/in.h>

/*============================================================================
 * 客户端会话结构
 *============================================================================*/

typedef struct {
    int sockfd;                         // 客户端套接字
    uint32_t session_id;                // 会话ID
    struct sockaddr_in addr;            // 客户端地址
    
    bool authenticated;                 // 是否已认证
    char username[64];                  // 用户名
    UserRole role;                      // 用户角色
    
    char cwd[MAX_PATH];                 // 当前工作目录
    time_t last_active;                 // 最后活跃时间
    
    bool active;                        // 会话是否活跃
} ClientSession;

/*============================================================================
 * 任务结构(线程池)
 *============================================================================*/

typedef struct {
    void (*function)(void *arg);        // 任务函数
    void *arg;                          // 任务参数
} Task;

/*============================================================================
 * 线程池结构
 *============================================================================*/

typedef struct {
    pthread_t *threads;                 // 工作线程数组
    int thread_count;                   // 线程数量
    
    Task *task_queue;                   // 任务队列
    int queue_size;                     // 队列大小
    int queue_front;                    // 队列头
    int queue_rear;                     // 队列尾
    int task_count;                     // 当前任务数
    
    pthread_mutex_t queue_lock;         // 队列锁
    pthread_cond_t queue_not_empty;     // 队列非空条件变量
    pthread_cond_t queue_not_full;      // 队列未满条件变量
    
    bool shutdown;                      // 关闭标志
} ThreadPool;

/*============================================================================
 * 服务器上下文结构
 *============================================================================*/

typedef struct {
    int listen_fd;                      // 监听套接字
    uint16_t port;                      // 监听端口
    bool running;                       // 运行状态
    
    VFSContext *vfs;                    // VFS上下文
    ThreadPool *pool;                   // 线程池
    
    ClientSession *sessions;            // 会话数组
    int max_sessions;                   // 最大会话数
    pthread_mutex_t sessions_lock;      // 会话锁
    
    uint32_t next_session_id;           // 下一个会话ID
    
    // 统计信息
    uint64_t total_requests;            // 总请求数
    uint64_t total_bytes_in;            // 总接收字节
    uint64_t total_bytes_out;           // 总发送字节
    time_t start_time;                  // 启动时间
} ServerContext;

/*============================================================================
 * 服务器函数声明
 *============================================================================*/

// 服务器生命周期
int server_init(ServerContext *ctx, uint16_t port, VFSContext *vfs);
int server_start(ServerContext *ctx);
void server_stop(ServerContext *ctx);
void server_destroy(ServerContext *ctx);

// 客户端处理
void server_handle_client(void *arg);
int server_accept_client(ServerContext *ctx, ClientSession *session);
void server_close_client(ServerContext *ctx, ClientSession *session);

// 命令处理
int server_process_command(ServerContext *ctx, ClientSession *session,
                           RequestHeader *header, void *payload);
int server_handle_login(ServerContext *ctx, ClientSession *session,
                        RequestHeader *header, LoginPayload *payload);
int server_handle_ls(ServerContext *ctx, ClientSession *session,
                     RequestHeader *header);
int server_handle_upload(ServerContext *ctx, ClientSession *session,
                         RequestHeader *header);
int server_handle_download(ServerContext *ctx, ClientSession *session,
                           RequestHeader *header);
int server_handle_rmdir(ServerContext *ctx, ClientSession *session,
                        RequestHeader *header);
int server_handle_mkdir(ServerContext *ctx, ClientSession *session,
                        RequestHeader *header);
int server_handle_delete(ServerContext *ctx, ClientSession *session,
                         RequestHeader *header);

// 论文评审命令
int server_handle_submit_paper(ServerContext *ctx, ClientSession *session,
                               RequestHeader *header, PaperSubmitPayload *payload);
int server_handle_review_paper(ServerContext *ctx, ClientSession *session,
                               RequestHeader *header, PaperStatusPayload *payload);
int server_handle_query_status(ServerContext *ctx, ClientSession *session,
                               RequestHeader *header);

// 评审意见命令 (新增)
int server_handle_upload_review(ServerContext *ctx, ClientSession *session,
                                RequestHeader *header, ReviewPayload *payload);
int server_handle_query_review(ServerContext *ctx, ClientSession *session,
                               RequestHeader *header);
int server_handle_assign_reviewer(ServerContext *ctx, ClientSession *session,
                                  RequestHeader *header, AssignReviewerPayload *payload);
int server_handle_make_decision(ServerContext *ctx, ClientSession *session,
                                RequestHeader *header);

// 备份命令 (新增)
int server_handle_backup_create(ServerContext *ctx, ClientSession *session,
                                RequestHeader *header);
int server_handle_backup_list(ServerContext *ctx, ClientSession *session,
                              RequestHeader *header);
int server_handle_backup_restore(ServerContext *ctx, ClientSession *session,
                                 RequestHeader *header);

// 用户管理命令 (新增)
int server_handle_user_add(ServerContext *ctx, ClientSession *session,
                           RequestHeader *header, UserInfoPayload *payload);
int server_handle_user_delete(ServerContext *ctx, ClientSession *session,
                              RequestHeader *header);
int server_handle_user_list(ServerContext *ctx, ClientSession *session,
                            RequestHeader *header);

// 系统状态命令 (新增)
int server_handle_system_status(ServerContext *ctx, ClientSession *session,
                                RequestHeader *header);

/*============================================================================
 * 线程池函数声明
 *============================================================================*/

ThreadPool* threadpool_create(int thread_count, int queue_size);
int threadpool_add_task(ThreadPool *pool, void (*function)(void *), void *arg);
void threadpool_destroy(ThreadPool *pool);
void* threadpool_worker(void *arg);

/*============================================================================
 * 会话管理函数
 *============================================================================*/

ClientSession* session_alloc(ServerContext *ctx);
void session_free(ServerContext *ctx, ClientSession *session);
ClientSession* session_find_by_id(ServerContext *ctx, uint32_t session_id);
void session_cleanup_inactive(ServerContext *ctx, int timeout);

#endif // SERVER_H
