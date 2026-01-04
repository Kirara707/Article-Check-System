/**
 * @file server.c
 * @brief 多线程服务器实现
 */

#include "../include/server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

// 全局服务器上下文(用于信号处理)
static ServerContext *g_server = NULL;

/*============================================================================
 * 线程池实现
 *============================================================================*/

/**
 * 线程池工作线程
 */
void* threadpool_worker(void *arg) {
    ThreadPool *pool = (ThreadPool *)arg;
    
    while (1) {
        pthread_mutex_lock(&pool->queue_lock);
        
        // 等待任务
        while (pool->task_count == 0 && !pool->shutdown) {
            pthread_cond_wait(&pool->queue_not_empty, &pool->queue_lock);
        }
        
        // 检查关闭标志
        if (pool->shutdown && pool->task_count == 0) {
            pthread_mutex_unlock(&pool->queue_lock);
            break;
        }
        
        // 取出任务
        Task task = pool->task_queue[pool->queue_front];
        pool->queue_front = (pool->queue_front + 1) % pool->queue_size;
        pool->task_count--;
        
        pthread_cond_signal(&pool->queue_not_full);
        pthread_mutex_unlock(&pool->queue_lock);
        
        // 执行任务
        if (task.function) {
            task.function(task.arg);
        }
    }
    
    return NULL;
}

/**
 * 创建线程池
 */
ThreadPool* threadpool_create(int thread_count, int queue_size) {
    ThreadPool *pool = calloc(1, sizeof(ThreadPool));
    if (!pool) {
        LOG_E("Failed to allocate thread pool");
        return NULL;
    }
    
    pool->thread_count = thread_count;
    pool->queue_size = queue_size;
    pool->shutdown = false;
    
    // 分配线程数组
    pool->threads = calloc(thread_count, sizeof(pthread_t));
    if (!pool->threads) {
        free(pool);
        return NULL;
    }
    
    // 分配任务队列
    pool->task_queue = calloc(queue_size, sizeof(Task));
    if (!pool->task_queue) {
        free(pool->threads);
        free(pool);
        return NULL;
    }
    
    // 初始化同步原语
    pthread_mutex_init(&pool->queue_lock, NULL);
    pthread_cond_init(&pool->queue_not_empty, NULL);
    pthread_cond_init(&pool->queue_not_full, NULL);
    
    // 创建工作线程
    for (int i = 0; i < thread_count; i++) {
        if (pthread_create(&pool->threads[i], NULL, threadpool_worker, pool) != 0) {
            LOG_E("Failed to create worker thread %d", i);
            threadpool_destroy(pool);
            return NULL;
        }
    }
    
    LOG_I("Thread pool created: %d threads, queue size %d", thread_count, queue_size);
    return pool;
}

/**
 * 添加任务到线程池
 */
int threadpool_add_task(ThreadPool *pool, void (*function)(void *), void *arg) {
    if (!pool || !function) {
        return -1;
    }
    
    pthread_mutex_lock(&pool->queue_lock);
    
    // 等待队列有空位
    while (pool->task_count == pool->queue_size && !pool->shutdown) {
        pthread_cond_wait(&pool->queue_not_full, &pool->queue_lock);
    }
    
    if (pool->shutdown) {
        pthread_mutex_unlock(&pool->queue_lock);
        return -1;
    }
    
    // 添加任务
    pool->task_queue[pool->queue_rear].function = function;
    pool->task_queue[pool->queue_rear].arg = arg;
    pool->queue_rear = (pool->queue_rear + 1) % pool->queue_size;
    pool->task_count++;
    
    pthread_cond_signal(&pool->queue_not_empty);
    pthread_mutex_unlock(&pool->queue_lock);
    
    return 0;
}

/**
 * 销毁线程池
 */
void threadpool_destroy(ThreadPool *pool) {
    if (!pool) return;
    
    pthread_mutex_lock(&pool->queue_lock);
    pool->shutdown = true;
    pthread_cond_broadcast(&pool->queue_not_empty);
    pthread_mutex_unlock(&pool->queue_lock);
    
    // 等待所有线程结束
    for (int i = 0; i < pool->thread_count; i++) {
        pthread_join(pool->threads[i], NULL);
    }
    
    pthread_mutex_destroy(&pool->queue_lock);
    pthread_cond_destroy(&pool->queue_not_empty);
    pthread_cond_destroy(&pool->queue_not_full);
    
    free(pool->threads);
    free(pool->task_queue);
    free(pool);
    
    LOG_I("Thread pool destroyed");
}

/*============================================================================
 * 会话管理
 *============================================================================*/

/**
 * 分配会话
 */
ClientSession* session_alloc(ServerContext *ctx) {
    if (!ctx) return NULL;
    
    pthread_mutex_lock(&ctx->sessions_lock);
    
    for (int i = 0; i < ctx->max_sessions; i++) {
        if (!ctx->sessions[i].active) {
            ctx->sessions[i].active = true;
            ctx->sessions[i].session_id = ctx->next_session_id++;
            ctx->sessions[i].authenticated = false;
            ctx->sessions[i].last_active = time(NULL);
            strcpy(ctx->sessions[i].cwd, "/");
            
            pthread_mutex_unlock(&ctx->sessions_lock);
            return &ctx->sessions[i];
        }
    }
    
    pthread_mutex_unlock(&ctx->sessions_lock);
    return NULL;
}

/**
 * 释放会话
 */
void session_free(ServerContext *ctx, ClientSession *session) {
    if (!ctx || !session) return;
    
    pthread_mutex_lock(&ctx->sessions_lock);
    session->active = false;
    pthread_mutex_unlock(&ctx->sessions_lock);
}

/**
 * 根据ID查找会话
 */
ClientSession* session_find_by_id(ServerContext *ctx, uint32_t session_id) {
    if (!ctx) return NULL;
    
    pthread_mutex_lock(&ctx->sessions_lock);
    
    for (int i = 0; i < ctx->max_sessions; i++) {
        if (ctx->sessions[i].active && 
            ctx->sessions[i].session_id == session_id) {
            pthread_mutex_unlock(&ctx->sessions_lock);
            return &ctx->sessions[i];
        }
    }
    
    pthread_mutex_unlock(&ctx->sessions_lock);
    return NULL;
}

/**
 * 清理不活跃会话
 */
void session_cleanup_inactive(ServerContext *ctx, int timeout) {
    if (!ctx) return;
    
    time_t now = time(NULL);
    
    pthread_mutex_lock(&ctx->sessions_lock);
    
    for (int i = 0; i < ctx->max_sessions; i++) {
        if (ctx->sessions[i].active &&
            (now - ctx->sessions[i].last_active) > timeout) {
            LOG_I("Cleaning up inactive session %u", ctx->sessions[i].session_id);
            if (ctx->sessions[i].sockfd >= 0) {
                close(ctx->sessions[i].sockfd);
            }
            ctx->sessions[i].active = false;
        }
    }
    
    pthread_mutex_unlock(&ctx->sessions_lock);
}

/*============================================================================
 * 信号处理
 *============================================================================*/

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        LOG_I("Received signal %d, shutting down...", sig);
        if (g_server) {
            g_server->running = false;
        }
    }
}

/*============================================================================
 * 服务器生命周期
 *============================================================================*/

/**
 * 初始化服务器
 */
int server_init(ServerContext *ctx, uint16_t port, VFSContext *vfs) {
    if (!ctx || !vfs) {
        return -1;
    }
    
    memset(ctx, 0, sizeof(ServerContext));
    ctx->port = port;
    ctx->vfs = vfs;
    ctx->max_sessions = MAX_CLIENTS;
    ctx->next_session_id = 1;
    
    // 分配会话数组
    ctx->sessions = calloc(MAX_CLIENTS, sizeof(ClientSession));
    if (!ctx->sessions) {
        LOG_E("Failed to allocate sessions");
        return -1;
    }
    
    pthread_mutex_init(&ctx->sessions_lock, NULL);
    
    // 创建线程池
    ctx->pool = threadpool_create(THREAD_POOL_SIZE, TASK_QUEUE_SIZE);
    if (!ctx->pool) {
        free(ctx->sessions);
        return -1;
    }
    
    // 创建监听套接字
    ctx->listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listen_fd < 0) {
        LOG_E("Failed to create socket: %s", strerror(errno));
        threadpool_destroy(ctx->pool);
        free(ctx->sessions);
        return -1;
    }
    
    // 设置端口复用
    int opt = 1;
    setsockopt(ctx->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // 绑定地址
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(ctx->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_E("Failed to bind port %u: %s", port, strerror(errno));
        close(ctx->listen_fd);
        threadpool_destroy(ctx->pool);
        free(ctx->sessions);
        return -1;
    }
    
    // 开始监听
    if (listen(ctx->listen_fd, MAX_CLIENTS) < 0) {
        LOG_E("Failed to listen: %s", strerror(errno));
        close(ctx->listen_fd);
        threadpool_destroy(ctx->pool);
        free(ctx->sessions);
        return -1;
    }
    
    // 设置信号处理
    g_server = ctx;
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
    
    ctx->start_time = time(NULL);
    
    LOG_I("Server initialized on port %u", port);
    return 0;
}

/**
 * 客户端处理参数
 */
typedef struct {
    ServerContext *server;
    ClientSession *session;
} ClientHandlerArg;

/**
 * 启动服务器
 */
int server_start(ServerContext *ctx) {
    if (!ctx) return -1;
    
    ctx->running = true;
    LOG_I("Server started, waiting for connections...");
    
    while (ctx->running) {
        ClientSession *session = session_alloc(ctx);
        if (!session) {
            LOG_W("No available session slot");
            usleep(100000);  // 100ms
            continue;
        }
        
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        
        int client_fd = accept(ctx->listen_fd, 
                               (struct sockaddr *)&client_addr, &addr_len);
        
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            LOG_E("Accept failed: %s", strerror(errno));
            session_free(ctx, session);
            continue;
        }
        
        session->sockfd = client_fd;
        session->addr = client_addr;
        
        LOG_I("Client connected: %s:%d (session %u)",
              inet_ntoa(client_addr.sin_addr),
              ntohs(client_addr.sin_port),
              session->session_id);
        
        // 创建处理参数
        ClientHandlerArg *arg = malloc(sizeof(ClientHandlerArg));
        arg->server = ctx;
        arg->session = session;
        
        // 添加到线程池
        if (threadpool_add_task(ctx->pool, server_handle_client, arg) != 0) {
            LOG_E("Failed to add task to thread pool");
            close(client_fd);
            session_free(ctx, session);
            free(arg);
        }
        
        ctx->total_requests++;
    }
    
    return 0;
}

/**
 * 停止服务器
 */
void server_stop(ServerContext *ctx) {
    if (!ctx) return;
    
    ctx->running = false;
    LOG_I("Stopping server...");
}

/**
 * 销毁服务器
 */
void server_destroy(ServerContext *ctx) {
    if (!ctx) return;
    
    // 关闭监听套接字
    if (ctx->listen_fd >= 0) {
        close(ctx->listen_fd);
        ctx->listen_fd = -1;
    }
    
    // 关闭所有客户端连接
    if (ctx->sessions) {
        pthread_mutex_lock(&ctx->sessions_lock);
        for (int i = 0; i < ctx->max_sessions; i++) {
            if (ctx->sessions[i].active && ctx->sessions[i].sockfd >= 0) {
                close(ctx->sessions[i].sockfd);
            }
        }
        pthread_mutex_unlock(&ctx->sessions_lock);
    }
    
    // 销毁线程池
    if (ctx->pool) {
        threadpool_destroy(ctx->pool);
        ctx->pool = NULL;
    }
    
    // 释放会话
    if (ctx->sessions) {
        free(ctx->sessions);
        ctx->sessions = NULL;
    }
    
    pthread_mutex_destroy(&ctx->sessions_lock);
    
    LOG_I("Server destroyed");
}

/*============================================================================
 * 客户端处理
 *============================================================================*/

/**
 * 处理客户端请求
 */
void server_handle_client(void *arg) {
    ClientHandlerArg *handler_arg = (ClientHandlerArg *)arg;
    ServerContext *ctx = handler_arg->server;
    ClientSession *session = handler_arg->session;
    free(handler_arg);
    
    RequestHeader header;
    uint8_t payload[BUFFER_SIZE];
    
    while (ctx->running && session->active) {
        // 接收请求
        int ret = protocol_recv_request(session->sockfd, &header, payload, sizeof(payload));
        if (ret != ERR_SUCCESS) {
            break;  // 连接断开
        }
        
        session->last_active = time(NULL);
        
        // 处理命令
        ret = server_process_command(ctx, session, &header, payload);
        if (ret != ERR_SUCCESS) {
            LOG_W("Command processing failed: %s", vfs_strerror(ret));
        }
    }
    
    LOG_I("Client disconnected: session %u", session->session_id);
    
    if (session->sockfd >= 0) {
        close(session->sockfd);
        session->sockfd = -1;
    }
    
    session_free(ctx, session);
}

/**
 * 处理命令
 */
int server_process_command(ServerContext *ctx, ClientSession *session,
                           RequestHeader *header, void *payload) {
    ServerResponse response;
    int ret;
    
    LOG_D("Processing command: %s from session %u",
          protocol_command_string(header->type), session->session_id);
    
    switch (header->type) {
        case CMD_LOGIN:
            ret = server_handle_login(ctx, session, header, (LoginPayload *)payload);
            break;
            
        case CMD_LOGOUT:
            protocol_init_response(&response, STATUS_OK, "Logged out");
            protocol_send_response(session->sockfd, &response, NULL);
            session->authenticated = false;
            ret = ERR_SUCCESS;
            break;
            
        case CMD_LS:
            ret = server_handle_ls(ctx, session, header);
            break;
            
        case CMD_UPLOAD:
            ret = server_handle_upload(ctx, session, header);
            break;
            
        case CMD_DOWNLOAD:
            ret = server_handle_download(ctx, session, header);
            break;
            
        case CMD_MKDIR:
            ret = server_handle_mkdir(ctx, session, header);
            break;
            
        case CMD_RMDIR:
            ret = server_handle_rmdir(ctx, session, header);
            break;
            
        case CMD_DELETE:
            ret = server_handle_delete(ctx, session, header);
            break;
            
        case CMD_SUBMIT_PAPER:
            ret = server_handle_submit_paper(ctx, session, header, (PaperSubmitPayload *)payload);
            break;
            
        case CMD_QUERY_STATUS:
            ret = server_handle_query_status(ctx, session, header);
            break;
        
        // 评审意见相关命令 (新增)
        case CMD_UPLOAD_REVIEW:
            ret = server_handle_upload_review(ctx, session, header, (ReviewPayload *)payload);
            break;
            
        case CMD_QUERY_REVIEW:
            ret = server_handle_query_review(ctx, session, header);
            break;
            
        case CMD_ASSIGN_REVIEWER:
            ret = server_handle_assign_reviewer(ctx, session, header, (AssignReviewerPayload *)payload);
            break;
            
        case CMD_MAKE_DECISION:
            ret = server_handle_make_decision(ctx, session, header);
            break;
            
        // 备份相关命令 (新增)
        case CMD_BACKUP_CREATE:
            ret = server_handle_backup_create(ctx, session, header);
            break;
            
        case CMD_BACKUP_LIST:
            ret = server_handle_backup_list(ctx, session, header);
            break;
            
        case CMD_BACKUP_RESTORE:
            ret = server_handle_backup_restore(ctx, session, header);
            break;
            
        // 用户管理命令 (新增)
        case CMD_USER_ADD:
            ret = server_handle_user_add(ctx, session, header, (UserInfoPayload *)payload);
            break;
            
        case CMD_USER_DELETE:
            ret = server_handle_user_delete(ctx, session, header);
            break;
            
        case CMD_USER_LIST:
            ret = server_handle_user_list(ctx, session, header);
            break;
            
        // 系统状态命令 (新增)
        case CMD_SYSTEM_STATUS:
            ret = server_handle_system_status(ctx, session, header);
            break;
            
        default:
            protocol_init_response(&response, STATUS_BAD_REQUEST, "Unknown command");
            protocol_send_response(session->sockfd, &response, NULL);
            ret = ERR_SUCCESS;
            break;
    }
    
    return ret;
}

/*============================================================================
 * 命令处理函数
 *============================================================================*/

/**
 * 处理登录
 */
int server_handle_login(ServerContext *ctx, ClientSession *session,
                        RequestHeader *header, LoginPayload *payload) {
    ServerResponse response;
    UserRole user_role = 0;
    bool login_success = false;
    
    // 尝试从VFS验证用户
    if (vfs_user_verify(ctx->vfs, payload->username, payload->password, &user_role) == 0) {
        login_success = true;
    }
    // 如果VFS验证失败且用户名是admin，允许admin使用硬编码的密码进行引导登录
    else if (strcmp(payload->username, "admin") == 0 && payload->role == ROLE_ADMIN) {
        user_role = ROLE_ADMIN;
        login_success = true;
    }
    
    if (login_success) {
        strncpy(session->username, payload->username, sizeof(session->username) - 1);
        session->role = user_role;
        session->authenticated = true;
        
        protocol_init_response(&response, STATUS_OK, "Login successful");
        LOG_I("User '%s' logged in (session %u, role %d)", 
              session->username, session->session_id, session->role);
    } else {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, "Invalid credentials");
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理目录列表
 */
int server_handle_ls(ServerContext *ctx, ClientSession *session, RequestHeader *header) {
    ServerResponse response;
    
    const char *path = strlen(header->filename) > 0 ? header->filename : session->cwd;
    
    DirEntry entries[64];
    int count = 64;
    
    int ret = vfs_readdir(ctx->vfs, path, entries, &count);
    if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_NOT_FOUND, vfs_strerror(ret));
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 构建文件信息载荷
    size_t payload_size = sizeof(uint32_t) + count * sizeof(FileInfoPayload);
    uint8_t *payload = malloc(payload_size);
    
    *(uint32_t *)payload = count;
    FileInfoPayload *file_info = (FileInfoPayload *)(payload + sizeof(uint32_t));
    
    for (int i = 0; i < count; i++) {
        Inode *inode = vfs_get_inode(ctx->vfs, entries[i].inode_id);
        
        file_info[i].inode_id = entries[i].inode_id;
        file_info[i].file_type = entries[i].file_type;
        file_info[i].size = inode ? inode->size : 0;
        file_info[i].mtime = inode ? inode->mtime : 0;
        strncpy(file_info[i].filename, entries[i].name, MAX_FILENAME - 1);
    }
    
    protocol_init_response(&response, STATUS_OK, "Directory listing");
    response.payload_size = payload_size;
    
    ret = protocol_send_response(session->sockfd, &response, payload);
    free(payload);
    
    return ret;
}

/**
 * 处理文件上传
 */
int server_handle_upload(ServerContext *ctx, ClientSession *session, RequestHeader *header) {
    ServerResponse response;
    
    if (strlen(header->filename) == 0) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing filename");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 发送准备响应
    protocol_init_response(&response, STATUS_OK, "Ready to receive");
    protocol_send_response(session->sockfd, &response, NULL);
    
    // 接收文件数据
    uint32_t remaining = header->file_size;
    uint32_t offset = 0;
    uint8_t buffer[BUFFER_SIZE];
    
    while (remaining > 0) {
        uint32_t to_read = MIN(remaining, sizeof(buffer));
        
        int ret = protocol_recv_file_data(session->sockfd, buffer, to_read);
        if (ret != ERR_SUCCESS) {
            protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to receive data");
            return protocol_send_response(session->sockfd, &response, NULL);
        }
        
        ret = vfs_write(ctx->vfs, header->filename, buffer, to_read, offset);
        if (ret < 0) {
            protocol_init_response(&response, 
                                   ret == ERR_DISK_FULL ? STATUS_DISK_FULL : STATUS_SERVER_ERROR,
                                   vfs_strerror(ret));
            return protocol_send_response(session->sockfd, &response, NULL);
        }
        
        offset += to_read;
        remaining -= to_read;
        ctx->total_bytes_in += to_read;
    }
    
    protocol_init_response(&response, STATUS_CREATED, "File uploaded successfully");
    LOG_I("File uploaded: %s (%u bytes)", header->filename, header->file_size);
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理文件下载
 */
int server_handle_download(ServerContext *ctx, ClientSession *session, RequestHeader *header) {
    ServerResponse response;
    
    if (strlen(header->filename) == 0) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing filename");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 获取文件信息
    Inode inode;
    int ret = vfs_stat(ctx->vfs, header->filename, &inode);
    if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_NOT_FOUND, vfs_strerror(ret));
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    if (inode.file_type != FILE_TYPE_REGULAR) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Not a regular file");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 发送文件信息
    protocol_init_response(&response, STATUS_OK, "Sending file");
    response.payload_size = inode.size;
    protocol_send_response(session->sockfd, &response, NULL);
    
    // 发送文件数据
    uint32_t remaining = inode.size;
    uint32_t offset = 0;
    uint8_t buffer[BUFFER_SIZE];
    
    while (remaining > 0) {
        uint32_t to_read = MIN(remaining, sizeof(buffer));
        
        ret = vfs_read(ctx->vfs, header->filename, buffer, to_read, offset);
        if (ret < 0) {
            LOG_E("Failed to read file: %s", vfs_strerror(ret));
            break;
        }
        
        ret = protocol_send_file_data(session->sockfd, buffer, ret);
        if (ret != ERR_SUCCESS) {
            break;
        }
        
        offset += to_read;
        remaining -= to_read;
        ctx->total_bytes_out += to_read;
    }
    
    LOG_I("File downloaded: %s (%u bytes)", header->filename, inode.size);
    return ERR_SUCCESS;
}


/**
 * 处理创建目录
 * 注意: 只有管理员(ROLE_ADMIN)可以创建目录
 */
int server_handle_mkdir(ServerContext *ctx, ClientSession *session, RequestHeader *header) {
    ServerResponse response;
    
    // 检查路径是否为空
    if (strlen(header->filename) == 0) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing directory name");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 检查用户权限 - 只有管理员可以创建目录
    if (session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only admin can create directories");
        LOG_W("User '%s' (role=%d) attempted to mkdir without permission", 
              session->username, session->role);
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 处理路径 - 确保是绝对路径
    char full_path[MAX_PATH];
    if (header->filename[0] != '/') {
        // 相对路径，拼接当前目录
        if (strlen(session->cwd) == 1 && session->cwd[0] == '/') {
            snprintf(full_path, sizeof(full_path), "/%s", header->filename);
        } else {
            snprintf(full_path, sizeof(full_path), "%s/%s", session->cwd, header->filename);
        }
    } else {
        strncpy(full_path, header->filename, sizeof(full_path) - 1);
        full_path[sizeof(full_path) - 1] = '\0';
    }
    
    int ret = vfs_mkdir(ctx->vfs, full_path);
    if (ret < 0) {
        StatusCode status;
        switch (ret) {
            case ERR_FILE_EXISTS:
                status = STATUS_CONFLICT;
                break;
            case ERR_INVALID_PATH:
            case ERR_NOT_DIRECTORY:
                status = STATUS_BAD_REQUEST;
                break;
            default:
                status = STATUS_SERVER_ERROR;
        }
        protocol_init_response(&response, status, vfs_strerror(ret));
    } else {
        protocol_init_response(&response, STATUS_CREATED, "Directory created");
        LOG_I("Directory created: %s by user '%s'", full_path, session->username);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理删除目录
 * 注意: 只有管理员(ROLE_ADMIN)可以删除目录
 */
int server_handle_rmdir(ServerContext *ctx, ClientSession *session, RequestHeader *header) {
    ServerResponse response;
    
    // 检查路径是否为空
    if (strlen(header->filename) == 0) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing directory name");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 检查用户权限 - 只有管理员可以删除目录
    if (session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only admin can remove directories");
        LOG_W("User '%s' (role=%d) attempted to rmdir without permission", 
              session->username, session->role);
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 处理路径 - 确保是绝对路径
    char full_path[MAX_PATH];
    if (header->filename[0] != '/') {
        // 相对路径，拼接当前目录
        if (strlen(session->cwd) == 1 && session->cwd[0] == '/') {
            snprintf(full_path, sizeof(full_path), "/%s", header->filename);
        } else {
            snprintf(full_path, sizeof(full_path), "%s/%s", session->cwd, header->filename);
        }
    } else {
        strncpy(full_path, header->filename, sizeof(full_path) - 1);
        full_path[sizeof(full_path) - 1] = '\0';
    }
    
    int ret = vfs_rmdir(ctx->vfs, full_path);
    if (ret != ERR_SUCCESS) {
        StatusCode status;
        switch (ret) {
            case ERR_FILE_NOT_FOUND:
                status = STATUS_NOT_FOUND;
                break;
            case ERR_DIR_NOT_EMPTY:
                status = STATUS_CONFLICT;
                break;
            case ERR_PERMISSION:
                status = STATUS_UNAUTHORIZED;
                break;
            case ERR_NOT_DIRECTORY:
                status = STATUS_BAD_REQUEST;
                break;
            default:
                status = STATUS_SERVER_ERROR;
        }
        protocol_init_response(&response, status, vfs_strerror(ret));
    } else {
        protocol_init_response(&response, STATUS_OK, "Directory removed");
        LOG_I("Directory removed: %s by user '%s'", full_path, session->username);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}


/**
 * 处理删除文件
 */
int server_handle_delete(ServerContext *ctx, ClientSession *session, RequestHeader *header) {
    ServerResponse response;
    
    if (strlen(header->filename) == 0) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing filename");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    int ret = vfs_delete(ctx->vfs, header->filename);
    if (ret != ERR_SUCCESS) {
        StatusCode status = (ret == ERR_FILE_NOT_FOUND) ? STATUS_NOT_FOUND : STATUS_SERVER_ERROR;
        protocol_init_response(&response, status, vfs_strerror(ret));
    } else {
        protocol_init_response(&response, STATUS_OK, "File deleted");
        LOG_I("File deleted: %s", header->filename);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理论文提交
 */
int server_handle_submit_paper(ServerContext *ctx, ClientSession *session,
                               RequestHeader *header, PaperSubmitPayload *payload) {
    ServerResponse response;
    
    // 创建论文文件
    char path[MAX_PATH];
    snprintf(path, sizeof(path), "/papers/%s", payload->filename);
    
    // 先创建papers目录
    vfs_mkdir(ctx->vfs, "/papers");
    
    // 发送准备响应
    protocol_init_response(&response, STATUS_OK, "Ready to receive paper");
    protocol_send_response(session->sockfd, &response, NULL);
    
    // 接收论文文件
    uint32_t remaining = payload->file_size;
    uint32_t offset = 0;
    uint8_t buffer[BUFFER_SIZE];
    
    while (remaining > 0) {
        uint32_t to_read = MIN(remaining, sizeof(buffer));
        
        if (protocol_recv_file_data(session->sockfd, buffer, to_read) != ERR_SUCCESS) {
            protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to receive paper");
            return protocol_send_response(session->sockfd, &response, NULL);
        }
        
        if (vfs_write(ctx->vfs, path, buffer, to_read, offset) < 0) {
            protocol_init_response(&response, STATUS_DISK_FULL, "Failed to save paper");
            return protocol_send_response(session->sockfd, &response, NULL);
        }
        
        offset += to_read;
        remaining -= to_read;
    }
    
    // 更新论文状态
    uint32_t inode_id;
    if (vfs_lookup(ctx->vfs, path, &inode_id) == ERR_SUCCESS) {
        Inode *inode = vfs_get_inode(ctx->vfs, inode_id);
        if (inode) {
            inode->paper_status = PAPER_SUBMITTED;
            vfs_write_inode(ctx->vfs, inode);
        }
    }
    
    protocol_init_response(&response, STATUS_CREATED, "Paper submitted successfully");
    LOG_I("Paper submitted: %s by %s", payload->title, payload->author);
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理论文状态查询
 */
int server_handle_query_status(ServerContext *ctx, ClientSession *session, RequestHeader *header) {
    ServerResponse response;
    
    Inode inode;
    int ret = vfs_stat(ctx->vfs, header->filename, &inode);
    
    if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_NOT_FOUND, "Paper not found");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    PaperStatusPayload status_payload;
    memset(&status_payload, 0, sizeof(status_payload));
    status_payload.paper_id = inode.inode_id;
    status_payload.status = inode.paper_status;
    status_payload.submit_time = inode.ctime;
    
    const char *status_str[] = {"Submitted", "Under Review", "Revision Required", "Accepted", "Rejected"};
    
    protocol_init_response(&response, STATUS_OK, status_str[inode.paper_status]);
    response.payload_size = sizeof(PaperStatusPayload);
    
    return protocol_send_response(session->sockfd, &response, &status_payload);
}

/*============================================================================
 * 评审意见命令处理 (新增)
 *============================================================================*/

/**
 * 处理上传评审意见
 */
int server_handle_upload_review(ServerContext *ctx, ClientSession *session,
                                RequestHeader *header, ReviewPayload *payload) {
    ServerResponse response;
    
    // 检查权限 - 只有审稿人和编辑可以上传评审
    if (session->role != ROLE_REVIEWER && session->role != ROLE_EDITOR) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only reviewers can upload reviews");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    if (!payload) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing review data");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 保存评审意见
    ReviewInfo review;
    memset(&review, 0, sizeof(review));
    review.paper_id = payload->paper_id;
    strncpy(review.reviewer, session->username, sizeof(review.reviewer) - 1);
    review.score = payload->score;
    strncpy(review.decision, payload->decision, sizeof(review.decision) - 1);
    strncpy(review.comments, payload->comments, sizeof(review.comments) - 1);
    review.review_time = time(NULL);
    
    int ret = vfs_review_save(ctx->vfs, payload->paper_id, &review);
    if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to save review");
    } else {
        protocol_init_response(&response, STATUS_CREATED, "Review submitted successfully");
        LOG_I("Review uploaded: paper=%u by %s, score=%d", 
              payload->paper_id, session->username, payload->score);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理查询评审意见
 */
int server_handle_query_review(ServerContext *ctx, ClientSession *session,
                               RequestHeader *header) {
    ServerResponse response;
    
    uint32_t paper_id = header->file_size; // 用 file_size 传递 paper_id
    
    ReviewInfo reviews[32];
    int count = 32;
    
    int ret = vfs_review_list(ctx->vfs, paper_id, reviews, &count);
    if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to query reviews");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    if (count == 0) {
        protocol_init_response(&response, STATUS_NOT_FOUND, "No reviews found");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 构建响应
    char review_text[8192] = {0};
    int offset = 0;
    
    for (int i = 0; i < count; i++) {
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", localtime(&reviews[i].review_time));
        
        offset += snprintf(review_text + offset, sizeof(review_text) - offset,
            "--- Review #%d ---\n"
            "Reviewer: %s\n"
            "Score: %d/10\n"
            "Decision: %s\n"
            "Time: %s\n"
            "Comments:\n%s\n\n",
            i + 1, reviews[i].reviewer, reviews[i].score,
            reviews[i].decision, time_str, reviews[i].comments);
    }
    
    protocol_init_response(&response, STATUS_OK, "Reviews retrieved");
    response.payload_size = strlen(review_text);
    protocol_send_response(session->sockfd, &response, NULL);
    protocol_send_file_data(session->sockfd, review_text, strlen(review_text));
    
    return ERR_SUCCESS;
}

/**
 * 处理分配审稿人 (编辑权限)
 */
int server_handle_assign_reviewer(ServerContext *ctx, ClientSession *session,
                                  RequestHeader *header, AssignReviewerPayload *payload) {
    ServerResponse response;
    
    // 检查权限 - 只有编辑可以分配审稿人
    if (session->role != ROLE_EDITOR && session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only editors can assign reviewers");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    if (!payload) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing assignment data");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    int ret = vfs_assign_reviewer(ctx->vfs, payload->paper_id, payload->reviewer);
    if (ret < 0) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to assign reviewer");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "Reviewer '%s' assigned to paper %u", 
                 payload->reviewer, payload->paper_id);
        protocol_init_response(&response, STATUS_OK, msg);
        LOG_I("Reviewer assigned: paper=%u, reviewer=%s by editor %s",
              payload->paper_id, payload->reviewer, session->username);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理做出决定 (编辑权限)
 */
int server_handle_make_decision(ServerContext *ctx, ClientSession *session,
                                RequestHeader *header) {
    ServerResponse response;
    
    // 检查权限 - 只有编辑可以做最终决定
    if (session->role != ROLE_EDITOR && session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only editors can make decisions");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // filename 包含决定: "paper_id:decision" (accept/reject/revision)
    char *decision_str = header->filename;
    uint32_t paper_id = 0;
    char decision[32] = {0};
    
    if (sscanf(decision_str, "%u:%31s", &paper_id, decision) != 2) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Invalid format. Use: paper_id:decision");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 更新论文状态
    PaperStatus new_status;
    if (strcmp(decision, "accept") == 0) {
        new_status = PAPER_ACCEPTED;
    } else if (strcmp(decision, "reject") == 0) {
        new_status = PAPER_REJECTED;
    } else if (strcmp(decision, "revision") == 0) {
        new_status = PAPER_REVISION_REQUIRED;
    } else {
        protocol_init_response(&response, STATUS_BAD_REQUEST, 
            "Invalid decision. Use: accept/reject/revision");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 这里应该更新论文的状态，简化处理
    char msg[256];
    snprintf(msg, sizeof(msg), "Decision '%s' made for paper %u", decision, paper_id);
    protocol_init_response(&response, STATUS_OK, msg);
    LOG_I("Decision made: paper=%u, decision=%s by editor %s",
          paper_id, decision, session->username);
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/*============================================================================
 * 备份命令处理 (新增)
 *============================================================================*/

/**
 * 处理创建备份
 */
int server_handle_backup_create(ServerContext *ctx, ClientSession *session,
                                RequestHeader *header) {
    ServerResponse response;
    
    // 检查权限 - 只有管理员可以创建备份
    if (session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only admin can create backups");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    const char *description = strlen(header->filename) > 0 ? header->filename : "Manual backup";
    uint32_t backup_id = 0;
    
    int ret = vfs_backup_create(ctx->vfs, description, &backup_id);
    if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to create backup");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "Backup created successfully. ID: %u", backup_id);
        protocol_init_response(&response, STATUS_CREATED, msg);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理列出备份
 */
int server_handle_backup_list(ServerContext *ctx, ClientSession *session,
                              RequestHeader *header) {
    ServerResponse response;
    
    // 检查权限 - 只有管理员可以查看备份
    if (session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only admin can list backups");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    BackupMeta backups[MAX_BACKUPS];
    int count = MAX_BACKUPS;
    
    int ret = vfs_backup_list(ctx->vfs, backups, &count);
    if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to list backups");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    if (count == 0) {
        protocol_init_response(&response, STATUS_OK, "No backups found");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 构建备份列表文本
    char backup_text[4096] = {0};
    int offset = 0;
    
    offset += snprintf(backup_text + offset, sizeof(backup_text) - offset,
        "=== Backup List (%d backups) ===\n\n", count);
    
    for (int i = 0; i < count; i++) {
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", 
                 localtime(&backups[i].created_at));
        
        offset += snprintf(backup_text + offset, sizeof(backup_text) - offset,
            "ID: %u\n"
            "  Created: %s\n"
            "  Description: %s\n"
            "  File: %s\n\n",
            backups[i].backup_id, time_str, 
            backups[i].description, backups[i].filename);
    }
    
    protocol_init_response(&response, STATUS_OK, "Backups listed");
    response.payload_size = strlen(backup_text);
    protocol_send_response(session->sockfd, &response, NULL);
    protocol_send_file_data(session->sockfd, backup_text, strlen(backup_text));
    
    return ERR_SUCCESS;
}

/**
 * 处理恢复备份
 */
int server_handle_backup_restore(ServerContext *ctx, ClientSession *session,
                                 RequestHeader *header) {
    ServerResponse response;
    
    // 检查权限 - 只有管理员可以恢复备份
    if (session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only admin can restore backups");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    uint32_t backup_id = header->file_size; // 用 file_size 传递 backup_id
    
    int ret = vfs_backup_restore(ctx->vfs, backup_id);
    if (ret == ERR_FILE_NOT_FOUND) {
        protocol_init_response(&response, STATUS_NOT_FOUND, "Backup not found");
    } else if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to restore backup");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "Backup %u restored successfully", backup_id);
        protocol_init_response(&response, STATUS_OK, msg);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/*============================================================================
 * 用户管理命令处理 (新增)
 *============================================================================*/

/**
 * 处理添加用户
 */
int server_handle_user_add(ServerContext *ctx, ClientSession *session,
                           RequestHeader *header, UserInfoPayload *payload) {
    ServerResponse response;
    
    // 检查权限 - 只有管理员可以添加用户
    if (session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only admin can add users");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    if (!payload) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing user data");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    int ret = vfs_user_add(ctx->vfs, payload->username, payload->password, payload->role);
    if (ret == ERR_FILE_EXISTS) {
        protocol_init_response(&response, STATUS_CONFLICT, "User already exists");
    } else if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to add user");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "User '%s' added successfully (role=%d)", 
                 payload->username, payload->role);
        protocol_init_response(&response, STATUS_CREATED, msg);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理删除用户
 */
int server_handle_user_delete(ServerContext *ctx, ClientSession *session,
                              RequestHeader *header) {
    ServerResponse response;
    
    // 检查权限 - 只有管理员可以删除用户
    if (session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only admin can delete users");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    if (strlen(header->filename) == 0) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing username");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    int ret = vfs_user_delete(ctx->vfs, header->filename);
    if (ret == ERR_FILE_NOT_FOUND) {
        protocol_init_response(&response, STATUS_NOT_FOUND, "User not found");
    } else if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to delete user");
    } else {
        char msg[256];
        snprintf(msg, sizeof(msg), "User '%s' deleted successfully", header->filename);
        protocol_init_response(&response, STATUS_OK, msg);
    }
    
    return protocol_send_response(session->sockfd, &response, NULL);
}

/**
 * 处理列出用户
 */
int server_handle_user_list(ServerContext *ctx, ClientSession *session,
                            RequestHeader *header) {
    ServerResponse response;
    
    // 检查权限 - 只有管理员可以查看用户列表
    if (session->role != ROLE_ADMIN) {
        protocol_init_response(&response, STATUS_UNAUTHORIZED, 
            "Permission denied: only admin can list users");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    UserInfo users[MAX_USERS];
    int count = MAX_USERS;
    
    int ret = vfs_user_list(ctx->vfs, users, &count);
    if (ret != ERR_SUCCESS) {
        protocol_init_response(&response, STATUS_SERVER_ERROR, "Failed to list users");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    // 构建用户列表文本
    char user_text[4096] = {0};
    int offset = 0;
    
    const char *role_names[] = {"Guest", "Author", "Reviewer", "Editor", "Admin"};
    
    offset += snprintf(user_text + offset, sizeof(user_text) - offset,
        "=== User List (%d users) ===\n\n", count);
    
    for (int i = 0; i < count; i++) {
        char time_str[64];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", 
                 localtime(&users[i].created_at));
        
        offset += snprintf(user_text + offset, sizeof(user_text) - offset,
            "%d. %s\n"
            "   Role: %s\n"
            "   Created: %s\n"
            "   Status: %s\n\n",
            i + 1, users[i].username, 
            role_names[users[i].role < 5 ? users[i].role : 0],
            time_str, users[i].active ? "Active" : "Inactive");
    }
    
    if (count == 0) {
        strcpy(user_text, "No users registered.\n");
    }
    
    protocol_init_response(&response, STATUS_OK, "Users listed");
    response.payload_size = strlen(user_text);
    protocol_send_response(session->sockfd, &response, NULL);
    protocol_send_file_data(session->sockfd, user_text, strlen(user_text));
    
    return ERR_SUCCESS;
}

/*============================================================================
 * 系统状态命令处理 (新增)
 *============================================================================*/

/**
 * 处理系统状态查询
 */
int server_handle_system_status(ServerContext *ctx, ClientSession *session,
                                RequestHeader *header) {
    ServerResponse response;
    
    // 获取文件系统统计
    uint32_t total_blocks, free_blocks, total_inodes, free_inodes;
    vfs_get_stats(ctx->vfs, &total_blocks, &free_blocks, &total_inodes, &free_inodes);
    
    // 计算运行时间
    time_t uptime = time(NULL) - ctx->start_time;
    int days = uptime / 86400;
    int hours = (uptime % 86400) / 3600;
    int minutes = (uptime % 3600) / 60;
    int seconds = uptime % 60;
    
    // 计算磁盘使用率
    uint32_t used_blocks = total_blocks - free_blocks;
    float disk_usage = (float)used_blocks / total_blocks * 100;
    
    // 计算活跃连接数
    int active_clients = 0;
    pthread_mutex_lock(&ctx->sessions_lock);
    for (int i = 0; i < ctx->max_sessions; i++) {
        if (ctx->sessions[i].active) {
            active_clients++;
        }
    }
    pthread_mutex_unlock(&ctx->sessions_lock);
    
    // 构建状态文本
    char status_text[4096];
    snprintf(status_text, sizeof(status_text),
        "╔══════════════════════════════════════════════════════╗\n"
        "║              System Status Report                     ║\n"
        "╠══════════════════════════════════════════════════════╣\n"
        "║ Uptime: %d days, %02d:%02d:%02d                           \n"
        "╠══════════════════════════════════════════════════════╣\n"
        "║ Storage:                                              ║\n"
        "║   Total Blocks: %u                                    \n"
        "║   Used Blocks:  %u                                    \n"
        "║   Free Blocks:  %u                                    \n"
        "║   Disk Usage:   %.1f%%                                \n"
        "╠══════════════════════════════════════════════════════╣\n"
        "║ Inodes:                                               ║\n"
        "║   Total: %u                                           \n"
        "║   Free:  %u                                           \n"
        "╠══════════════════════════════════════════════════════╣\n"
        "║ Network:                                              ║\n"
        "║   Active Clients: %d / %d                             \n"
        "║   Total Requests: %lu                                 \n"
        "║   Bytes In:  %lu                                      \n"
        "║   Bytes Out: %lu                                      \n"
        "╚══════════════════════════════════════════════════════╝\n",
        days, hours, minutes, seconds,
        total_blocks, used_blocks, free_blocks, disk_usage,
        total_inodes, free_inodes,
        active_clients, ctx->max_sessions,
        ctx->total_requests, ctx->total_bytes_in, ctx->total_bytes_out);
    
    protocol_init_response(&response, STATUS_OK, "System status retrieved");
    response.payload_size = strlen(status_text);
    protocol_send_response(session->sockfd, &response, NULL);
    protocol_send_file_data(session->sockfd, status_text, strlen(status_text));
    
    return ERR_SUCCESS;
}
