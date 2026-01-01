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
            
        case CMD_DELETE:
            ret = server_handle_delete(ctx, session, header);
            break;
            
        case CMD_SUBMIT_PAPER:
            ret = server_handle_submit_paper(ctx, session, header, (PaperSubmitPayload *)payload);
            break;
            
        case CMD_QUERY_STATUS:
            ret = server_handle_query_status(ctx, session, header);
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
    
    // 简单的认证(生产环境应使用加密和数据库)
    if (strlen(payload->username) > 0) {
        strncpy(session->username, payload->username, sizeof(session->username) - 1);
        session->role = payload->role;
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
 */
int server_handle_mkdir(ServerContext *ctx, ClientSession *session, RequestHeader *header) {
    ServerResponse response;
    
    if (strlen(header->filename) == 0) {
        protocol_init_response(&response, STATUS_BAD_REQUEST, "Missing directory name");
        return protocol_send_response(session->sockfd, &response, NULL);
    }
    
    int ret = vfs_mkdir(ctx->vfs, header->filename);
    if (ret < 0) {
        StatusCode status = (ret == ERR_FILE_EXISTS) ? STATUS_CONFLICT : STATUS_SERVER_ERROR;
        protocol_init_response(&response, status, vfs_strerror(ret));
    } else {
        protocol_init_response(&response, STATUS_CREATED, "Directory created");
        LOG_I("Directory created: %s", header->filename);
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
