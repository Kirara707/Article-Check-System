/**
 * @file protocol.h
 * @brief 网络通信协议定义
 * 
 * 协议结构:
 * +----------------+----------------+
 * | RequestHeader  |    Payload     |
 * | (固定大小)     |  (可变大小)    |
 * +----------------+----------------+
 */

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "common.h"

/*============================================================================
 * 协议版本
 *============================================================================*/

#define PROTOCOL_VERSION    1
#define PROTOCOL_MAGIC      0x50525450  // "PRTP"

/*============================================================================
 * 请求头结构
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t magic;                     // 协议魔数
    uint32_t version;                   // 协议版本
    CommandType type;                   // 命令类型
    uint32_t payload_size;              // 载荷大小
    uint32_t session_id;                // 会话ID
    char filename[MAX_FILENAME];        // 目标路径
    uint32_t file_size;                 // 文件大小(上传时)
    uint32_t offset;                    // 偏移量
    uint32_t flags;                     // 标志位
    uint8_t reserved[52];               // 保留空间
} RequestHeader;

/*============================================================================
 * 响应结构
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t magic;                     // 协议魔数
    uint32_t version;                   // 协议版本
    StatusCode status_code;             // 状态码
    uint32_t payload_size;              // 载荷大小
    char message[256];                  // 状态消息
    uint8_t reserved[48];               // 保留空间
} ServerResponse;

/*============================================================================
 * 登录请求载荷
 *============================================================================*/

typedef struct __attribute__((packed)) {
    char username[64];                  // 用户名
    char password[64];                  // 密码(应该加密)
    UserRole role;                      // 请求的角色
} LoginPayload;

/*============================================================================
 * 文件信息载荷
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t inode_id;                  // Inode编号
    FileType file_type;                 // 文件类型
    uint32_t size;                      // 文件大小
    uint64_t mtime;                     // 修改时间
    char filename[MAX_FILENAME];        // 文件名
} FileInfoPayload;

/*============================================================================
 * 目录列表载荷
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t entry_count;               // 条目数量
    FileInfoPayload entries[];          // 文件信息数组(柔性数组)
} DirListPayload;

/*============================================================================
 * 论文提交载荷
 *============================================================================*/

typedef struct __attribute__((packed)) {
    char title[256];                    // 论文标题
    char author[128];                   // 作者
    char abstract[1024];                // 摘要
    char filename[MAX_FILENAME];        // 文件名
    uint32_t file_size;                 // 文件大小
} PaperSubmitPayload;

/*============================================================================
 * 论文状态载荷
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t paper_id;                  // 论文ID
    PaperStatus status;                 // 当前状态
    char reviewer[64];                  // 评审者
    char comments[1024];                // 评审意见
    uint64_t submit_time;               // 提交时间
    uint64_t review_time;               // 评审时间
} PaperStatusPayload;

/*============================================================================
 * 协议工具函数
 *============================================================================*/

// 初始化请求头
void protocol_init_request(RequestHeader *header, CommandType type);

// 初始化响应
void protocol_init_response(ServerResponse *response, StatusCode status, const char *message);

// 发送请求
int protocol_send_request(int sockfd, const RequestHeader *header, const void *payload);

// 接收请求
int protocol_recv_request(int sockfd, RequestHeader *header, void *payload, uint32_t max_payload);

// 发送响应
int protocol_send_response(int sockfd, const ServerResponse *response, const void *payload);

// 接收响应
int protocol_recv_response(int sockfd, ServerResponse *response, void *payload, uint32_t max_payload);

// 发送文件数据
int protocol_send_file_data(int sockfd, const void *data, uint32_t size);

// 接收文件数据
int protocol_recv_file_data(int sockfd, void *data, uint32_t size);

// 验证协议头
bool protocol_validate_header(const RequestHeader *header);

// 获取状态码描述
const char* protocol_status_string(StatusCode status);

// 获取命令类型描述
const char* protocol_command_string(CommandType type);

#endif // PROTOCOL_H
