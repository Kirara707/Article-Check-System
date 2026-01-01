/**
 * @file protocol.c
 * @brief 网络通信协议实现
 */

#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

/*============================================================================
 * 协议初始化函数
 *============================================================================*/

/**
 * 初始化请求头
 */
void protocol_init_request(RequestHeader *header, CommandType type) {
    if (!header) return;
    
    memset(header, 0, sizeof(RequestHeader));
    header->magic = PROTOCOL_MAGIC;
    header->version = PROTOCOL_VERSION;
    header->type = type;
}

/**
 * 初始化响应
 */
void protocol_init_response(ServerResponse *response, StatusCode status, const char *message) {
    if (!response) return;
    
    memset(response, 0, sizeof(ServerResponse));
    response->magic = PROTOCOL_MAGIC;
    response->version = PROTOCOL_VERSION;
    response->status_code = status;
    
    if (message) {
        strncpy(response->message, message, sizeof(response->message) - 1);
    }
}

/*============================================================================
 * 网络发送接收函数
 *============================================================================*/

/**
 * 可靠发送 - 确保发送所有数据
 */
static ssize_t send_all(int sockfd, const void *buf, size_t len) {
    size_t total_sent = 0;
    const uint8_t *ptr = (const uint8_t *)buf;
    
    while (total_sent < len) {
        ssize_t sent = send(sockfd, ptr + total_sent, len - total_sent, 0);
        if (sent <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total_sent += sent;
    }
    
    return total_sent;
}

/**
 * 可靠接收 - 确保接收所有数据
 */
static ssize_t recv_all(int sockfd, void *buf, size_t len) {
    size_t total_recv = 0;
    uint8_t *ptr = (uint8_t *)buf;
    
    while (total_recv < len) {
        ssize_t received = recv(sockfd, ptr + total_recv, len - total_recv, 0);
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (received == 0) {
            // 连接关闭
            return total_recv;
        }
        total_recv += received;
    }
    
    return total_recv;
}

/**
 * 发送请求
 */
int protocol_send_request(int sockfd, const RequestHeader *header, const void *payload) {
    if (sockfd < 0 || !header) {
        return ERR_NETWORK;
    }
    
    // 发送请求头
    if (send_all(sockfd, header, sizeof(RequestHeader)) != sizeof(RequestHeader)) {
        LOG_E("Failed to send request header: %s", strerror(errno));
        return ERR_NETWORK;
    }
    
    // 发送载荷
    if (payload && header->payload_size > 0) {
        if (send_all(sockfd, payload, header->payload_size) != header->payload_size) {
            LOG_E("Failed to send payload: %s", strerror(errno));
            return ERR_NETWORK;
        }
    }
    
    return ERR_SUCCESS;
}

/**
 * 接收请求
 */
int protocol_recv_request(int sockfd, RequestHeader *header, void *payload, uint32_t max_payload) {
    if (sockfd < 0 || !header) {
        return ERR_NETWORK;
    }
    
    // 接收请求头
    ssize_t received = recv_all(sockfd, header, sizeof(RequestHeader));
    if (received != sizeof(RequestHeader)) {
        if (received == 0) {
            return ERR_NETWORK;  // 连接关闭
        }
        LOG_E("Failed to receive request header: %s", strerror(errno));
        return ERR_NETWORK;
    }
    
    // 验证协议头
    if (!protocol_validate_header(header)) {
        LOG_E("Invalid protocol header");
        return ERR_NETWORK;
    }
    
    // 接收载荷
    if (payload && header->payload_size > 0) {
        uint32_t recv_size = MIN(header->payload_size, max_payload);
        if (recv_all(sockfd, payload, recv_size) != recv_size) {
            LOG_E("Failed to receive payload: %s", strerror(errno));
            return ERR_NETWORK;
        }
        
        // 丢弃多余数据
        if (header->payload_size > max_payload) {
            uint32_t skip = header->payload_size - max_payload;
            uint8_t skip_buf[1024];
            while (skip > 0) {
                uint32_t to_skip = MIN(skip, sizeof(skip_buf));
                recv_all(sockfd, skip_buf, to_skip);
                skip -= to_skip;
            }
        }
    }
    
    return ERR_SUCCESS;
}

/**
 * 发送响应
 */
int protocol_send_response(int sockfd, const ServerResponse *response, const void *payload) {
    if (sockfd < 0 || !response) {
        return ERR_NETWORK;
    }
    
    // 发送响应头
    if (send_all(sockfd, response, sizeof(ServerResponse)) != sizeof(ServerResponse)) {
        LOG_E("Failed to send response: %s", strerror(errno));
        return ERR_NETWORK;
    }
    
    // 发送载荷
    if (payload && response->payload_size > 0) {
        if (send_all(sockfd, payload, response->payload_size) != response->payload_size) {
            LOG_E("Failed to send response payload: %s", strerror(errno));
            return ERR_NETWORK;
        }
    }
    
    return ERR_SUCCESS;
}

/**
 * 接收响应
 */
int protocol_recv_response(int sockfd, ServerResponse *response, void *payload, uint32_t max_payload) {
    if (sockfd < 0 || !response) {
        return ERR_NETWORK;
    }
    
    // 接收响应头
    ssize_t received = recv_all(sockfd, response, sizeof(ServerResponse));
    if (received != sizeof(ServerResponse)) {
        LOG_E("Failed to receive response: %s", strerror(errno));
        return ERR_NETWORK;
    }
    
    // 验证魔数
    if (response->magic != PROTOCOL_MAGIC) {
        LOG_E("Invalid response magic");
        return ERR_NETWORK;
    }
    
    // 接收载荷
    if (payload && response->payload_size > 0) {
        uint32_t recv_size = MIN(response->payload_size, max_payload);
        if (recv_all(sockfd, payload, recv_size) != recv_size) {
            LOG_E("Failed to receive response payload: %s", strerror(errno));
            return ERR_NETWORK;
        }
    }
    
    return ERR_SUCCESS;
}

/**
 * 发送文件数据
 */
int protocol_send_file_data(int sockfd, const void *data, uint32_t size) {
    if (sockfd < 0 || !data) {
        return ERR_NETWORK;
    }
    
    if (send_all(sockfd, data, size) != size) {
        LOG_E("Failed to send file data: %s", strerror(errno));
        return ERR_NETWORK;
    }
    
    return ERR_SUCCESS;
}

/**
 * 接收文件数据
 */
int protocol_recv_file_data(int sockfd, void *data, uint32_t size) {
    if (sockfd < 0 || !data) {
        return ERR_NETWORK;
    }
    
    if (recv_all(sockfd, data, size) != size) {
        LOG_E("Failed to receive file data: %s", strerror(errno));
        return ERR_NETWORK;
    }
    
    return ERR_SUCCESS;
}

/**
 * 验证协议头
 */
bool protocol_validate_header(const RequestHeader *header) {
    if (!header) return false;
    
    if (header->magic != PROTOCOL_MAGIC) {
        LOG_E("Invalid magic: 0x%08X", header->magic);
        return false;
    }
    
    if (header->version != PROTOCOL_VERSION) {
        LOG_W("Version mismatch: %u vs %u", header->version, PROTOCOL_VERSION);
        // 可以选择是否兼容
    }
    
    return true;
}

/**
 * 获取状态码描述
 */
const char* protocol_status_string(StatusCode status) {
    switch (status) {
        case STATUS_OK:           return "OK";
        case STATUS_CREATED:      return "Created";
        case STATUS_BAD_REQUEST:  return "Bad Request";
        case STATUS_UNAUTHORIZED: return "Unauthorized";
        case STATUS_NOT_FOUND:    return "Not Found";
        case STATUS_CONFLICT:     return "Conflict";
        case STATUS_SERVER_ERROR: return "Internal Server Error";
        case STATUS_DISK_FULL:    return "Disk Full";
        default:                  return "Unknown Status";
    }
}

/**
 * 获取命令类型描述
 */
const char* protocol_command_string(CommandType type) {
    switch (type) {
        case CMD_LOGIN:         return "LOGIN";
        case CMD_LOGOUT:        return "LOGOUT";
        case CMD_LS:            return "LS";
        case CMD_UPLOAD:        return "UPLOAD";
        case CMD_DOWNLOAD:      return "DOWNLOAD";
        case CMD_DELETE:        return "DELETE";
        case CMD_MKDIR:         return "MKDIR";
        case CMD_RMDIR:         return "RMDIR";
        case CMD_CD:            return "CD";
        case CMD_STAT:          return "STAT";
        case CMD_FORMAT:        return "FORMAT";
        case CMD_SUBMIT_PAPER:  return "SUBMIT_PAPER";
        case CMD_REVIEW_PAPER:  return "REVIEW_PAPER";
        case CMD_QUERY_STATUS:  return "QUERY_STATUS";
        case CMD_UPDATE_STATUS: return "UPDATE_STATUS";
        default:                return "UNKNOWN";
    }
}
