/**
 * @file common.h
 * @brief 通用定义和常量
 * 
 * 科学论文评审平台 - 虚拟文件系统
 */

#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/*============================================================================
 * 系统常量定义
 *============================================================================*/

#define BLOCK_SIZE          4096        // 块大小: 4KB
#define DISK_SIZE           (64 * 1024 * 1024)  // 磁盘大小: 64MB
#define TOTAL_BLOCKS        (DISK_SIZE / BLOCK_SIZE)  // 总块数: 16384

#define MAX_FILENAME        128         // 最大文件名长度
#define MAX_PATH            512         // 最大路径长度
#define MAX_DIRECT_BLOCKS   12          // 直接块数量
#define INODE_COUNT         1024        // Inode总数

#define SUPERBLOCK_MAGIC    0x53465653  // "SVFS" - Simple VFS
#define VFS_VERSION         1           // 文件系统版本

/*============================================================================
 * 网络相关常量
 *============================================================================*/

#define DEFAULT_PORT        8080        // 默认端口
#define MAX_CLIENTS         512         // 最大客户端数
#define BUFFER_SIZE         8192        // 缓冲区大小
#define HEARTBEAT_TIMEOUT   30          // 心跳超时(秒)

/*============================================================================
 * 线程池常量
 *============================================================================*/

#define THREAD_POOL_SIZE    16          // 线程池大小
#define TASK_QUEUE_SIZE     256         // 任务队列大小

/*============================================================================
 * 状态码定义
 *============================================================================*/

typedef enum {
    STATUS_OK               = 200,      // 成功
    STATUS_CREATED          = 201,      // 创建成功
    STATUS_BAD_REQUEST      = 400,      // 请求错误
    STATUS_UNAUTHORIZED     = 401,      // 未授权
    STATUS_NOT_FOUND        = 404,      // 未找到
    STATUS_CONFLICT         = 409,      // 冲突
    STATUS_SERVER_ERROR     = 500,      // 服务器错误
    STATUS_DISK_FULL        = 507,      // 磁盘已满
} StatusCode;

/*============================================================================
 * 命令类型枚举
 *============================================================================*/

typedef enum {
    CMD_LOGIN       = 0,    // 登录
    CMD_LOGOUT      = 1,    // 登出
    CMD_LS          = 2,    // 列出文件
    CMD_UPLOAD      = 3,    // 上传文件
    CMD_DOWNLOAD    = 4,    // 下载文件
    CMD_DELETE      = 5,    // 删除文件
    CMD_MKDIR       = 6,    // 创建目录
    CMD_RMDIR       = 7,    // 删除目录
    CMD_CD          = 8,    // 切换目录
    CMD_STAT        = 9,    // 获取文件信息
    CMD_FORMAT      = 10,   // 格式化磁盘
    
    // 论文评审相关命令
    CMD_SUBMIT_PAPER    = 20,   // 提交论文
    CMD_REVIEW_PAPER    = 21,   // 评审论文  
    CMD_QUERY_STATUS    = 22,   // 查询状态
    CMD_UPDATE_STATUS   = 23,   // 更新状态
    
    // 评审意见相关命令 (新增)
    CMD_UPLOAD_REVIEW   = 30,   // 上传评审意见
    CMD_QUERY_REVIEW    = 31,   // 查询评审意见
    CMD_ASSIGN_REVIEWER = 32,   // 分配审稿人 (编辑权限)
    CMD_MAKE_DECISION   = 33,   // 做出决定 (编辑权限)
    
    // 备份相关命令 (新增)
    CMD_BACKUP_CREATE   = 40,   // 创建备份
    CMD_BACKUP_LIST     = 41,   // 列出备份
    CMD_BACKUP_RESTORE  = 42,   // 恢复备份
    
    // 用户管理命令 (新增)
    CMD_USER_ADD        = 50,   // 添加用户
    CMD_USER_DELETE     = 51,   // 删除用户
    CMD_USER_LIST       = 52,   // 列出用户
    
    // 系统状态命令 (新增)
    CMD_SYSTEM_STATUS   = 60,   // 系统状态
} CommandType;

/*============================================================================
 * 文件类型枚举
 *============================================================================*/

typedef enum {
    FILE_TYPE_REGULAR   = 0,    // 普通文件
    FILE_TYPE_DIRECTORY = 1,    // 目录
    FILE_TYPE_SYMLINK   = 2,    // 符号链接
} FileType;

/*============================================================================
 * 论文状态枚举
 *============================================================================*/

typedef enum {
    PAPER_SUBMITTED         = 0,    // 已提交
    PAPER_UNDER_REVIEW      = 1,    // 审核中
    PAPER_REVISION_REQUIRED = 2,    // 需要修改
    PAPER_ACCEPTED          = 3,    // 已接受
    PAPER_REJECTED          = 4,    // 已拒绝
} PaperStatus;

/*============================================================================
 * 用户角色枚举
 *============================================================================*/

typedef enum {
    ROLE_GUEST      = 0,    // 访客
    ROLE_AUTHOR     = 1,    // 作者
    ROLE_REVIEWER   = 2,    // 评审者
    ROLE_EDITOR     = 3,    // 编辑 (新增)
    ROLE_ADMIN      = 4,    // 管理员
} UserRole;

/*============================================================================
 * 错误码定义
 *============================================================================*/

typedef enum {
    ERR_SUCCESS         = 0,
    ERR_DISK_FULL       = -1,
    ERR_FILE_NOT_FOUND  = -2,
    ERR_FILE_EXISTS     = -3,
    ERR_PERMISSION      = -4,
    ERR_INVALID_PATH    = -5,
    ERR_IO_ERROR        = -6,
    ERR_NO_INODE        = -7,
    ERR_INVALID_INODE   = -8,
    ERR_DIR_NOT_EMPTY   = -9,
    ERR_NOT_DIRECTORY   = -10,
    ERR_IS_DIRECTORY    = -11,
    ERR_NETWORK         = -12,
    ERR_TIMEOUT         = -13,
    ERR_AUTH_FAILED     = -14,
} ErrorCode;

/*============================================================================
 * 实用宏定义
 *============================================================================*/

#define MIN(a, b)           ((a) < (b) ? (a) : (b))
#define MAX(a, b)           ((a) > (b) ? (a) : (b))
#define ALIGN_UP(x, align)  (((x) + (align) - 1) & ~((align) - 1))
#define ARRAY_SIZE(arr)     (sizeof(arr) / sizeof((arr)[0]))

// 位图操作宏
#define BITMAP_SET(bitmap, bit)     ((bitmap)[(bit) / 8] |= (1 << ((bit) % 8)))
#define BITMAP_CLEAR(bitmap, bit)   ((bitmap)[(bit) / 8] &= ~(1 << ((bit) % 8)))
#define BITMAP_GET(bitmap, bit)     (((bitmap)[(bit) / 8] >> ((bit) % 8)) & 1)

// 日志宏
#define LOG_DEBUG   0
#define LOG_INFO    1
#define LOG_WARN    2
#define LOG_ERROR   3

#ifndef LOG_LEVEL
#define LOG_LEVEL LOG_INFO
#endif

#define LOG(level, fmt, ...) do { \
    if (level >= LOG_LEVEL) { \
        const char *level_str[] = {"DEBUG", "INFO", "WARN", "ERROR"}; \
        fprintf(stderr, "[%s] %s:%d: " fmt "\n", \
                level_str[level], __FILE__, __LINE__, ##__VA_ARGS__); \
    } \
} while(0)

#define LOG_D(fmt, ...) LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_I(fmt, ...) LOG(LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_W(fmt, ...) LOG(LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_E(fmt, ...) LOG(LOG_ERROR, fmt, ##__VA_ARGS__)

#endif // COMMON_H
