/**
 * @file vfs.h
 * @brief 虚拟文件系统核心结构定义
 * 
 * 磁盘布局:
 * +------------+---------------+---------------+-------------+-------------+
 * | SuperBlock | Inode Bitmap  | Data Bitmap   | Inode Table | Data Blocks |
 * | (1 block)  | (1 block)     | (2 blocks)    | (32 blocks) | (剩余块)    |
 * +------------+---------------+---------------+-------------+-------------+
 */

#ifndef VFS_H
#define VFS_H

#include "common.h"
#include <time.h>

/*============================================================================
 * 磁盘布局常量
 *============================================================================*/

#define SUPERBLOCK_BLOCK    0           // SuperBlock位置
#define INODE_BITMAP_BLOCK  1           // Inode位图起始块
#define INODE_BITMAP_BLOCKS 1           // Inode位图块数
#define DATA_BITMAP_BLOCK   2           // 数据位图起始块
#define DATA_BITMAP_BLOCKS  2           // 数据位图块数
#define INODE_TABLE_BLOCK   4           // Inode表起始块
#define INODE_TABLE_BLOCKS  32          // Inode表块数
#define DATA_BLOCK_START    36          // 数据块起始位置

#define INODES_PER_BLOCK    (BLOCK_SIZE / sizeof(Inode))
#define ROOT_INODE          0           // 根目录Inode号

/*============================================================================
 * SuperBlock结构
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t magic;                     // 魔数: SUPERBLOCK_MAGIC
    uint32_t version;                   // 文件系统版本
    uint32_t block_size;                // 块大小
    uint32_t total_blocks;              // 总块数
    uint32_t free_blocks;               // 空闲块数
    uint32_t total_inodes;              // 总Inode数
    uint32_t free_inodes;               // 空闲Inode数
    
    uint32_t inode_bitmap_start;        // Inode位图起始块
    uint32_t inode_bitmap_blocks;       // Inode位图块数
    uint32_t data_bitmap_start;         // 数据位图起始块
    uint32_t data_bitmap_blocks;        // 数据位图块数
    uint32_t inode_table_start;         // Inode表起始块
    uint32_t inode_table_blocks;        // Inode表块数
    uint32_t data_block_start;          // 数据块起始位置
    
    uint64_t create_time;               // 创建时间
    uint64_t mount_time;                // 挂载时间
    uint64_t write_time;                // 最后写入时间
    uint32_t mount_count;               // 挂载次数
    
    char volume_name[64];               // 卷名
    uint8_t reserved[3948];             // 保留空间(填满一个块)
} SuperBlock;

/*============================================================================
 * Inode结构
 *============================================================================*/

typedef struct __attribute__((packed)) {
    uint32_t inode_id;                  // Inode编号
    uint16_t mode;                      // 文件模式(类型+权限)
    uint16_t link_count;                // 硬链接计数
    uint32_t uid;                       // 用户ID
    uint32_t gid;                       // 组ID
    uint32_t size;                      // 文件大小(字节)
    uint32_t blocks;                    // 占用块数
    
    uint64_t atime;                     // 最后访问时间
    uint64_t mtime;                     // 最后修改时间
    uint64_t ctime;                     // 创建时间
    
    uint32_t direct_blocks[MAX_DIRECT_BLOCKS];  // 直接块指针
    uint32_t indirect_block;            // 一级间接块
    uint32_t double_indirect_block;     // 二级间接块
    
    FileType file_type;                 // 文件类型
    PaperStatus paper_status;           // 论文状态(如果是论文)
    
    uint8_t reserved[40];               // 保留空间
    
    // 运行时字段(不存盘)
    pthread_mutex_t lock;               // Inode级锁
    bool dirty;                         // 脏标记
} Inode;

/*============================================================================
 * 目录项结构
 *============================================================================*/

#define MAX_DIR_ENTRIES     (BLOCK_SIZE / sizeof(DirEntry))
#define DIR_ENTRY_NAME_LEN  120

typedef struct __attribute__((packed)) {
    uint32_t inode_id;                  // Inode编号
    uint8_t  file_type;                 // 文件类型
    uint8_t  name_len;                  // 名称长度
    char     name[DIR_ENTRY_NAME_LEN];  // 文件名
    uint16_t reserved;                  // 对齐填充
} DirEntry;

/*============================================================================
 * 文件描述符结构(运行时)
 *============================================================================*/

typedef struct {
    int fd;                             // 文件描述符ID
    uint32_t inode_id;                  // 关联的Inode
    uint32_t offset;                    // 当前偏移
    uint32_t flags;                     // 打开标志
    bool in_use;                        // 是否在使用
} FileDescriptor;

/*============================================================================
 * VFS上下文结构
 *============================================================================*/

typedef struct {
    int disk_fd;                        // 磁盘文件描述符
    char disk_path[MAX_PATH];           // 磁盘文件路径
    
    SuperBlock sb;                      // SuperBlock缓存
    uint8_t *inode_bitmap;              // Inode位图缓存
    uint8_t *data_bitmap;               // 数据位图缓存
    Inode *inode_table;                 // Inode表缓存
    
    pthread_mutex_t sb_lock;            // SuperBlock锁
    pthread_mutex_t inode_bitmap_lock;  // Inode位图锁
    pthread_mutex_t data_bitmap_lock;   // 数据位图锁
    
    bool mounted;                       // 是否已挂载
    bool readonly;                      // 只读模式
} VFSContext;

/*============================================================================
 * VFS操作函数声明
 *============================================================================*/

// 初始化和挂载
int vfs_init(VFSContext *ctx, const char *disk_path);
int vfs_format(VFSContext *ctx);
int vfs_mount(VFSContext *ctx);
int vfs_unmount(VFSContext *ctx);
void vfs_destroy(VFSContext *ctx);

// Inode操作
int vfs_alloc_inode(VFSContext *ctx, FileType type);
int vfs_free_inode(VFSContext *ctx, uint32_t inode_id);
Inode* vfs_get_inode(VFSContext *ctx, uint32_t inode_id);
int vfs_write_inode(VFSContext *ctx, Inode *inode);

// 数据块操作
int vfs_alloc_block(VFSContext *ctx);
int vfs_free_block(VFSContext *ctx, uint32_t block_id);
int vfs_read_block(VFSContext *ctx, uint32_t block_id, void *buf);
int vfs_write_block(VFSContext *ctx, uint32_t block_id, const void *buf);

// 文件操作
int vfs_create(VFSContext *ctx, const char *path, FileType type);
int vfs_delete(VFSContext *ctx, const char *path);
int vfs_read(VFSContext *ctx, const char *path, void *buf, uint32_t size, uint32_t offset);
int vfs_write(VFSContext *ctx, const char *path, const void *buf, uint32_t size, uint32_t offset);
int vfs_stat(VFSContext *ctx, const char *path, Inode *inode);

// 目录操作
int vfs_mkdir(VFSContext *ctx, const char *path);
int vfs_rmdir(VFSContext *ctx, const char *path);
int vfs_readdir(VFSContext *ctx, const char *path, DirEntry *entries, int *count);
int vfs_lookup(VFSContext *ctx, const char *path, uint32_t *inode_id);

// 路径解析
int vfs_path_resolve(VFSContext *ctx, const char *path, uint32_t *parent_inode, char *filename);

// 工具函数
const char* vfs_strerror(int err);
void vfs_print_superblock(SuperBlock *sb);
void vfs_print_inode(Inode *inode);

/*============================================================================
 * 备份相关函数 (新增)
 *============================================================================*/

// 备份元数据结构
typedef struct {
    uint32_t backup_id;                 // 备份ID
    time_t created_at;                  // 创建时间
    char description[256];              // 描述
    uint32_t size;                      // 备份大小(字节)
    char filename[MAX_FILENAME];        // 备份文件名
} BackupMeta;

#define MAX_BACKUPS 100                 // 最大备份数

// 创建备份 - 将整个磁盘镜像复制到备份目录
int vfs_backup_create(VFSContext *ctx, const char *description, uint32_t *backup_id);

// 列出备份
int vfs_backup_list(VFSContext *ctx, BackupMeta *backups, int *count);

// 恢复备份
int vfs_backup_restore(VFSContext *ctx, uint32_t backup_id);

// 删除备份
int vfs_backup_delete(VFSContext *ctx, uint32_t backup_id);

/*============================================================================
 * 用户管理相关函数 (新增)
 *============================================================================*/

// 用户信息结构
typedef struct {
    char username[64];
    char password[64];                  // 存储哈希
    UserRole role;
    char email[128];
    time_t created_at;
    bool active;
} UserInfo;

#define MAX_USERS 256                   // 最大用户数

// 用户管理
int vfs_user_add(VFSContext *ctx, const char *username, const char *password, UserRole role);
int vfs_user_delete(VFSContext *ctx, const char *username);
int vfs_user_list(VFSContext *ctx, UserInfo *users, int *count);
int vfs_user_verify(VFSContext *ctx, const char *username, const char *password, UserRole *role);
int vfs_user_exists(VFSContext *ctx, const char *username);

/*============================================================================
 * 评审相关函数 (新增)
 *============================================================================*/

// 评审信息结构
typedef struct {
    uint32_t review_id;
    uint32_t paper_id;
    char reviewer[64];
    int32_t score;                      // 1-10
    char decision[32];                  // accept/reject/revision
    char comments[2048];
    time_t review_time;
} ReviewInfo;

// 保存评审意见
int vfs_review_save(VFSContext *ctx, uint32_t paper_id, const ReviewInfo *review);

// 获取论文的所有评审意见
int vfs_review_list(VFSContext *ctx, uint32_t paper_id, ReviewInfo *reviews, int *count);

// 分配审稿人
int vfs_assign_reviewer(VFSContext *ctx, uint32_t paper_id, const char *reviewer);

// 获取系统统计信息
void vfs_get_stats(VFSContext *ctx, uint32_t *total_blocks, uint32_t *free_blocks,
                   uint32_t *total_inodes, uint32_t *free_inodes);

#endif // VFS_H
