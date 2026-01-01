/**
 * @file vfs.c
 * @brief 虚拟文件系统核心实现
 */

#include "../include/vfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

/*============================================================================
 * 内部辅助函数
 *============================================================================*/

/**
 * 读取磁盘块(底层)
 */
static int disk_read_block(VFSContext *ctx, uint32_t block_id, void *buf) {
    if (ctx->disk_fd < 0) {
        return ERR_IO_ERROR;
    }
    
    off_t offset = (off_t)block_id * BLOCK_SIZE;
    if (lseek(ctx->disk_fd, offset, SEEK_SET) < 0) {
        LOG_E("lseek failed: %s", strerror(errno));
        return ERR_IO_ERROR;
    }
    
    ssize_t bytes = read(ctx->disk_fd, buf, BLOCK_SIZE);
    if (bytes != BLOCK_SIZE) {
        LOG_E("read failed: expected %d, got %zd", BLOCK_SIZE, bytes);
        return ERR_IO_ERROR;
    }
    
    return ERR_SUCCESS;
}

/**
 * 写入磁盘块(底层)
 */
static int disk_write_block(VFSContext *ctx, uint32_t block_id, const void *buf) {
    if (ctx->disk_fd < 0 || ctx->readonly) {
        return ERR_IO_ERROR;
    }
    
    off_t offset = (off_t)block_id * BLOCK_SIZE;
    if (lseek(ctx->disk_fd, offset, SEEK_SET) < 0) {
        LOG_E("lseek failed: %s", strerror(errno));
        return ERR_IO_ERROR;
    }
    
    ssize_t bytes = write(ctx->disk_fd, buf, BLOCK_SIZE);
    if (bytes != BLOCK_SIZE) {
        LOG_E("write failed: expected %d, got %zd", BLOCK_SIZE, bytes);
        return ERR_IO_ERROR;
    }
    
    return ERR_SUCCESS;
}

/*============================================================================
 * VFS初始化和挂载
 *============================================================================*/

/**
 * 初始化VFS上下文
 */
int vfs_init(VFSContext *ctx, const char *disk_path) {
    if (!ctx || !disk_path) {
        return ERR_INVALID_PATH;
    }
    
    memset(ctx, 0, sizeof(VFSContext));
    strncpy(ctx->disk_path, disk_path, MAX_PATH - 1);
    
    // 初始化锁
    pthread_mutex_init(&ctx->sb_lock, NULL);
    pthread_mutex_init(&ctx->inode_bitmap_lock, NULL);
    pthread_mutex_init(&ctx->data_bitmap_lock, NULL);
    
    // 分配位图和Inode表内存
    ctx->inode_bitmap = calloc(1, INODE_BITMAP_BLOCKS * BLOCK_SIZE);
    ctx->data_bitmap = calloc(1, DATA_BITMAP_BLOCKS * BLOCK_SIZE);
    ctx->inode_table = calloc(INODE_COUNT, sizeof(Inode));
    
    if (!ctx->inode_bitmap || !ctx->data_bitmap || !ctx->inode_table) {
        LOG_E("Failed to allocate memory for VFS structures");
        vfs_destroy(ctx);
        return ERR_IO_ERROR;
    }
    
    // 尝试打开现有磁盘文件
    ctx->disk_fd = open(disk_path, O_RDWR);
    if (ctx->disk_fd < 0) {
        // 创建新磁盘文件
        ctx->disk_fd = open(disk_path, O_RDWR | O_CREAT, 0644);
        if (ctx->disk_fd < 0) {
            LOG_E("Failed to create disk file: %s", strerror(errno));
            vfs_destroy(ctx);
            return ERR_IO_ERROR;
        }
        
        // 扩展到指定大小
        if (ftruncate(ctx->disk_fd, DISK_SIZE) < 0) {
            LOG_E("Failed to truncate disk file: %s", strerror(errno));
            vfs_destroy(ctx);
            return ERR_IO_ERROR;
        }
        
        LOG_I("Created new disk file: %s (%d MB)", disk_path, DISK_SIZE / (1024 * 1024));
        
        // 格式化新磁盘
        int ret = vfs_format(ctx);
        if (ret != ERR_SUCCESS) {
            vfs_destroy(ctx);
            return ret;
        }
    }
    
    LOG_I("VFS initialized: %s", disk_path);
    return ERR_SUCCESS;
}

/**
 * 格式化磁盘
 */
int vfs_format(VFSContext *ctx) {
    if (!ctx || ctx->disk_fd < 0) {
        return ERR_IO_ERROR;
    }
    
    LOG_I("Formatting disk...");
    
    // 初始化SuperBlock
    SuperBlock *sb = &ctx->sb;
    memset(sb, 0, sizeof(SuperBlock));
    
    sb->magic = SUPERBLOCK_MAGIC;
    sb->version = VFS_VERSION;
    sb->block_size = BLOCK_SIZE;
    sb->total_blocks = TOTAL_BLOCKS;
    sb->free_blocks = TOTAL_BLOCKS - DATA_BLOCK_START;
    sb->total_inodes = INODE_COUNT;
    sb->free_inodes = INODE_COUNT - 1;  // 根目录占用一个
    
    sb->inode_bitmap_start = INODE_BITMAP_BLOCK;
    sb->inode_bitmap_blocks = INODE_BITMAP_BLOCKS;
    sb->data_bitmap_start = DATA_BITMAP_BLOCK;
    sb->data_bitmap_blocks = DATA_BITMAP_BLOCKS;
    sb->inode_table_start = INODE_TABLE_BLOCK;
    sb->inode_table_blocks = INODE_TABLE_BLOCKS;
    sb->data_block_start = DATA_BLOCK_START;
    
    sb->create_time = time(NULL);
    sb->mount_time = 0;
    sb->write_time = time(NULL);
    sb->mount_count = 0;
    
    strncpy(sb->volume_name, "PaperReviewFS", sizeof(sb->volume_name) - 1);
    
    // 写入SuperBlock
    int ret = disk_write_block(ctx, SUPERBLOCK_BLOCK, sb);
    if (ret != ERR_SUCCESS) {
        return ret;
    }
    
    // 初始化位图
    memset(ctx->inode_bitmap, 0, INODE_BITMAP_BLOCKS * BLOCK_SIZE);
    memset(ctx->data_bitmap, 0, DATA_BITMAP_BLOCKS * BLOCK_SIZE);
    
    // 标记根目录Inode为已使用
    BITMAP_SET(ctx->inode_bitmap, ROOT_INODE);
    
    // 写入位图
    for (int i = 0; i < INODE_BITMAP_BLOCKS; i++) {
        ret = disk_write_block(ctx, INODE_BITMAP_BLOCK + i, 
                               ctx->inode_bitmap + i * BLOCK_SIZE);
        if (ret != ERR_SUCCESS) return ret;
    }
    
    for (int i = 0; i < DATA_BITMAP_BLOCKS; i++) {
        ret = disk_write_block(ctx, DATA_BITMAP_BLOCK + i,
                               ctx->data_bitmap + i * BLOCK_SIZE);
        if (ret != ERR_SUCCESS) return ret;
    }
    
    // 初始化根目录Inode
    Inode *root = &ctx->inode_table[ROOT_INODE];
    memset(root, 0, sizeof(Inode));
    
    root->inode_id = ROOT_INODE;
    root->mode = 0755;
    root->link_count = 2;  // . 和 ..
    root->file_type = FILE_TYPE_DIRECTORY;
    root->ctime = root->mtime = root->atime = time(NULL);
    pthread_mutex_init(&root->lock, NULL);
    
    // 写入Inode表
    uint8_t block_buf[BLOCK_SIZE];
    for (uint32_t i = 0; i < INODE_TABLE_BLOCKS; i++) {
        memset(block_buf, 0, BLOCK_SIZE);
        int inodes_in_block = MIN(INODES_PER_BLOCK, INODE_COUNT - i * INODES_PER_BLOCK);
        
        for (int j = 0; j < inodes_in_block; j++) {
            uint32_t inode_idx = i * INODES_PER_BLOCK + j;
            if (inode_idx < INODE_COUNT) {
                memcpy(block_buf + j * sizeof(Inode), 
                       &ctx->inode_table[inode_idx], sizeof(Inode));
            }
        }
        
        ret = disk_write_block(ctx, INODE_TABLE_BLOCK + i, block_buf);
        if (ret != ERR_SUCCESS) return ret;
    }
    
    // 同步到磁盘
    fsync(ctx->disk_fd);
    
    LOG_I("Disk formatted successfully");
    LOG_I("  Total blocks: %u", sb->total_blocks);
    LOG_I("  Free blocks: %u", sb->free_blocks);
    LOG_I("  Total inodes: %u", sb->total_inodes);
    LOG_I("  Free inodes: %u", sb->free_inodes);
    
    return ERR_SUCCESS;
}

/**
 * 挂载文件系统
 */
int vfs_mount(VFSContext *ctx) {
    if (!ctx || ctx->disk_fd < 0) {
        return ERR_IO_ERROR;
    }
    
    if (ctx->mounted) {
        LOG_W("VFS already mounted");
        return ERR_SUCCESS;
    }
    
    // 读取SuperBlock
    int ret = disk_read_block(ctx, SUPERBLOCK_BLOCK, &ctx->sb);
    if (ret != ERR_SUCCESS) {
        return ret;
    }
    
    // 验证魔数
    if (ctx->sb.magic != SUPERBLOCK_MAGIC) {
        LOG_E("Invalid superblock magic: 0x%X", ctx->sb.magic);
        return ERR_IO_ERROR;
    }
    
    // 读取位图
    for (int i = 0; i < INODE_BITMAP_BLOCKS; i++) {
        ret = disk_read_block(ctx, INODE_BITMAP_BLOCK + i,
                              ctx->inode_bitmap + i * BLOCK_SIZE);
        if (ret != ERR_SUCCESS) return ret;
    }
    
    for (int i = 0; i < DATA_BITMAP_BLOCKS; i++) {
        ret = disk_read_block(ctx, DATA_BITMAP_BLOCK + i,
                              ctx->data_bitmap + i * BLOCK_SIZE);
        if (ret != ERR_SUCCESS) return ret;
    }
    
    // 读取Inode表
    uint8_t block_buf[BLOCK_SIZE];
    for (uint32_t i = 0; i < INODE_TABLE_BLOCKS; i++) {
        ret = disk_read_block(ctx, INODE_TABLE_BLOCK + i, block_buf);
        if (ret != ERR_SUCCESS) return ret;
        
        int inodes_in_block = MIN(INODES_PER_BLOCK, INODE_COUNT - i * INODES_PER_BLOCK);
        for (int j = 0; j < inodes_in_block; j++) {
            uint32_t inode_idx = i * INODES_PER_BLOCK + j;
            if (inode_idx < INODE_COUNT) {
                memcpy(&ctx->inode_table[inode_idx],
                       block_buf + j * sizeof(Inode), sizeof(Inode));
                pthread_mutex_init(&ctx->inode_table[inode_idx].lock, NULL);
            }
        }
    }
    
    // 更新挂载信息
    ctx->sb.mount_time = time(NULL);
    ctx->sb.mount_count++;
    disk_write_block(ctx, SUPERBLOCK_BLOCK, &ctx->sb);
    
    ctx->mounted = true;
    
    LOG_I("VFS mounted: %s", ctx->sb.volume_name);
    vfs_print_superblock(&ctx->sb);
    
    return ERR_SUCCESS;
}

/**
 * 卸载文件系统
 */
int vfs_unmount(VFSContext *ctx) {
    if (!ctx || !ctx->mounted) {
        return ERR_SUCCESS;
    }
    
    // 同步SuperBlock
    ctx->sb.write_time = time(NULL);
    disk_write_block(ctx, SUPERBLOCK_BLOCK, &ctx->sb);
    
    // 同步位图
    for (int i = 0; i < INODE_BITMAP_BLOCKS; i++) {
        disk_write_block(ctx, INODE_BITMAP_BLOCK + i,
                         ctx->inode_bitmap + i * BLOCK_SIZE);
    }
    
    for (int i = 0; i < DATA_BITMAP_BLOCKS; i++) {
        disk_write_block(ctx, DATA_BITMAP_BLOCK + i,
                         ctx->data_bitmap + i * BLOCK_SIZE);
    }
    
    // 同步Inode表
    uint8_t block_buf[BLOCK_SIZE];
    for (uint32_t i = 0; i < INODE_TABLE_BLOCKS; i++) {
        memset(block_buf, 0, BLOCK_SIZE);
        int inodes_in_block = MIN(INODES_PER_BLOCK, INODE_COUNT - i * INODES_PER_BLOCK);
        
        for (int j = 0; j < inodes_in_block; j++) {
            uint32_t inode_idx = i * INODES_PER_BLOCK + j;
            if (inode_idx < INODE_COUNT) {
                memcpy(block_buf + j * sizeof(Inode),
                       &ctx->inode_table[inode_idx], sizeof(Inode));
            }
        }
        
        disk_write_block(ctx, INODE_TABLE_BLOCK + i, block_buf);
    }
    
    fsync(ctx->disk_fd);
    ctx->mounted = false;
    
    LOG_I("VFS unmounted");
    return ERR_SUCCESS;
}

/**
 * 销毁VFS上下文
 */
void vfs_destroy(VFSContext *ctx) {
    if (!ctx) return;
    
    if (ctx->mounted) {
        vfs_unmount(ctx);
    }
    
    if (ctx->disk_fd >= 0) {
        close(ctx->disk_fd);
        ctx->disk_fd = -1;
    }
    
    if (ctx->inode_bitmap) {
        free(ctx->inode_bitmap);
        ctx->inode_bitmap = NULL;
    }
    
    if (ctx->data_bitmap) {
        free(ctx->data_bitmap);
        ctx->data_bitmap = NULL;
    }
    
    if (ctx->inode_table) {
        // 销毁Inode锁
        for (int i = 0; i < INODE_COUNT; i++) {
            pthread_mutex_destroy(&ctx->inode_table[i].lock);
        }
        free(ctx->inode_table);
        ctx->inode_table = NULL;
    }
    
    pthread_mutex_destroy(&ctx->sb_lock);
    pthread_mutex_destroy(&ctx->inode_bitmap_lock);
    pthread_mutex_destroy(&ctx->data_bitmap_lock);
    
    LOG_I("VFS destroyed");
}

/*============================================================================
 * Inode操作
 *============================================================================*/

/**
 * 分配新Inode
 */
int vfs_alloc_inode(VFSContext *ctx, FileType type) {
    if (!ctx || !ctx->mounted) {
        return ERR_IO_ERROR;
    }
    
    pthread_mutex_lock(&ctx->inode_bitmap_lock);
    
    // 查找空闲Inode
    int inode_id = -1;
    for (uint32_t i = 0; i < INODE_COUNT; i++) {
        if (!BITMAP_GET(ctx->inode_bitmap, i)) {
            inode_id = i;
            BITMAP_SET(ctx->inode_bitmap, i);
            break;
        }
    }
    
    pthread_mutex_unlock(&ctx->inode_bitmap_lock);
    
    if (inode_id < 0) {
        LOG_E("No free inode available");
        return ERR_NO_INODE;
    }
    
    // 初始化Inode
    Inode *inode = &ctx->inode_table[inode_id];
    pthread_mutex_lock(&inode->lock);
    
    memset(inode, 0, sizeof(Inode));
    inode->inode_id = inode_id;
    inode->mode = (type == FILE_TYPE_DIRECTORY) ? 0755 : 0644;
    inode->link_count = 1;
    inode->file_type = type;
    inode->ctime = inode->mtime = inode->atime = time(NULL);
    pthread_mutex_init(&inode->lock, NULL);
    
    pthread_mutex_unlock(&inode->lock);
    
    // 更新SuperBlock
    pthread_mutex_lock(&ctx->sb_lock);
    ctx->sb.free_inodes--;
    pthread_mutex_unlock(&ctx->sb_lock);
    
    LOG_D("Allocated inode %d, type=%d", inode_id, type);
    return inode_id;
}

/**
 * 释放Inode
 */
int vfs_free_inode(VFSContext *ctx, uint32_t inode_id) {
    if (!ctx || !ctx->mounted || inode_id >= INODE_COUNT) {
        return ERR_INVALID_INODE;
    }
    
    if (inode_id == ROOT_INODE) {
        LOG_E("Cannot free root inode");
        return ERR_PERMISSION;
    }
    
    Inode *inode = &ctx->inode_table[inode_id];
    pthread_mutex_lock(&inode->lock);
    
    // 释放所有数据块
    for (int i = 0; i < MAX_DIRECT_BLOCKS; i++) {
        if (inode->direct_blocks[i] != 0) {
            vfs_free_block(ctx, inode->direct_blocks[i]);
            inode->direct_blocks[i] = 0;
        }
    }
    
    // TODO: 释放间接块
    
    memset(inode, 0, sizeof(Inode));
    pthread_mutex_unlock(&inode->lock);
    
    // 更新位图
    pthread_mutex_lock(&ctx->inode_bitmap_lock);
    BITMAP_CLEAR(ctx->inode_bitmap, inode_id);
    pthread_mutex_unlock(&ctx->inode_bitmap_lock);
    
    // 更新SuperBlock
    pthread_mutex_lock(&ctx->sb_lock);
    ctx->sb.free_inodes++;
    pthread_mutex_unlock(&ctx->sb_lock);
    
    LOG_D("Freed inode %u", inode_id);
    return ERR_SUCCESS;
}

/**
 * 获取Inode指针
 */
Inode* vfs_get_inode(VFSContext *ctx, uint32_t inode_id) {
    if (!ctx || !ctx->mounted || inode_id >= INODE_COUNT) {
        return NULL;
    }
    
    if (!BITMAP_GET(ctx->inode_bitmap, inode_id)) {
        return NULL;  // Inode未分配
    }
    
    return &ctx->inode_table[inode_id];
}

/**
 * 写入Inode到磁盘
 */
int vfs_write_inode(VFSContext *ctx, Inode *inode) {
    if (!ctx || !ctx->mounted || !inode) {
        return ERR_INVALID_INODE;
    }
    
    uint32_t block_idx = inode->inode_id / INODES_PER_BLOCK;
    uint32_t offset_in_block = inode->inode_id % INODES_PER_BLOCK;
    
    uint8_t block_buf[BLOCK_SIZE];
    int ret = disk_read_block(ctx, INODE_TABLE_BLOCK + block_idx, block_buf);
    if (ret != ERR_SUCCESS) return ret;
    
    memcpy(block_buf + offset_in_block * sizeof(Inode), inode, sizeof(Inode));
    
    ret = disk_write_block(ctx, INODE_TABLE_BLOCK + block_idx, block_buf);
    return ret;
}

/*============================================================================
 * 数据块操作
 *============================================================================*/

/**
 * 分配数据块
 */
int vfs_alloc_block(VFSContext *ctx) {
    if (!ctx || !ctx->mounted) {
        return ERR_IO_ERROR;
    }
    
    pthread_mutex_lock(&ctx->data_bitmap_lock);
    
    uint32_t total_data_blocks = TOTAL_BLOCKS - DATA_BLOCK_START;
    int block_id = -1;
    
    for (uint32_t i = 0; i < total_data_blocks; i++) {
        if (!BITMAP_GET(ctx->data_bitmap, i)) {
            block_id = DATA_BLOCK_START + i;
            BITMAP_SET(ctx->data_bitmap, i);
            break;
        }
    }
    
    pthread_mutex_unlock(&ctx->data_bitmap_lock);
    
    if (block_id < 0) {
        LOG_E("No free block available");
        return ERR_DISK_FULL;
    }
    
    // 更新SuperBlock
    pthread_mutex_lock(&ctx->sb_lock);
    ctx->sb.free_blocks--;
    pthread_mutex_unlock(&ctx->sb_lock);
    
    // 清零新块
    uint8_t zero_buf[BLOCK_SIZE] = {0};
    disk_write_block(ctx, block_id, zero_buf);
    
    LOG_D("Allocated block %d", block_id);
    return block_id;
}

/**
 * 释放数据块
 */
int vfs_free_block(VFSContext *ctx, uint32_t block_id) {
    if (!ctx || !ctx->mounted) {
        return ERR_IO_ERROR;
    }
    
    if (block_id < DATA_BLOCK_START || block_id >= TOTAL_BLOCKS) {
        LOG_E("Invalid block id: %u", block_id);
        return ERR_IO_ERROR;
    }
    
    uint32_t bitmap_idx = block_id - DATA_BLOCK_START;
    
    pthread_mutex_lock(&ctx->data_bitmap_lock);
    BITMAP_CLEAR(ctx->data_bitmap, bitmap_idx);
    pthread_mutex_unlock(&ctx->data_bitmap_lock);
    
    // 更新SuperBlock
    pthread_mutex_lock(&ctx->sb_lock);
    ctx->sb.free_blocks++;
    pthread_mutex_unlock(&ctx->sb_lock);
    
    LOG_D("Freed block %u", block_id);
    return ERR_SUCCESS;
}

/**
 * 读取数据块
 */
int vfs_read_block(VFSContext *ctx, uint32_t block_id, void *buf) {
    return disk_read_block(ctx, block_id, buf);
}

/**
 * 写入数据块
 */
int vfs_write_block(VFSContext *ctx, uint32_t block_id, const void *buf) {
    return disk_write_block(ctx, block_id, buf);
}

/*============================================================================
 * 文件操作
 *============================================================================*/

/**
 * 创建文件或目录
 */
int vfs_create(VFSContext *ctx, const char *path, FileType type) {
    if (!ctx || !ctx->mounted || !path) {
        return ERR_INVALID_PATH;
    }
    
    uint32_t parent_inode_id;
    char filename[MAX_FILENAME];
    
    int ret = vfs_path_resolve(ctx, path, &parent_inode_id, filename);
    if (ret != ERR_SUCCESS) {
        return ret;
    }
    
    Inode *parent = vfs_get_inode(ctx, parent_inode_id);
    if (!parent || parent->file_type != FILE_TYPE_DIRECTORY) {
        return ERR_NOT_DIRECTORY;
    }
    
    // 检查是否已存在
    uint32_t existing_inode;
    if (vfs_lookup(ctx, path, &existing_inode) == ERR_SUCCESS) {
        return ERR_FILE_EXISTS;
    }
    
    // 分配新Inode
    int new_inode_id = vfs_alloc_inode(ctx, type);
    if (new_inode_id < 0) {
        return new_inode_id;
    }
    
    // 添加目录项到父目录
    pthread_mutex_lock(&parent->lock);
    
    // 查找空闲目录项位置
    bool added = false;
    for (int i = 0; i < MAX_DIRECT_BLOCKS && !added; i++) {
        uint32_t block_id = parent->direct_blocks[i];
        
        if (block_id == 0) {
            // 分配新块
            block_id = vfs_alloc_block(ctx);
            if (block_id < 0) {
                pthread_mutex_unlock(&parent->lock);
                vfs_free_inode(ctx, new_inode_id);
                return ERR_DISK_FULL;
            }
            parent->direct_blocks[i] = block_id;
            parent->blocks++;
        }
        
        DirEntry entries[MAX_DIR_ENTRIES];
        vfs_read_block(ctx, block_id, entries);
        
        for (int j = 0; j < MAX_DIR_ENTRIES; j++) {
            if (entries[j].inode_id == 0) {
                entries[j].inode_id = new_inode_id;
                entries[j].file_type = type;
                entries[j].name_len = strlen(filename);
                strncpy(entries[j].name, filename, DIR_ENTRY_NAME_LEN - 1);
                
                vfs_write_block(ctx, block_id, entries);
                added = true;
                break;
            }
        }
    }
    
    parent->mtime = time(NULL);
    if (type == FILE_TYPE_DIRECTORY) {
        parent->link_count++;
    }
    
    pthread_mutex_unlock(&parent->lock);
    
    if (!added) {
        vfs_free_inode(ctx, new_inode_id);
        return ERR_DISK_FULL;
    }
    
    LOG_I("Created %s: %s (inode %d)", 
          type == FILE_TYPE_DIRECTORY ? "directory" : "file",
          path, new_inode_id);
    
    return new_inode_id;
}

/**
 * 删除文件
 */
int vfs_delete(VFSContext *ctx, const char *path) {
    if (!ctx || !ctx->mounted || !path) {
        return ERR_INVALID_PATH;
    }
    
    uint32_t inode_id;
    int ret = vfs_lookup(ctx, path, &inode_id);
    if (ret != ERR_SUCCESS) {
        return ERR_FILE_NOT_FOUND;
    }
    
    Inode *inode = vfs_get_inode(ctx, inode_id);
    if (!inode) {
        return ERR_FILE_NOT_FOUND;
    }
    
    if (inode->file_type == FILE_TYPE_DIRECTORY) {
        return ERR_IS_DIRECTORY;
    }
    
    // 从父目录中移除
    uint32_t parent_inode_id;
    char filename[MAX_FILENAME];
    ret = vfs_path_resolve(ctx, path, &parent_inode_id, filename);
    if (ret != ERR_SUCCESS) {
        return ret;
    }
    
    Inode *parent = vfs_get_inode(ctx, parent_inode_id);
    pthread_mutex_lock(&parent->lock);
    
    bool removed = false;
    for (int i = 0; i < MAX_DIRECT_BLOCKS && !removed; i++) {
        uint32_t block_id = parent->direct_blocks[i];
        if (block_id == 0) continue;
        
        DirEntry entries[MAX_DIR_ENTRIES];
        vfs_read_block(ctx, block_id, entries);
        
        for (int j = 0; j < MAX_DIR_ENTRIES; j++) {
            if (entries[j].inode_id == inode_id) {
                memset(&entries[j], 0, sizeof(DirEntry));
                vfs_write_block(ctx, block_id, entries);
                removed = true;
                break;
            }
        }
    }
    
    parent->mtime = time(NULL);
    pthread_mutex_unlock(&parent->lock);
    
    // 释放Inode
    ret = vfs_free_inode(ctx, inode_id);
    
    LOG_I("Deleted file: %s", path);
    return ret;
}

/**
 * 读取文件内容
 */
int vfs_read(VFSContext *ctx, const char *path, void *buf, uint32_t size, uint32_t offset) {
    if (!ctx || !ctx->mounted || !path || !buf) {
        return ERR_INVALID_PATH;
    }
    
    uint32_t inode_id;
    int ret = vfs_lookup(ctx, path, &inode_id);
    if (ret != ERR_SUCCESS) {
        return ERR_FILE_NOT_FOUND;
    }
    
    Inode *inode = vfs_get_inode(ctx, inode_id);
    if (!inode || inode->file_type != FILE_TYPE_REGULAR) {
        return ERR_FILE_NOT_FOUND;
    }
    
    pthread_mutex_lock(&inode->lock);
    
    if (offset >= inode->size) {
        pthread_mutex_unlock(&inode->lock);
        return 0;  // EOF
    }
    
    uint32_t bytes_to_read = MIN(size, inode->size - offset);
    uint32_t bytes_read = 0;
    uint8_t block_buf[BLOCK_SIZE];
    
    while (bytes_read < bytes_to_read) {
        uint32_t block_idx = (offset + bytes_read) / BLOCK_SIZE;
        uint32_t block_offset = (offset + bytes_read) % BLOCK_SIZE;
        
        if (block_idx >= MAX_DIRECT_BLOCKS) {
            // TODO: 处理间接块
            break;
        }
        
        uint32_t block_id = inode->direct_blocks[block_idx];
        if (block_id == 0) {
            break;
        }
        
        ret = vfs_read_block(ctx, block_id, block_buf);
        if (ret != ERR_SUCCESS) {
            pthread_mutex_unlock(&inode->lock);
            return ret;
        }
        
        uint32_t copy_size = MIN(BLOCK_SIZE - block_offset, bytes_to_read - bytes_read);
        memcpy((uint8_t*)buf + bytes_read, block_buf + block_offset, copy_size);
        bytes_read += copy_size;
    }
    
    inode->atime = time(NULL);
    pthread_mutex_unlock(&inode->lock);
    
    return bytes_read;
}

/**
 * 写入文件内容
 */
int vfs_write(VFSContext *ctx, const char *path, const void *buf, uint32_t size, uint32_t offset) {
    if (!ctx || !ctx->mounted || !path || !buf) {
        return ERR_INVALID_PATH;
    }
    
    uint32_t inode_id;
    int ret = vfs_lookup(ctx, path, &inode_id);
    if (ret != ERR_SUCCESS) {
        // 创建新文件
        inode_id = vfs_create(ctx, path, FILE_TYPE_REGULAR);
        if (inode_id < 0) {
            return inode_id;
        }
    }
    
    Inode *inode = vfs_get_inode(ctx, inode_id);
    if (!inode || inode->file_type != FILE_TYPE_REGULAR) {
        return ERR_IS_DIRECTORY;
    }
    
    pthread_mutex_lock(&inode->lock);
    
    uint32_t bytes_written = 0;
    uint8_t block_buf[BLOCK_SIZE];
    
    while (bytes_written < size) {
        uint32_t block_idx = (offset + bytes_written) / BLOCK_SIZE;
        uint32_t block_offset = (offset + bytes_written) % BLOCK_SIZE;
        
        if (block_idx >= MAX_DIRECT_BLOCKS) {
            // TODO: 处理间接块
            LOG_W("File too large, indirect blocks not implemented");
            break;
        }
        
        uint32_t block_id = inode->direct_blocks[block_idx];
        if (block_id == 0) {
            // 分配新块
            block_id = vfs_alloc_block(ctx);
            if (block_id < 0) {
                pthread_mutex_unlock(&inode->lock);
                return ERR_DISK_FULL;
            }
            inode->direct_blocks[block_idx] = block_id;
            inode->blocks++;
            memset(block_buf, 0, BLOCK_SIZE);
        } else {
            vfs_read_block(ctx, block_id, block_buf);
        }
        
        uint32_t copy_size = MIN(BLOCK_SIZE - block_offset, size - bytes_written);
        memcpy(block_buf + block_offset, (const uint8_t*)buf + bytes_written, copy_size);
        
        ret = vfs_write_block(ctx, block_id, block_buf);
        if (ret != ERR_SUCCESS) {
            pthread_mutex_unlock(&inode->lock);
            return ret;
        }
        
        bytes_written += copy_size;
    }
    
    // 更新文件大小
    if (offset + bytes_written > inode->size) {
        inode->size = offset + bytes_written;
    }
    
    inode->mtime = time(NULL);
    pthread_mutex_unlock(&inode->lock);
    
    return bytes_written;
}

/**
 * 获取文件信息
 */
int vfs_stat(VFSContext *ctx, const char *path, Inode *inode_out) {
    if (!ctx || !ctx->mounted || !path || !inode_out) {
        return ERR_INVALID_PATH;
    }
    
    uint32_t inode_id;
    int ret = vfs_lookup(ctx, path, &inode_id);
    if (ret != ERR_SUCCESS) {
        return ERR_FILE_NOT_FOUND;
    }
    
    Inode *inode = vfs_get_inode(ctx, inode_id);
    if (!inode) {
        return ERR_FILE_NOT_FOUND;
    }
    
    memcpy(inode_out, inode, sizeof(Inode));
    return ERR_SUCCESS;
}

/*============================================================================
 * 目录操作
 *============================================================================*/

/**
 * 创建目录
 */
int vfs_mkdir(VFSContext *ctx, const char *path) {
    return vfs_create(ctx, path, FILE_TYPE_DIRECTORY);
}

/**
 * 删除目录
 */
int vfs_rmdir(VFSContext *ctx, const char *path) {
    if (!ctx || !ctx->mounted || !path) {
        return ERR_INVALID_PATH;
    }
    
    uint32_t inode_id;
    int ret = vfs_lookup(ctx, path, &inode_id);
    if (ret != ERR_SUCCESS) {
        return ERR_FILE_NOT_FOUND;
    }
    
    if (inode_id == ROOT_INODE) {
        return ERR_PERMISSION;
    }
    
    Inode *inode = vfs_get_inode(ctx, inode_id);
    if (!inode || inode->file_type != FILE_TYPE_DIRECTORY) {
        return ERR_NOT_DIRECTORY;
    }
    
    // 检查目录是否为空
    DirEntry entries[MAX_DIR_ENTRIES];
    for (int i = 0; i < MAX_DIRECT_BLOCKS; i++) {
        uint32_t block_id = inode->direct_blocks[i];
        if (block_id == 0) continue;
        
        vfs_read_block(ctx, block_id, entries);
        for (int j = 0; j < MAX_DIR_ENTRIES; j++) {
            if (entries[j].inode_id != 0) {
                return ERR_DIR_NOT_EMPTY;
            }
        }
    }
    
    // 从父目录移除并释放
    uint32_t parent_inode_id;
    char filename[MAX_FILENAME];
    ret = vfs_path_resolve(ctx, path, &parent_inode_id, filename);
    if (ret != ERR_SUCCESS) {
        return ret;
    }
    
    Inode *parent = vfs_get_inode(ctx, parent_inode_id);
    pthread_mutex_lock(&parent->lock);
    
    for (int i = 0; i < MAX_DIRECT_BLOCKS; i++) {
        uint32_t block_id = parent->direct_blocks[i];
        if (block_id == 0) continue;
        
        vfs_read_block(ctx, block_id, entries);
        for (int j = 0; j < MAX_DIR_ENTRIES; j++) {
            if (entries[j].inode_id == inode_id) {
                memset(&entries[j], 0, sizeof(DirEntry));
                vfs_write_block(ctx, block_id, entries);
                parent->link_count--;
                break;
            }
        }
    }
    
    parent->mtime = time(NULL);
    pthread_mutex_unlock(&parent->lock);
    
    vfs_free_inode(ctx, inode_id);
    
    LOG_I("Removed directory: %s", path);
    return ERR_SUCCESS;
}

/**
 * 读取目录内容
 */
int vfs_readdir(VFSContext *ctx, const char *path, DirEntry *entries_out, int *count) {
    if (!ctx || !ctx->mounted || !path || !entries_out || !count) {
        return ERR_INVALID_PATH;
    }
    
    uint32_t inode_id;
    int ret = vfs_lookup(ctx, path, &inode_id);
    if (ret != ERR_SUCCESS) {
        return ERR_FILE_NOT_FOUND;
    }
    
    Inode *inode = vfs_get_inode(ctx, inode_id);
    if (!inode || inode->file_type != FILE_TYPE_DIRECTORY) {
        return ERR_NOT_DIRECTORY;
    }
    
    pthread_mutex_lock(&inode->lock);
    
    int entry_count = 0;
    int max_entries = *count;
    DirEntry block_entries[MAX_DIR_ENTRIES];
    
    for (int i = 0; i < MAX_DIRECT_BLOCKS && entry_count < max_entries; i++) {
        uint32_t block_id = inode->direct_blocks[i];
        if (block_id == 0) continue;
        
        vfs_read_block(ctx, block_id, block_entries);
        
        for (int j = 0; j < MAX_DIR_ENTRIES && entry_count < max_entries; j++) {
            if (block_entries[j].inode_id != 0) {
                memcpy(&entries_out[entry_count], &block_entries[j], sizeof(DirEntry));
                entry_count++;
            }
        }
    }
    
    *count = entry_count;
    inode->atime = time(NULL);
    
    pthread_mutex_unlock(&inode->lock);
    
    return ERR_SUCCESS;
}

/**
 * 查找路径对应的Inode
 */
int vfs_lookup(VFSContext *ctx, const char *path, uint32_t *inode_id) {
    if (!ctx || !ctx->mounted || !path || !inode_id) {
        return ERR_INVALID_PATH;
    }
    
    // 根目录
    if (strcmp(path, "/") == 0) {
        *inode_id = ROOT_INODE;
        return ERR_SUCCESS;
    }
    
    // 从根目录开始遍历
    uint32_t current_inode = ROOT_INODE;
    char path_copy[MAX_PATH];
    strncpy(path_copy, path, MAX_PATH - 1);
    
    char *token = strtok(path_copy, "/");
    while (token != NULL) {
        Inode *inode = vfs_get_inode(ctx, current_inode);
        if (!inode || inode->file_type != FILE_TYPE_DIRECTORY) {
            return ERR_NOT_DIRECTORY;
        }
        
        bool found = false;
        DirEntry entries[MAX_DIR_ENTRIES];
        
        for (int i = 0; i < MAX_DIRECT_BLOCKS && !found; i++) {
            uint32_t block_id = inode->direct_blocks[i];
            if (block_id == 0) continue;
            
            vfs_read_block(ctx, block_id, entries);
            
            for (int j = 0; j < MAX_DIR_ENTRIES; j++) {
                if (entries[j].inode_id != 0 && 
                    strcmp(entries[j].name, token) == 0) {
                    current_inode = entries[j].inode_id;
                    found = true;
                    break;
                }
            }
        }
        
        if (!found) {
            return ERR_FILE_NOT_FOUND;
        }
        
        token = strtok(NULL, "/");
    }
    
    *inode_id = current_inode;
    return ERR_SUCCESS;
}

/**
 * 解析路径，获取父目录和文件名
 */
int vfs_path_resolve(VFSContext *ctx, const char *path, uint32_t *parent_inode, char *filename) {
    if (!ctx || !path || !parent_inode || !filename) {
        return ERR_INVALID_PATH;
    }
    
    if (strlen(path) == 0 || path[0] != '/') {
        return ERR_INVALID_PATH;
    }
    
    // 查找最后一个斜杠
    const char *last_slash = strrchr(path, '/');
    if (last_slash == path) {
        // 根目录下的文件
        *parent_inode = ROOT_INODE;
        strncpy(filename, path + 1, MAX_FILENAME - 1);
    } else {
        // 提取父目录路径
        char parent_path[MAX_PATH];
        size_t parent_len = last_slash - path;
        strncpy(parent_path, path, parent_len);
        parent_path[parent_len] = '\0';
        
        int ret = vfs_lookup(ctx, parent_path, parent_inode);
        if (ret != ERR_SUCCESS) {
            return ret;
        }
        
        strncpy(filename, last_slash + 1, MAX_FILENAME - 1);
    }
    
    filename[MAX_FILENAME - 1] = '\0';
    return ERR_SUCCESS;
}

/*============================================================================
 * 工具函数
 *============================================================================*/

/**
 * 错误码转字符串
 */
const char* vfs_strerror(int err) {
    switch (err) {
        case ERR_SUCCESS:        return "Success";
        case ERR_DISK_FULL:      return "Disk full";
        case ERR_FILE_NOT_FOUND: return "File not found";
        case ERR_FILE_EXISTS:    return "File exists";
        case ERR_PERMISSION:     return "Permission denied";
        case ERR_INVALID_PATH:   return "Invalid path";
        case ERR_IO_ERROR:       return "I/O error";
        case ERR_NO_INODE:       return "No free inode";
        case ERR_INVALID_INODE:  return "Invalid inode";
        case ERR_DIR_NOT_EMPTY:  return "Directory not empty";
        case ERR_NOT_DIRECTORY:  return "Not a directory";
        case ERR_IS_DIRECTORY:   return "Is a directory";
        default:                 return "Unknown error";
    }
}

/**
 * 打印SuperBlock信息
 */
void vfs_print_superblock(SuperBlock *sb) {
    printf("=== SuperBlock ===\n");
    printf("  Magic:        0x%08X\n", sb->magic);
    printf("  Version:      %u\n", sb->version);
    printf("  Block size:   %u bytes\n", sb->block_size);
    printf("  Total blocks: %u\n", sb->total_blocks);
    printf("  Free blocks:  %u\n", sb->free_blocks);
    printf("  Total inodes: %u\n", sb->total_inodes);
    printf("  Free inodes:  %u\n", sb->free_inodes);
    printf("  Volume name:  %s\n", sb->volume_name);
    printf("==================\n");
}

/**
 * 打印Inode信息
 */
void vfs_print_inode(Inode *inode) {
    const char *type_str[] = {"Regular", "Directory", "Symlink"};
    
    printf("=== Inode %u ===\n", inode->inode_id);
    printf("  Type:       %s\n", type_str[inode->file_type]);
    printf("  Mode:       %04o\n", inode->mode);
    printf("  Size:       %u bytes\n", inode->size);
    printf("  Blocks:     %u\n", inode->blocks);
    printf("  Links:      %u\n", inode->link_count);
    printf("================\n");
}
