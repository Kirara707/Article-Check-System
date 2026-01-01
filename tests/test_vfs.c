/**
 * @file test_vfs.c
 * @brief VFS单元测试
 */

#include "../include/vfs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define TEST_DISK   "./test_disk.img"
#define PASSED      "\033[32mPASSED\033[0m"
#define FAILED      "\033[31mFAILED\033[0m"

static int tests_run = 0;
static int tests_passed = 0;

#define RUN_TEST(test) do { \
    printf("  %-40s ", #test); \
    fflush(stdout); \
    tests_run++; \
    if (test()) { \
        printf("%s\n", PASSED); \
        tests_passed++; \
    } else { \
        printf("%s\n", FAILED); \
    } \
} while(0)

/*============================================================================
 * 测试用例
 *============================================================================*/

// 测试VFS初始化
int test_vfs_init(void) {
    VFSContext ctx;
    
    // 删除旧的测试磁盘
    unlink(TEST_DISK);
    
    int ret = vfs_init(&ctx, TEST_DISK);
    if (ret != ERR_SUCCESS) return 0;
    
    // 检查磁盘文件是否存在
    if (access(TEST_DISK, F_OK) != 0) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试格式化
int test_vfs_format(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    
    int ret = vfs_format(&ctx);
    if (ret != ERR_SUCCESS) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    // 验证SuperBlock
    if (ctx.sb.magic != SUPERBLOCK_MAGIC) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    if (ctx.sb.total_blocks != TOTAL_BLOCKS) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试挂载
int test_vfs_mount(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    
    int ret = vfs_mount(&ctx);
    if (ret != ERR_SUCCESS) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    if (!ctx.mounted) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    vfs_unmount(&ctx);
    vfs_destroy(&ctx);
    return 1;
}

// 测试Inode分配
int test_inode_alloc(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    vfs_mount(&ctx);
    
    int inode1 = vfs_alloc_inode(&ctx, FILE_TYPE_REGULAR);
    int inode2 = vfs_alloc_inode(&ctx, FILE_TYPE_DIRECTORY);
    
    if (inode1 < 0 || inode2 < 0) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    if (inode1 == inode2) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    // 释放Inode
    vfs_free_inode(&ctx, inode1);
    vfs_free_inode(&ctx, inode2);
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试块分配
int test_block_alloc(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    vfs_mount(&ctx);
    
    uint32_t free_before = ctx.sb.free_blocks;
    
    int block1 = vfs_alloc_block(&ctx);
    int block2 = vfs_alloc_block(&ctx);
    
    if (block1 < 0 || block2 < 0) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    if (ctx.sb.free_blocks != free_before - 2) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    // 释放块
    vfs_free_block(&ctx, block1);
    vfs_free_block(&ctx, block2);
    
    if (ctx.sb.free_blocks != free_before) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试目录创建
int test_mkdir(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    vfs_format(&ctx);
    vfs_mount(&ctx);
    
    int ret = vfs_mkdir(&ctx, "/testdir");
    if (ret < 0) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    // 验证目录存在
    uint32_t inode_id;
    ret = vfs_lookup(&ctx, "/testdir", &inode_id);
    if (ret != ERR_SUCCESS) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    Inode *inode = vfs_get_inode(&ctx, inode_id);
    if (!inode || inode->file_type != FILE_TYPE_DIRECTORY) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试文件创建和写入
int test_file_write(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    vfs_format(&ctx);
    vfs_mount(&ctx);
    
    const char *test_data = "Hello, Paper Review File System!";
    int len = strlen(test_data);
    
    int ret = vfs_write(&ctx, "/testfile.txt", test_data, len, 0);
    if (ret != len) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    // 验证文件存在
    Inode inode;
    ret = vfs_stat(&ctx, "/testfile.txt", &inode);
    if (ret != ERR_SUCCESS) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    if (inode.size != len) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试文件读取
int test_file_read(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    vfs_mount(&ctx);
    
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    
    int ret = vfs_read(&ctx, "/testfile.txt", buffer, sizeof(buffer), 0);
    if (ret < 0) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    if (strstr(buffer, "Hello") == NULL) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试文件删除
int test_file_delete(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    vfs_mount(&ctx);
    
    int ret = vfs_delete(&ctx, "/testfile.txt");
    if (ret != ERR_SUCCESS) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    // 验证文件不存在
    uint32_t inode_id;
    ret = vfs_lookup(&ctx, "/testfile.txt", &inode_id);
    if (ret == ERR_SUCCESS) {
        vfs_destroy(&ctx);
        return 0;  // 应该找不到
    }
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试目录列表
int test_readdir(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    vfs_format(&ctx);
    vfs_mount(&ctx);
    
    // 创建几个目录和文件
    vfs_mkdir(&ctx, "/dir1");
    vfs_mkdir(&ctx, "/dir2");
    vfs_write(&ctx, "/file1.txt", "test", 4, 0);
    
    // 读取根目录
    DirEntry entries[32];
    int count = 32;
    
    int ret = vfs_readdir(&ctx, "/", entries, &count);
    if (ret != ERR_SUCCESS) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    if (count != 3) {
        vfs_destroy(&ctx);
        return 0;
    }
    
    vfs_destroy(&ctx);
    return 1;
}

// 测试大文件
int test_large_file(void) {
    VFSContext ctx;
    vfs_init(&ctx, TEST_DISK);
    vfs_format(&ctx);
    vfs_mount(&ctx);
    
    // 写入多块数据 (>4KB)
    char *data = malloc(BLOCK_SIZE * 3);
    memset(data, 'A', BLOCK_SIZE * 3);
    
    int ret = vfs_write(&ctx, "/largefile.bin", data, BLOCK_SIZE * 3, 0);
    if (ret != BLOCK_SIZE * 3) {
        free(data);
        vfs_destroy(&ctx);
        return 0;
    }
    
    // 读取验证
    char *read_buf = malloc(BLOCK_SIZE * 3);
    ret = vfs_read(&ctx, "/largefile.bin", read_buf, BLOCK_SIZE * 3, 0);
    if (ret != BLOCK_SIZE * 3) {
        free(data);
        free(read_buf);
        vfs_destroy(&ctx);
        return 0;
    }
    
    if (memcmp(data, read_buf, BLOCK_SIZE * 3) != 0) {
        free(data);
        free(read_buf);
        vfs_destroy(&ctx);
        return 0;
    }
    
    free(data);
    free(read_buf);
    vfs_destroy(&ctx);
    return 1;
}

/*============================================================================
 * 主函数
 *============================================================================*/

int main(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║         VFS Unit Tests                               ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    RUN_TEST(test_vfs_init);
    RUN_TEST(test_vfs_format);
    RUN_TEST(test_vfs_mount);
    RUN_TEST(test_inode_alloc);
    RUN_TEST(test_block_alloc);
    RUN_TEST(test_mkdir);
    RUN_TEST(test_file_write);
    RUN_TEST(test_file_read);
    RUN_TEST(test_file_delete);
    RUN_TEST(test_readdir);
    RUN_TEST(test_large_file);
    
    printf("\n");
    printf("════════════════════════════════════════════════════════\n");
    printf("Results: %d/%d tests passed", tests_passed, tests_run);
    if (tests_passed == tests_run) {
        printf(" ✓\n");
    } else {
        printf(" ✗\n");
    }
    printf("════════════════════════════════════════════════════════\n");
    printf("\n");
    
    // 清理测试磁盘
    unlink(TEST_DISK);
    
    return (tests_passed == tests_run) ? 0 : 1;
}
