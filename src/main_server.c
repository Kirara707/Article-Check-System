/**
 * @file main_server.c
 * @brief 服务器主程序入口
 * 
 * 用法: ./prfs_server [port] [disk_path]
 */

#include "../include/common.h"
#include "../include/vfs.h"
#include "../include/server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#define DEFAULT_DISK_PATH   "./disk.img"

void print_usage(const char *prog) {
    printf("Paper Review File System Server\n");
    printf("Usage: %s [options]\n", prog);
    printf("\nOptions:\n");
    printf("  -p, --port <port>       Listen port (default: %d)\n", DEFAULT_PORT);
    printf("  -d, --disk <path>       Disk image path (default: %s)\n", DEFAULT_DISK_PATH);
    printf("  -f, --format            Format disk before starting\n");
    printf("  -v, --verbose           Enable verbose logging\n");
    printf("  -h, --help              Show this help\n");
    printf("\nExamples:\n");
    printf("  %s                      Start with defaults\n", prog);
    printf("  %s -p 9000              Use port 9000\n", prog);
    printf("  %s -d /data/disk.img -f Format and use custom disk\n", prog);
}

int main(int argc, char *argv[]) {
    uint16_t port = DEFAULT_PORT;
    const char *disk_path = DEFAULT_DISK_PATH;
    bool format_disk = false;
    bool verbose = false;
    
    // 解析命令行参数
    static struct option long_options[] = {
        {"port",    required_argument, 0, 'p'},
        {"disk",    required_argument, 0, 'd'},
        {"format",  no_argument,       0, 'f'},
        {"verbose", no_argument,       0, 'v'},
        {"help",    no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:d:fvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            case 'd':
                disk_path = optarg;
                break;
            case 'f':
                format_disk = true;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    printf("\n");
    printf("╔══════════════════════════════════════════════════════╗\n");
    printf("║     Paper Review File System Server                  ║\n");
    printf("║     Version 1.0                                      ║\n");
    printf("╚══════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // 初始化VFS
    VFSContext vfs;
    int ret = vfs_init(&vfs, disk_path);
    if (ret != ERR_SUCCESS) {
        fprintf(stderr, "Failed to initialize VFS: %s\n", vfs_strerror(ret));
        return 1;
    }
    
    // 格式化(如果请求)
    if (format_disk) {
        printf("Formatting disk...\n");
        ret = vfs_format(&vfs);
        if (ret != ERR_SUCCESS) {
            fprintf(stderr, "Failed to format disk: %s\n", vfs_strerror(ret));
            vfs_destroy(&vfs);
            return 1;
        }
    }
    
    // 挂载文件系统
    ret = vfs_mount(&vfs);
    if (ret != ERR_SUCCESS) {
        fprintf(stderr, "Failed to mount VFS: %s\n", vfs_strerror(ret));
        vfs_destroy(&vfs);
        return 1;
    }
    
    // 初始化服务器
    ServerContext server;
    ret = server_init(&server, port, &vfs);
    if (ret != 0) {
        fprintf(stderr, "Failed to initialize server\n");
        vfs_destroy(&vfs);
        return 1;
    }
    
    printf("Configuration:\n");
    printf("  Disk:        %s\n", disk_path);
    printf("  Port:        %u\n", port);
    printf("  Threads:     %d\n", THREAD_POOL_SIZE);
    printf("  Max clients: %d\n", MAX_CLIENTS);
    printf("\n");
    printf("Server ready. Press Ctrl+C to stop.\n");
    printf("\n");
    
    // 启动服务器(阻塞)
    server_start(&server);
    
    // 清理
    printf("\nShutting down...\n");
    server_destroy(&server);
    vfs_unmount(&vfs);
    vfs_destroy(&vfs);
    
    printf("Server stopped.\n");
    return 0;
}
