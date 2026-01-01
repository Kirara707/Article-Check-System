/**
 * @file main_client.c
 * @brief 客户端主程序入口
 * 
 * 用法: ./prfs_client [host] [port]
 */

#include "../include/common.h"
#include "../include/client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

void print_usage(const char *prog) {
    printf("Paper Review File System Client\n");
    printf("Usage: %s [options]\n", prog);
    printf("\nOptions:\n");
    printf("  -s, --server <host>     Server hostname (default: localhost)\n");
    printf("  -p, --port <port>       Server port (default: %d)\n", DEFAULT_PORT);
    printf("  -u, --user <username>   Auto-login username\n");
    printf("  -h, --help              Show this help\n");
    printf("\nExamples:\n");
    printf("  %s                      Interactive mode\n", prog);
    printf("  %s -s 192.168.1.100     Connect to specific host\n", prog);
    printf("  %s -s localhost -p 9000 Connect to localhost:9000\n", prog);
}

int main(int argc, char *argv[]) {
    const char *server = NULL;
    uint16_t port = DEFAULT_PORT;
    const char *username = NULL;
    
    // 解析命令行参数
    static struct option long_options[] = {
        {"server", required_argument, 0, 's'},
        {"port",   required_argument, 0, 'p'},
        {"user",   required_argument, 0, 'u'},
        {"help",   no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "s:p:u:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 's':
                server = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'u':
                username = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // 初始化客户端
    ClientContext ctx;
    if (client_init(&ctx) != 0) {
        fprintf(stderr, "Failed to initialize client\n");
        return 1;
    }
    
    // 如果指定了服务器，自动连接
    if (server) {
        if (client_connect(&ctx, server, port) != 0) {
            fprintf(stderr, "Failed to connect to %s:%u\n", server, port);
            client_destroy(&ctx);
            return 1;
        }
        
        // 如果指定了用户名，自动登录
        if (username) {
            client_login(&ctx, username, "", ROLE_AUTHOR);
        }
    }
    
    // 进入交互模式
    client_interactive(&ctx);
    
    // 清理
    client_destroy(&ctx);
    
    return 0;
}
