# Paper Review File System (PRFS)

科学论文评审平台 - 虚拟文件系统与网络通信集成项目

## 项目概述

本项目实现了一个完整的C/S架构文件系统，专为科学论文评审场景设计。系统集成了虚拟存储层、网络通信协议和并发处理能力。

### 核心特性

- **虚拟文件系统 (VFS)**: 模拟块设备，支持 SuperBlock、Inode、位图管理
- **网络通信**: 基于TCP的客户端/服务器模型，自定义二进制协议
- **并发处理**: 线程池架构，支持512+并发连接
- **LRU缓存**: 16MB块缓存，减少磁盘I/O延迟
- **论文评审**: 完整的状态机工作流 (提交 → 评审 → 接受/拒绝)

## 系统架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client Application                        │
├─────────────────────────────────────────────────────────────────┤
│                      Protocol Layer (TCP)                        │
├─────────────────────────────────────────────────────────────────┤
│                        Server Framework                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Thread Pool │  │   Session   │  │   Command   │             │
│  │  (16 workers)│  │   Manager   │  │   Handler   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│                       LRU Block Cache                            │
├─────────────────────────────────────────────────────────────────┤
│                    Virtual File System                           │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐   │
│  │ SuperBlock│  │  Bitmaps  │  │  Inodes   │  │Data Blocks│   │
│  └───────────┘  └───────────┘  └───────────┘  └───────────┘   │
├─────────────────────────────────────────────────────────────────┤
│                         disk.img                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 磁盘布局

```
Block 0:     SuperBlock (4KB)
Block 1:     Inode Bitmap (4KB) - 管理1024个Inode
Block 2-3:   Data Bitmap (8KB) - 管理16K数据块
Block 4-35:  Inode Table (128KB) - 1024个Inode
Block 36+:   Data Blocks - 用户数据存储
```

## 快速开始

### 环境要求

- GCC 7.0+ (支持 C11)
- POSIX 兼容系统 (Linux, macOS)
- pthread 库
- Make

### 编译

```bash
# 编译所有组件
make

# 仅编译服务器
make bin/prfs_server

# 仅编译客户端
make bin/prfs_client

# 清理构建
make clean
```

### 运行

**启动服务器:**

```bash
# 使用默认配置 (端口8080, 磁盘./disk.img)
./bin/prfs_server

# 自定义配置
./bin/prfs_server -p 9000 -d /data/papers.img

# 首次运行时格式化磁盘
./bin/prfs_server -f
```

**启动客户端:**

```bash
# 交互模式
./bin/prfs_client

# 直接连接服务器
./bin/prfs_client -s localhost -p 8080
```

### 客户端命令

```
connect <host> <port>     - 连接服务器
disconnect                - 断开连接
login <user> <role>       - 登录 (role: 0=访客, 1=作者, 2=评审, 3=管理员)
logout                    - 登出

ls [path]                 - 列出目录
cd <path>                 - 切换目录
pwd                       - 显示当前目录
mkdir <path>              - 创建目录
rmdir <path>              - 删除目录

upload <local> <remote>   - 上传文件
download <remote> <local> - 下载文件
delete <path>             - 删除文件
stat <path>               - 显示文件信息

submit <file> <title> <author> - 提交论文
status                    - 显示连接状态
help                      - 显示帮助
quit                      - 退出
```

## 项目结构

```
Op Sys/
├── include/              # 头文件
│   ├── common.h          # 通用定义和常量
│   ├── vfs.h             # VFS结构和接口
│   ├── protocol.h        # 网络协议定义
│   ├── server.h          # 服务器框架
│   ├── client.h          # 客户端接口
│   └── cache.h           # LRU缓存
├── src/                  # 源文件
│   ├── vfs.c             # VFS实现
│   ├── protocol.c        # 协议实现
│   ├── server.c          # 服务器实现
│   ├── client.c          # 客户端实现
│   ├── cache.c           # 缓存实现
│   ├── main_server.c     # 服务器入口
│   └── main_client.c     # 客户端入口
├── tests/                # 测试文件
│   ├── test_vfs.c        # VFS单元测试
│   └── run_tests.sh      # 测试运行脚本
├── docs/                 # 文档
├── Makefile              # 构建脚本
├── BUILD_PLAN.md         # 构建计划
└── README.md             # 本文件
```

## 协议规范

### 请求头 (RequestHeader)

```c
struct RequestHeader {
    uint32_t magic;           // 0x50525450 ("PRTP")
    uint32_t version;         // 协议版本
    CommandType type;         // 命令类型
    uint32_t payload_size;    // 载荷大小
    uint32_t session_id;      // 会话ID
    char filename[128];       // 目标路径
    uint32_t file_size;       // 文件大小
    uint32_t offset;          // 偏移量
    uint32_t flags;           // 标志位
};
```

### 响应 (ServerResponse)

```c
struct ServerResponse {
    uint32_t magic;           // 0x50525450
    uint32_t version;         // 协议版本
    StatusCode status_code;   // 状态码 (200, 404, 507等)
    uint32_t payload_size;    // 载荷大小
    char message[256];        // 状态消息
};
```

### 状态码

| 代码 | 含义 |
|------|------|
| 200  | OK - 成功 |
| 201  | Created - 创建成功 |
| 400  | Bad Request - 请求错误 |
| 401  | Unauthorized - 未授权 |
| 404  | Not Found - 未找到 |
| 409  | Conflict - 冲突 |
| 500  | Server Error - 服务器错误 |
| 507  | Disk Full - 磁盘已满 |

## 测试

```bash
# 运行所有测试
make test

# 或直接运行
cd tests && ./run_tests.sh

# 内存检查
make valgrind
```

## 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| BLOCK_SIZE | 4096 | 块大小 (字节) |
| DISK_SIZE | 64MB | 磁盘大小 |
| INODE_COUNT | 1024 | 最大Inode数 |
| MAX_CLIENTS | 512 | 最大客户端数 |
| THREAD_POOL_SIZE | 16 | 线程池大小 |
| CACHE_SIZE | 16MB | 缓存大小 |
| DEFAULT_PORT | 8080 | 默认端口 |

## 论文评审工作流

```
                    ┌──────────────┐
                    │  Submitted   │
                    └──────┬───────┘
                           │
                           ▼
                    ┌──────────────┐
                    │ Under Review │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
       ┌──────────┐ ┌──────────┐ ┌──────────┐
       │ Accepted │ │ Revision │ │ Rejected │
       └──────────┘ │ Required │ └──────────┘
                    └────┬─────┘
                         │
                         ▼
                  ┌──────────────┐
                  │  Resubmit    │
                  └──────────────┘
```

## 未来改进

- [ ] 多级间接块支持 (大文件)
- [ ] 符号链接
- [ ] 文件权限控制
- [ ] 日志/WAL机制
- [ ] Web界面
- [ ] 分布式存储支持

## 许可证

MIT License

## 作者

操作系统课程项目组
