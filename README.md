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
=== 连接管理 ===
connect <host> <port>     - 连接服务器
disconnect                - 断开连接
login <user> <role>       - 登录 (role: 0=访客, 1=作者, 2=评审, 3=编辑, 4=管理员)
logout                    - 登出
status                    - 显示连接状态

=== 文件操作 ===
ls [path]                 - 列出目录
cd <path>                 - 切换目录
pwd                       - 显示当前目录
mkdir <path>              - 创建目录 (仅管理员)
rmdir <path>              - 删除目录 (仅管理员)
upload <local> <remote>   - 上传文件
download <remote> <local> - 下载文件
delete <path>             - 删除文件
stat <path>               - 显示文件信息

=== 论文提交 ===
submit <file> <title> <author> - 提交论文

=== 评审管理 (评审/编辑) ===
review <paper_id> <score> <decision> <comments> - 上传评审意见
getreview <paper_id>      - 查询论文的评审意见
assign <paper_id> <reviewer> - 分配审稿人 (编辑权限)
decide <paper_id> <accept|reject|revision> - 做出决定 (编辑权限)

=== 备份管理 (管理员) ===
backup create [desc]      - 创建备份
backup list               - 列出所有备份
backup restore <id>       - 恢复指定备份

=== 用户管理 (管理员) ===
useradd <username> <password> <role> - 添加用户
userdel <username>        - 删除用户
userlist                  - 列出所有用户

=== 系统信息 ===
sysinfo                   - 显示系统状态

=== 通用 ===
help                      - 显示帮助
quit                      - 退出
```

### 命令使用示例

#### 连接和登录
```bash
# 连接到本地服务器
connect localhost 8080

# 以管理员身份登录 (role=3)
login admin 4

# 以作者身份登录 (role=1)
login zhangsan 1

# 以评审身份登录 (role=2)
login reviewer1 2
```

#### 目录操作 (需要管理员权限)
```bash
# 使用绝对路径创建目录
mkdir /papers
mkdir /papers/2024

# 使用相对路径创建目录 (基于当前目录)
cd /papers
mkdir submissions      # 实际创建 /papers/submissions

# 列出目录内容
ls                     # 列出当前目录
ls /                   # 列出根目录
ls /papers             # 列出指定目录

# 切换目录
cd /papers             # 切换到绝对路径
cd submissions         # 切换到子目录
cd ..                  # 返回上级目录

# 显示当前目录
pwd

# 删除空目录 (目录必须为空)
rmdir /papers/submissions
```

#### 文件操作
```bash
# 上传文件 (本地路径 -> 远程路径)
upload ./paper.pdf /papers/paper.pdf
upload ./draft.txt /papers/2024/draft.txt

# 下载文件 (远程路径 -> 本地路径)
download /papers/paper.pdf ./downloaded.pdf

# 删除文件
delete /papers/old_paper.pdf

# 查看文件信息
stat /papers/paper.pdf
```

#### 论文提交 (作者权限)
```bash
# 以作者身份登录
login author1 1

# 提交论文
submit ./my_paper.pdf "Deep Learning Research" "Zhang San"
```

#### 备份管理 (管理员权限)
```bash
# 以管理员身份登录
login admin 4

# 创建备份并添加描述
backup create "Before major update"

# 列出所有备份
backup list
# 输出示例:
# === Backup List (2 backups) ===
# ID: 1767514511
#   Created: 2026-01-04 16:15:11
#   Description: Before major update
#   File: backup_1767514511.img

# 恢复指定备份
backup restore 1767514511
```

#### 用户管理 (管理员权限)
```bash
# 添加新用户
useradd zhangsan password123 1   # 添加作者
useradd reviewer1 pass456 2      # 添加评审员
useradd editor1 pass789 3        # 添加编辑

# 列出所有用户
userlist
# 输出示例:
# === User List (3 users) ===
# 1. zhangsan
#    Role: Author
#    Created: 2026-01-04 16:20
#    Status: Active

# 删除用户
userdel zhangsan
```

#### 评审管理 (评审/编辑权限)
```bash
# 以评审身份登录
login reviewer1 2

# 上传评审意见 (paper_id, score, decision)
review 12345 8 accept "Great paper with solid methodology"

# 查询评审意见
getreview 12345

# 以编辑身份登录
login editor1 3

# 分配审稿人
assign 12345 reviewer1

# 做出最终决定
decide 12345 accept
decide 12346 reject
decide 12347 revision
```

#### 系统状态查看
```bash
# 查看系统状态
sysinfo
# 输出示例:
# ╔══════════════════════════════════════════════════════╗
# ║              System Status Report                     ║
# ╠══════════════════════════════════════════════════════╣
# ║ Uptime: 0 days, 02:15:30
# ║ Storage: Used 36/16384 blocks (0.2%)
# ║ Inodes: Free 1023/1024
# ║ Active Clients: 2 / 512
# ╚══════════════════════════════════════════════════════╝
```

#### 常见错误及解决方法

| 错误信息 | 原因 | 解决方法 |
|----------|------|----------|
| Permission denied: only admin can create directories | 非管理员尝试创建目录 | 使用 `login admin 4` 以管理员身份登录 |
| Permission denied: only admin can create backups | 非管理员尝试备份 | 使用 `login admin 4` 以管理员身份登录 |
| Permission denied: only reviewers can upload reviews | 非评审员尝试上传评审 | 使用评审员角色登录 (role=2) |
| Permission denied: only editors can assign reviewers | 非编辑尝试分配审稿人 | 使用编辑角色登录 (role=3) |
| Invalid path | 路径格式错误 | 使用绝对路径如 `/papers` 而不是 `papers` |
| Directory not empty | 尝试删除非空目录 | 先删除目录内的文件 |
| File not found | 文件或目录不存在 | 使用 `ls` 确认路径正确 |
| User already exists | 尝试添加已存在的用户 | 选择不同的用户名 |
| Backup not found | 备份ID不存在 | 使用 `backup list` 查看可用备份 |

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

## 新增功能 (v2.0)

- [x] **编辑角色**: 新增 ROLE_EDITOR (3)，可分配审稿人和做出最终决定
- [x] **备份系统**: 支持创建、列出、恢复完整文件系统备份
- [x] **用户管理**: 管理员可添加、删除、列出系统用户
- [x] **评审管理**: 评审员可上传评审意见，编辑可分配审稿人
- [x] **系统状态**: 实时查看存储使用、运行时间、连接数等信息

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
