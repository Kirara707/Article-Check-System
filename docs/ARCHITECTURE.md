# Paper Review File System - Architecture Document
# 系统架构文档

## 1. 系统概述

Paper Review File System (PRFS) 是一个专为科学论文评审场景设计的分布式文件系统。
系统采用客户端-服务器架构，集成了虚拟存储层、网络通信和并发处理能力。

## 2. 架构层次

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application Layer                            │
│  ┌───────────────────┐        ┌───────────────────┐            │
│  │   Client CLI      │        │  Paper Review API │            │
│  └───────────────────┘        └───────────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│                     Protocol Layer                               │
│  ┌───────────────────────────────────────────────┐             │
│  │  Binary Protocol (PRTP)                       │             │
│  │  - Request/Response Model                     │             │
│  │  - Session Management                         │             │
│  └───────────────────────────────────────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│                     Server Framework                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ Thread Pool  │  │   Session    │  │   Command    │         │
│  │ (16 workers) │  │   Manager    │  │   Handler    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
├─────────────────────────────────────────────────────────────────┤
│                     Caching Layer                                │
│  ┌───────────────────────────────────────────────┐             │
│  │  LRU Block Cache (16MB)                       │             │
│  │  - Hash Table + Doubly Linked List            │             │
│  │  - Write-back Policy                          │             │
│  └───────────────────────────────────────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│                     VFS Layer                                    │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐               │
│  │ SuperBlock │  │   Inode    │  │   Bitmap   │               │
│  │  Manager   │  │   Table    │  │   Manager  │               │
│  └────────────┘  └────────────┘  └────────────┘               │
│  ┌────────────────────────────────────────────────┐            │
│  │  Block I/O Layer                               │            │
│  └────────────────────────────────────────────────┘            │
├─────────────────────────────────────────────────────────────────┤
│                     Storage Layer                                │
│  ┌───────────────────────────────────────────────┐             │
│  │  disk.img (64MB)                              │             │
│  └───────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## 3. 核心模块

### 3.1 VFS模块 (vfs.c)

负责虚拟文件系统的核心操作。

**主要结构:**
- `SuperBlock`: 文件系统元数据
- `Inode`: 文件/目录元数据
- `DirEntry`: 目录项

**主要接口:**
```c
int vfs_init(VFSContext *ctx, const char *disk_path);
int vfs_format(VFSContext *ctx);
int vfs_mount(VFSContext *ctx);
int vfs_create(VFSContext *ctx, const char *path, FileType type);
int vfs_read(VFSContext *ctx, const char *path, void *buf, uint32_t size, uint32_t offset);
int vfs_write(VFSContext *ctx, const char *path, const void *buf, uint32_t size, uint32_t offset);
```

### 3.2 协议模块 (protocol.c)

处理客户端-服务器通信协议。

**主要结构:**
- `RequestHeader`: 请求头
- `ServerResponse`: 响应结构

**主要接口:**
```c
int protocol_send_request(int sockfd, const RequestHeader *header, const void *payload);
int protocol_recv_request(int sockfd, RequestHeader *header, void *payload, uint32_t max_payload);
int protocol_send_response(int sockfd, const ServerResponse *response, const void *payload);
```

### 3.3 服务器模块 (server.c)

多线程服务器框架。

**主要组件:**
- `ThreadPool`: 线程池管理
- `ClientSession`: 客户端会话
- `ServerContext`: 服务器上下文

**并发模型:**
```
                    ┌─────────────────┐
                    │   Main Thread   │
                    │  (Accept Loop)  │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────┴─────┐  ┌─────┴─────┐  ┌─────┴─────┐
        │ Worker 1  │  │ Worker 2  │  │ Worker N  │
        │ (handle)  │  │ (handle)  │  │ (handle)  │
        └───────────┘  └───────────┘  └───────────┘
```

### 3.4 缓存模块 (cache.c)

LRU块缓存实现。

**数据结构:**
```
Hash Table                    LRU List
┌───────┐                 ┌─────┐
│ [0]   │────────────────>│ MRU │ (Most Recently Used)
├───────┤                 ├─────┤
│ [1]   │────>┌─────┐     │     │
├───────┤     │block│<--->│     │
│ [2]   │     └─────┘     ├─────┤
├───────┤                 │     │
│ ...   │                 ├─────┤
├───────┤                 │ LRU │ (Least Recently Used)
│ [N]   │                 └─────┘
└───────┘
```

## 4. 数据流

### 4.1 文件上传流程

```
Client          Server          VFS            Disk
  │                │              │              │
  │──upload req──->│              │              │
  │                │──alloc inode>│              │
  │                │              │──write sb──->│
  │                │<─────────────│              │
  │<──200 OK───────│              │              │
  │                │              │              │
  │──file data───->│              │              │
  │                │──vfs_write──>│              │
  │                │              │──alloc block>│
  │                │              │<─────────────│
  │                │              │──write data->│
  │                │<─────────────│              │
  │<──201 Created─│              │              │
```

### 4.2 缓存读取流程

```
Application      Cache          Disk
     │              │              │
     │──read req──->│              │
     │              │──lookup──>   │
     │              │  (hit?)      │
     │              │   │          │
     │              │   ├─ HIT ────┼─> return from cache
     │              │   │          │
     │              │   └─ MISS    │
     │              │──────────────>│ read block
     │              │<──────────────│
     │              │──add to cache │
     │              │──update LRU   │
     │<─────────────│              │
```

## 5. 同步机制

### 5.1 锁层次

```
Level 1: Global Locks
├── sb_lock           - SuperBlock操作
├── inode_bitmap_lock - Inode分配
└── data_bitmap_lock  - 块分配

Level 2: Fine-grained Locks
├── inode.lock        - 单个Inode操作
└── cache.lock        - 缓存操作

Level 3: Session Locks
└── sessions_lock     - 会话管理
```

### 5.2 死锁预防

- 按固定顺序获取锁
- Inode锁按Inode ID升序获取
- 超时机制 (未来改进)

## 6. 内存管理

### 6.1 内存布局

```
┌────────────────────────────────────────┐
│ VFSContext                             │
├────────────────────────────────────────┤
│ inode_bitmap (1 page)                  │
│ data_bitmap  (2 pages)                 │
│ inode_table  (1024 * sizeof(Inode))    │
├────────────────────────────────────────┤
│ BlockCache                             │
│ └── entries[4096] (16MB data)          │
├────────────────────────────────────────┤
│ ThreadPool                             │
│ ├── threads[16]                        │
│ └── task_queue[256]                    │
├────────────────────────────────────────┤
│ Sessions[512]                          │
└────────────────────────────────────────┘
```

### 6.2 内存估算

| 组件 | 大小 |
|------|------|
| Inode表 | ~256 KB |
| 位图 | ~12 KB |
| 块缓存 | 16 MB |
| 会话 | ~128 KB |
| 线程栈 | 16 * 8MB = 128 MB |
| **总计** | **~145 MB** |

## 7. 性能特性

### 7.1 设计目标

| 指标 | 目标 |
|------|------|
| 并发连接 | 512+ |
| 缓存命中率 | >80% |
| 单连接吞吐 | >50 MB/s |
| 平均延迟 | <10ms |

### 7.2 瓶颈分析

1. **磁盘I/O**: 通过LRU缓存缓解
2. **网络带宽**: 可配置缓冲区
3. **锁竞争**: 细粒度锁+无锁队列
4. **内存复制**: 零拷贝优化 (未来)

## 8. 扩展点

### 8.1 水平扩展

- 分布式元数据服务器
- 数据分片 (Sharding)
- 读副本

### 8.2 垂直扩展

- 更大的缓存
- 更多的工作线程
- NUMA感知调度

## 9. 安全架构

```
┌─────────────────────────────────────┐
│         Security Layer              │
├─────────────────────────────────────┤
│ Authentication                      │
│ ├── Username/Password               │
│ └── Role-based Access              │
├─────────────────────────────────────┤
│ Authorization                       │
│ ├── File Permissions               │
│ └── Operation Restrictions         │
├─────────────────────────────────────┤
│ Audit                               │
│ └── Access Logging                 │
└─────────────────────────────────────┘
```

## 10. 部署架构

### 10.1 单机部署

```
┌──────────────────────────────────┐
│           Server Host            │
│  ┌────────────┐ ┌────────────┐  │
│  │   PRFS     │ │  disk.img  │  │
│  │  Server    │ │            │  │
│  └────────────┘ └────────────┘  │
└──────────────────────────────────┘
        ▲
        │ TCP
        │
┌───────┴──────────────────────────┐
│       Client Hosts               │
│  ┌────────┐  ┌────────┐         │
│  │Client 1│  │Client 2│ ...     │
│  └────────┘  └────────┘         │
└──────────────────────────────────┘
```

### 10.2 高可用部署 (未来)

```
                ┌─────────────┐
                │ Load Balancer│
                └──────┬──────┘
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
    ┌─────────┐   ┌─────────┐   ┌─────────┐
    │ Server1 │   │ Server2 │   │ Server3 │
    └────┬────┘   └────┬────┘   └────┬────┘
         │             │             │
         └─────────────┼─────────────┘
                       ▼
              ┌────────────────┐
              │ Shared Storage │
              └────────────────┘
```
