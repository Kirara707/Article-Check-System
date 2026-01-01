# Paper Review File System - Protocol Specification
# 协议规范文档 v1.0

## 1. 概述

PRFS协议是一个基于TCP的二进制协议，用于客户端和服务器之间的通信。
协议采用请求-响应模式，支持文件操作、目录管理和论文评审功能。

## 2. 协议格式

### 2.1 基本结构

```
+------------------+------------------+
|   Header         |    Payload       |
|   (固定大小)     |   (可变大小)     |
+------------------+------------------+
```

### 2.2 请求头 (RequestHeader) - 256字节

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | magic | 魔数: 0x50525450 ("PRTP") |
| 4 | 4 | version | 协议版本: 1 |
| 8 | 4 | type | 命令类型 (CommandType枚举) |
| 12 | 4 | payload_size | 载荷大小 (字节) |
| 16 | 4 | session_id | 会话ID |
| 20 | 128 | filename | 目标路径 (UTF-8, null终止) |
| 148 | 4 | file_size | 文件大小 (上传时使用) |
| 152 | 4 | offset | 偏移量 |
| 156 | 4 | flags | 标志位 |
| 160 | 52 | reserved | 保留 (填充为0) |

### 2.3 响应头 (ServerResponse) - 320字节

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| 0 | 4 | magic | 魔数: 0x50525450 |
| 4 | 4 | version | 协议版本 |
| 8 | 4 | status_code | 状态码 |
| 12 | 4 | payload_size | 载荷大小 |
| 16 | 256 | message | 状态消息 (UTF-8) |
| 272 | 48 | reserved | 保留 |

## 3. 命令类型 (CommandType)

### 3.1 基础命令

| 值 | 命令 | 说明 | 请求载荷 | 响应载荷 |
|----|------|------|----------|----------|
| 0 | CMD_LOGIN | 登录 | LoginPayload | 无 |
| 1 | CMD_LOGOUT | 登出 | 无 | 无 |
| 2 | CMD_LS | 列目录 | 无 | DirListPayload |
| 3 | CMD_UPLOAD | 上传 | 文件数据 | 无 |
| 4 | CMD_DOWNLOAD | 下载 | 无 | 文件数据 |
| 5 | CMD_DELETE | 删除 | 无 | 无 |
| 6 | CMD_MKDIR | 创建目录 | 无 | 无 |
| 7 | CMD_RMDIR | 删除目录 | 无 | 无 |
| 8 | CMD_CD | 切换目录 | 无 | 无 |
| 9 | CMD_STAT | 文件信息 | 无 | FileInfoPayload |
| 10 | CMD_FORMAT | 格式化 | 无 | 无 |

### 3.2 论文评审命令

| 值 | 命令 | 说明 |
|----|------|------|
| 20 | CMD_SUBMIT_PAPER | 提交论文 |
| 21 | CMD_REVIEW_PAPER | 评审论文 |
| 22 | CMD_QUERY_STATUS | 查询状态 |
| 23 | CMD_UPDATE_STATUS | 更新状态 |

## 4. 载荷结构

### 4.1 LoginPayload (132字节)

```c
struct LoginPayload {
    char username[64];    // 用户名
    char password[64];    // 密码
    uint32_t role;        // 角色 (UserRole)
};
```

### 4.2 FileInfoPayload (148字节)

```c
struct FileInfoPayload {
    uint32_t inode_id;        // Inode编号
    uint32_t file_type;       // 文件类型
    uint32_t size;            // 文件大小
    uint64_t mtime;           // 修改时间
    char filename[128];       // 文件名
};
```

### 4.3 DirListPayload (可变长度)

```c
struct DirListPayload {
    uint32_t entry_count;         // 条目数量
    FileInfoPayload entries[];    // 文件信息数组
};
```

### 4.4 PaperSubmitPayload (1420字节)

```c
struct PaperSubmitPayload {
    char title[256];          // 论文标题
    char author[128];         // 作者
    char abstract[1024];      // 摘要
    char filename[128];       // 文件名
    uint32_t file_size;       // 文件大小
};
```

### 4.5 PaperStatusPayload (1108字节)

```c
struct PaperStatusPayload {
    uint32_t paper_id;        // 论文ID
    uint32_t status;          // 状态 (PaperStatus)
    char reviewer[64];        // 评审者
    char comments[1024];      // 评审意见
    uint64_t submit_time;     // 提交时间
    uint64_t review_time;     // 评审时间
};
```

## 5. 状态码

| 代码 | 名称 | 说明 |
|------|------|------|
| 200 | STATUS_OK | 成功 |
| 201 | STATUS_CREATED | 创建成功 |
| 400 | STATUS_BAD_REQUEST | 请求格式错误 |
| 401 | STATUS_UNAUTHORIZED | 需要认证 |
| 404 | STATUS_NOT_FOUND | 资源不存在 |
| 409 | STATUS_CONFLICT | 资源冲突 |
| 500 | STATUS_SERVER_ERROR | 服务器内部错误 |
| 507 | STATUS_DISK_FULL | 磁盘空间不足 |

## 6. 通信流程

### 6.1 文件上传流程

```
Client                          Server
  |                                |
  |-- RequestHeader (CMD_UPLOAD) ->|
  |   (filename, file_size)        |
  |                                |
  |<- ServerResponse (200 OK) -----|
  |                                |
  |-- File Data (chunks) --------->|
  |   (payload_size bytes)         |
  |                                |
  |<- ServerResponse (201 Created)-|
  |                                |
```

### 6.2 文件下载流程

```
Client                          Server
  |                                |
  |-- RequestHeader (CMD_DOWNLOAD)->|
  |   (filename)                   |
  |                                |
  |<- ServerResponse (200 OK) -----|
  |   (payload_size = file_size)   |
  |                                |
  |<- File Data (chunks) ----------|
  |                                |
```

### 6.3 目录列表流程

```
Client                          Server
  |                                |
  |-- RequestHeader (CMD_LS) ----->|
  |   (filename = path)            |
  |                                |
  |<- ServerResponse (200 OK) -----|
  |   (payload_size = dir_list)    |
  |                                |
  |<- DirListPayload --------------|
  |                                |
```

## 7. 错误处理

### 7.1 协议错误

- 魔数不匹配: 关闭连接
- 版本不匹配: 返回400 Bad Request
- 无效命令: 返回400 Bad Request

### 7.2 业务错误

- 文件不存在: 返回404 Not Found
- 权限不足: 返回401 Unauthorized
- 磁盘满: 返回507 Disk Full

## 8. 安全考虑

### 8.1 当前实现

- 密码以明文传输 (仅用于演示)
- 基于角色的简单访问控制

### 8.2 生产环境建议

- 使用TLS加密通信
- 密码哈希存储
- 实施速率限制
- 添加请求签名验证

## 9. 版本历史

| 版本 | 日期 | 变更 |
|------|------|------|
| 1.0 | 2026-01-01 | 初始版本 |
