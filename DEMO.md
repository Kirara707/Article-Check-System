# 论文评审文件系统 - 完整演示指南

## 第一步：准备环境

```bash
cd /home/lizhe/Op\ Sys
rm -f disk.img
make clean && make
```

## 第二步：启动服务器

在**第一个终端**中运行：

```bash
cd /home/lizhe/Op\ Sys
./bin/prfs_server
```

你会看到：
```
[INFO] src/vfs.c:294: VFS mounted: PaperReviewFS
=== SuperBlock ===
  Magic:        0x53465653
  Version:      1
  Block size:   4096 bytes
  Total blocks: 16384
  Free blocks:  16348
  Total inodes: 1024
  Free inodes:  1023
  Volume name:  PaperReviewFS
==================
```

**保持服务器运行，不要关闭这个终端！**

---

## 第三步：演示所有功能

在**第二个终端**中运行客户端：

```bash
cd /home/lizhe/Op\ Sys
./bin/prfs_client
```

你会看到提示符：
```
Paper Review File System Client
================================
Type 'help' for available commands.

prfs>
```

然后按顺序输入以下命令：

### 3.1 连接和登录

```
connect localhost 8080
login admin 4
```

输出：
```
Connected to localhost:8080
Login successful: Login successful
```

### 3.2 查看系统状态

```
sysinfo
```

### 3.3 用户管理系统

#### 添加用户
```
useradd author1 pass123 1
useradd reviewer1 rev456 2
useradd editor1 edit789 3
```

#### 列出所有用户
```
userlist
```

### 3.4 备份系统

#### 创建备份
```
backup create "Snapshot before demo"
```

#### 列出备份
```
backup list
```

### 3.5 文件操作

#### 创建目录
```
mkdir /papers
mkdir /papers/2024
mkdir /papers/reviews
```

#### 列出目录
```
ls /
ls /papers
```

---

### 3.6 论文提交流程

**首先在终端创建示例论文文件：**
```bash
echo "Deep Learning Research Paper" > /tmp/paper1.txt
echo "Graph Neural Networks Study" > /tmp/paper2.txt
echo "Reinforcement Learning Methods" > /tmp/paper3.txt
```

**然后在客户端中：**
```
logout
login author1 pass123 1
upload /tmp/paper1.txt /papers/paper_2024_001.txt
upload /tmp/paper2.txt /papers/paper_2024_002.txt
upload /tmp/paper3.txt /papers/paper_2024_003.txt
status
```

### 3.7 编辑分配审稿人

```
logout
login editor1 edit789 3
assign 1 reviewer1
assign 2 reviewer1
assign 3 reviewer1
```

### 3.8 评审员上传评审意见

```
logout
login reviewer1 rev456 2
review 1 9 accept
review 2 7 revision
review 3 5 reject
```

#### 查询评审意见
```
getreview 1
getreview 2
```

### 3.9 编辑做出最终决定

```
logout
login editor1 edit789 3
decide 1 accept
decide 2 revision
decide 3 reject
```

### 3.10 权限验证

```
logout
login author1 pass123 1
mkdir /unauthorized
backup create test
useradd testuser pass 1
```

输出：
```
Error: Permission denied: only admin can create directories
Error: Permission denied: only admin can create backups
Error: Permission denied: only admin can add users
```

### 3.11 退出

```
quit
```

---

## 一次性运行完整演示脚本

**第一步：创建示例文件**
```bash
echo "Sample Paper 1" > /tmp/sample1.txt
echo "Sample Paper 2" > /tmp/sample2.txt
echo "Sample Paper 3" > /tmp/sample3.txt
```

**第二步：运行脚本**
```bash
cd /home/lizhe/Op\ Sys
./bin/prfs_client << 'DEMO'
connect localhost 8080
login admin 4
sysinfo
useradd alice alice123 1
useradd bob bob456 2
useradd charlie charlie789 3
userlist
backup create "Before demo"
backup list
mkdir /submissions
logout
login alice alice123 1
upload /tmp/sample1.txt /submissions/paper1.txt
upload /tmp/sample2.txt /submissions/paper2.txt
upload /tmp/sample3.txt /submissions/paper3.txt
ls /submissions
logout
login charlie charlie789 3
assign 1 bob
assign 2 bob
assign 3 bob
logout
login bob bob456 2
review 1 9 accept
review 2 7 revision
review 3 5 reject
getreview 1
logout
login charlie charlie789 3
decide 1 accept
decide 2 revision
decide 3 reject
sysinfo
quit
DEMO
```

---

## 登录命令格式说明

**新的登录命令格式：**
```
login <username> <password> <role>
```

**示例：**
- `login admin 4` - 管理员引导登录（无需密码）
- `login editor1 edit789 3` - 编辑角色登录
- `login reviewer1 rev456 2` - 审稿人登录
- `login author1 pass123 1` - 作者登录

---

## 用户角色说明

| 角色 | 编号 | 权限 |
|------|------|------|
| Guest | 0 | 只能查看信息 |
| Author | 1 | 可以提交论文 |
| Reviewer | 2 | 可以上传评审意见 |
| Editor | 3 | 可以分配审稿人和做出决定 |
| Admin | 4 | 最高权限，所有操作 |

---

## 关键命令总结

| 功能 | 命令 | 权限 |
|------|------|------|
| 添加用户 | `useradd <name> <pass> <role>` | Admin |
| 列出用户 | `userlist` | Admin |
| 创建备份 | `backup create [desc]` | Admin |
| 创建目录 | `mkdir <path>` | Admin |
| 上传文件 | `upload <local> <remote>` | 所有 |
| 上传评审 | `review <id> <score> <decision>` | Reviewer/Editor |
| 分配审稿人 | `assign <id> <reviewer>` | Editor/Admin |
| 做出决定 | `decide <id> <decision>` | Editor/Admin |

---

## 完成！

所有功能演示完毕：
- ✅ 用户管理系统
- ✅ 备份和恢复功能
- ✅ 文件系统操作
- ✅ 评审意见管理
- ✅ 编辑决策流程
- ✅ 权限控制验证
- ✅ 系统监控
