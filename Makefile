# Paper Review File System
# Makefile

# 编译器设置
CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g -O2 -pthread
LDFLAGS = -pthread

# 目录
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
TEST_DIR = tests

# 源文件
COMMON_SRC = $(SRC_DIR)/vfs.c $(SRC_DIR)/protocol.c $(SRC_DIR)/cache.c
SERVER_SRC = $(SRC_DIR)/server.c $(SRC_DIR)/main_server.c
CLIENT_SRC = $(SRC_DIR)/client.c $(SRC_DIR)/main_client.c

# 目标文件
COMMON_OBJ = $(COMMON_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
SERVER_OBJ = $(SERVER_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
CLIENT_OBJ = $(CLIENT_SRC:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# 可执行文件
SERVER_BIN = $(BIN_DIR)/prfs_server
CLIENT_BIN = $(BIN_DIR)/prfs_client

# 包含路径
INCLUDES = -I$(INC_DIR)

# 默认目标
.PHONY: all clean test install help

all: directories $(SERVER_BIN) $(CLIENT_BIN)
	@echo ""
	@echo "╔══════════════════════════════════════════════════════╗"
	@echo "║  Build Complete!                                     ║"
	@echo "╠══════════════════════════════════════════════════════╣"
	@echo "║  Server: $(SERVER_BIN)"
	@echo "║  Client: $(CLIENT_BIN)"
	@echo "╚══════════════════════════════════════════════════════╝"
	@echo ""

# 创建目录
directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# 编译服务器
$(SERVER_BIN): $(COMMON_OBJ) $(SERVER_OBJ)
	@echo "[LINK] $@"
	@$(CC) $(LDFLAGS) -o $@ $^

# 编译客户端
$(CLIENT_BIN): $(COMMON_OBJ) $(CLIENT_OBJ)
	@echo "[LINK] $@"
	@$(CC) $(LDFLAGS) -o $@ $^

# 编译目标文件
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "[CC] $<"
	@$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

# 清理
clean:
	@echo "Cleaning..."
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@rm -f disk.img
	@echo "Done."

# 深度清理(包括测试文件)
distclean: clean
	@rm -rf $(TEST_DIR)/*.o
	@rm -f *.log

# 测试
test: all
	@echo "Running tests..."
	@cd $(TEST_DIR) && ./run_tests.sh

# 运行服务器
run-server: $(SERVER_BIN)
	@echo "Starting server..."
	@$(SERVER_BIN) -f

# 运行客户端
run-client: $(CLIENT_BIN)
	@echo "Starting client..."
	@$(CLIENT_BIN)

# 格式化磁盘
format: $(SERVER_BIN)
	@echo "Formatting disk..."
	@$(SERVER_BIN) -f &
	@sleep 1
	@pkill -f prfs_server

# 内存检查
valgrind: $(SERVER_BIN)
	@echo "Running with valgrind..."
	@valgrind --leak-check=full --show-leak-kinds=all $(SERVER_BIN) -f

# 帮助
help:
	@echo ""
	@echo "Paper Review File System - Build System"
	@echo "========================================"
	@echo ""
	@echo "Targets:"
	@echo "  all          - Build server and client (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  distclean    - Deep clean including logs"
	@echo "  test         - Run tests"
	@echo "  run-server   - Build and run server"
	@echo "  run-client   - Build and run client"
	@echo "  format       - Format disk image"
	@echo "  valgrind     - Run with memory checking"
	@echo "  help         - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make                  # Build everything"
	@echo "  make run-server       # Start server"
	@echo "  make run-client       # Start client"
	@echo "  make clean && make    # Rebuild"
	@echo ""

# 依赖关系
$(OBJ_DIR)/vfs.o: $(SRC_DIR)/vfs.c $(INC_DIR)/vfs.h $(INC_DIR)/common.h
$(OBJ_DIR)/protocol.o: $(SRC_DIR)/protocol.c $(INC_DIR)/protocol.h $(INC_DIR)/common.h
$(OBJ_DIR)/cache.o: $(SRC_DIR)/cache.c $(INC_DIR)/cache.h $(INC_DIR)/common.h
$(OBJ_DIR)/server.o: $(SRC_DIR)/server.c $(INC_DIR)/server.h $(INC_DIR)/vfs.h $(INC_DIR)/protocol.h
$(OBJ_DIR)/client.o: $(SRC_DIR)/client.c $(INC_DIR)/client.h $(INC_DIR)/protocol.h
$(OBJ_DIR)/main_server.o: $(SRC_DIR)/main_server.c $(INC_DIR)/server.h $(INC_DIR)/vfs.h
$(OBJ_DIR)/main_client.o: $(SRC_DIR)/main_client.c $(INC_DIR)/client.h
