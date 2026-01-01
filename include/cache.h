/**
 * @file cache.h
 * @brief LRU块缓存头文件
 */

#ifndef CACHE_H
#define CACHE_H

#include "common.h"

/*============================================================================
 * 缓存常量
 *============================================================================*/

#define CACHE_SIZE          (16 * 1024 * 1024)  // 缓存大小: 16MB
#define CACHE_BLOCK_COUNT   (CACHE_SIZE / BLOCK_SIZE)  // 缓存块数

/*============================================================================
 * 缓存项结构
 *============================================================================*/

typedef struct CacheEntry {
    uint32_t block_id;                  // 块ID
    uint8_t *data;                      // 块数据
    bool valid;                         // 有效标志
    bool dirty;                         // 脏标志
    
    struct CacheEntry *prev;            // LRU链表前驱
    struct CacheEntry *next;            // LRU链表后继
    struct CacheEntry *hash_next;       // 哈希链表后继
} CacheEntry;

/*============================================================================
 * 缓存上下文结构
 *============================================================================*/

typedef struct {
    CacheEntry *entries;                // 缓存项数组
    CacheEntry *hash_table[CACHE_BLOCK_COUNT]; // 哈希表
    
    CacheEntry *lru_head;               // LRU头(最近使用)
    CacheEntry *lru_tail;               // LRU尾(最久未用)
    
    int cached_count;                   // 已缓存块数
    uint64_t hits;                      // 命中次数
    uint64_t misses;                    // 未命中次数
    
    pthread_mutex_t lock;               // 缓存锁
    
    // 磁盘IO回调函数
    int (*read_block)(void *ctx, uint32_t block_id, void *buf);
    int (*write_block)(void *ctx, uint32_t block_id, const void *buf);
    void *io_ctx;                       // IO上下文
} BlockCache;

/*============================================================================
 * 缓存函数声明
 *============================================================================*/

// 初始化和销毁
int cache_init(BlockCache *cache,
               int (*read_block)(void *, uint32_t, void *),
               int (*write_block)(void *, uint32_t, const void *),
               void *io_ctx);
void cache_destroy(BlockCache *cache);

// 读写操作
int cache_read(BlockCache *cache, uint32_t block_id, void *buf);
int cache_write(BlockCache *cache, uint32_t block_id, const void *buf);

// 缓存管理
int cache_flush(BlockCache *cache);
int cache_flush_block(BlockCache *cache, uint32_t block_id);
int cache_invalidate(BlockCache *cache, uint32_t block_id);
void cache_clear(BlockCache *cache);

// 统计信息
double cache_hit_rate(BlockCache *cache);
void cache_print_stats(BlockCache *cache);

#endif // CACHE_H
