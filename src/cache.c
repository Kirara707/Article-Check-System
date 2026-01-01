/**
 * @file cache.c
 * @brief LRU块缓存实现
 */

#include "../include/cache.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*============================================================================
 * 内部辅助函数
 *============================================================================*/

/**
 * 计算块ID的哈希值
 */
static inline uint32_t cache_hash(uint32_t block_id) {
    return block_id % CACHE_BLOCK_COUNT;
}

/**
 * 将缓存项移到LRU链表头部(最近使用)
 */
static void lru_move_to_head(BlockCache *cache, CacheEntry *entry) {
    if (entry == cache->lru_head) {
        return;  // 已经在头部
    }
    
    // 从当前位置移除
    if (entry->prev) {
        entry->prev->next = entry->next;
    }
    if (entry->next) {
        entry->next->prev = entry->prev;
    }
    if (entry == cache->lru_tail) {
        cache->lru_tail = entry->prev;
    }
    
    // 插入头部
    entry->prev = NULL;
    entry->next = cache->lru_head;
    if (cache->lru_head) {
        cache->lru_head->prev = entry;
    }
    cache->lru_head = entry;
    
    if (!cache->lru_tail) {
        cache->lru_tail = entry;
    }
}

/**
 * 从哈希表中查找缓存项
 */
static CacheEntry* cache_find(BlockCache *cache, uint32_t block_id) {
    uint32_t hash = cache_hash(block_id);
    CacheEntry *entry = cache->hash_table[hash];
    
    while (entry) {
        if (entry->valid && entry->block_id == block_id) {
            return entry;
        }
        entry = entry->hash_next;
    }
    
    return NULL;
}

/**
 * 添加到哈希表
 */
static void cache_hash_add(BlockCache *cache, CacheEntry *entry) {
    uint32_t hash = cache_hash(entry->block_id);
    entry->hash_next = cache->hash_table[hash];
    cache->hash_table[hash] = entry;
}

/**
 * 从哈希表中移除
 */
static void cache_hash_remove(BlockCache *cache, CacheEntry *entry) {
    uint32_t hash = cache_hash(entry->block_id);
    
    CacheEntry **pp = &cache->hash_table[hash];
    while (*pp) {
        if (*pp == entry) {
            *pp = entry->hash_next;
            entry->hash_next = NULL;
            return;
        }
        pp = &(*pp)->hash_next;
    }
}

/**
 * 淘汰最久未使用的缓存项
 */
static CacheEntry* cache_evict(BlockCache *cache) {
    CacheEntry *victim = cache->lru_tail;
    
    if (!victim) {
        return NULL;
    }
    
    // 如果是脏块，先写回
    if (victim->dirty) {
        if (cache->write_block) {
            cache->write_block(cache->io_ctx, victim->block_id, victim->data);
        }
        victim->dirty = false;
    }
    
    // 从哈希表移除
    cache_hash_remove(cache, victim);
    
    victim->valid = false;
    cache->cached_count--;
    
    return victim;
}

/*============================================================================
 * 公共接口
 *============================================================================*/

/**
 * 初始化缓存
 */
int cache_init(BlockCache *cache,
               int (*read_block)(void *, uint32_t, void *),
               int (*write_block)(void *, uint32_t, const void *),
               void *io_ctx) {
    if (!cache) {
        return -1;
    }
    
    memset(cache, 0, sizeof(BlockCache));
    
    cache->read_block = read_block;
    cache->write_block = write_block;
    cache->io_ctx = io_ctx;
    
    pthread_mutex_init(&cache->lock, NULL);
    
    // 分配缓存项数组
    cache->entries = calloc(CACHE_BLOCK_COUNT, sizeof(CacheEntry));
    if (!cache->entries) {
        return -1;
    }
    
    // 为每个缓存项分配数据缓冲区
    for (int i = 0; i < CACHE_BLOCK_COUNT; i++) {
        cache->entries[i].data = malloc(BLOCK_SIZE);
        if (!cache->entries[i].data) {
            // 清理已分配的内存
            for (int j = 0; j < i; j++) {
                free(cache->entries[j].data);
            }
            free(cache->entries);
            return -1;
        }
        cache->entries[i].valid = false;
    }
    
    LOG_I("Block cache initialized: %d entries, %d KB",
          CACHE_BLOCK_COUNT, CACHE_SIZE / 1024);
    
    return 0;
}

/**
 * 销毁缓存
 */
void cache_destroy(BlockCache *cache) {
    if (!cache) return;
    
    // 刷新所有脏块
    cache_flush(cache);
    
    // 释放内存
    if (cache->entries) {
        for (int i = 0; i < CACHE_BLOCK_COUNT; i++) {
            if (cache->entries[i].data) {
                free(cache->entries[i].data);
            }
        }
        free(cache->entries);
        cache->entries = NULL;
    }
    
    pthread_mutex_destroy(&cache->lock);
    
    LOG_I("Block cache destroyed");
}

/**
 * 读取块
 */
int cache_read(BlockCache *cache, uint32_t block_id, void *buf) {
    if (!cache || !buf) {
        return -1;
    }
    
    pthread_mutex_lock(&cache->lock);
    
    // 查找缓存
    CacheEntry *entry = cache_find(cache, block_id);
    
    if (entry) {
        // 缓存命中
        cache->hits++;
        memcpy(buf, entry->data, BLOCK_SIZE);
        lru_move_to_head(cache, entry);
        pthread_mutex_unlock(&cache->lock);
        return 0;
    }
    
    // 缓存未命中
    cache->misses++;
    
    // 查找空闲缓存项或淘汰
    CacheEntry *new_entry = NULL;
    
    if (cache->cached_count < CACHE_BLOCK_COUNT) {
        // 查找空闲项
        for (int i = 0; i < CACHE_BLOCK_COUNT; i++) {
            if (!cache->entries[i].valid) {
                new_entry = &cache->entries[i];
                break;
            }
        }
    }
    
    if (!new_entry) {
        // 淘汰最久未使用的
        new_entry = cache_evict(cache);
    }
    
    if (!new_entry) {
        pthread_mutex_unlock(&cache->lock);
        // 直接读取
        return cache->read_block(cache->io_ctx, block_id, buf);
    }
    
    // 从磁盘读取
    int ret = cache->read_block(cache->io_ctx, block_id, new_entry->data);
    if (ret != 0) {
        pthread_mutex_unlock(&cache->lock);
        return ret;
    }
    
    // 设置缓存项
    new_entry->block_id = block_id;
    new_entry->valid = true;
    new_entry->dirty = false;
    
    // 添加到哈希表和LRU链表
    cache_hash_add(cache, new_entry);
    lru_move_to_head(cache, new_entry);
    cache->cached_count++;
    
    memcpy(buf, new_entry->data, BLOCK_SIZE);
    
    pthread_mutex_unlock(&cache->lock);
    return 0;
}

/**
 * 写入块
 */
int cache_write(BlockCache *cache, uint32_t block_id, const void *buf) {
    if (!cache || !buf) {
        return -1;
    }
    
    pthread_mutex_lock(&cache->lock);
    
    // 查找缓存
    CacheEntry *entry = cache_find(cache, block_id);
    
    if (entry) {
        // 更新缓存
        memcpy(entry->data, buf, BLOCK_SIZE);
        entry->dirty = true;
        lru_move_to_head(cache, entry);
        pthread_mutex_unlock(&cache->lock);
        return 0;
    }
    
    // 查找空闲缓存项或淘汰
    CacheEntry *new_entry = NULL;
    
    if (cache->cached_count < CACHE_BLOCK_COUNT) {
        for (int i = 0; i < CACHE_BLOCK_COUNT; i++) {
            if (!cache->entries[i].valid) {
                new_entry = &cache->entries[i];
                break;
            }
        }
    }
    
    if (!new_entry) {
        new_entry = cache_evict(cache);
    }
    
    if (!new_entry) {
        pthread_mutex_unlock(&cache->lock);
        // 直接写入
        return cache->write_block(cache->io_ctx, block_id, buf);
    }
    
    // 设置缓存项
    new_entry->block_id = block_id;
    memcpy(new_entry->data, buf, BLOCK_SIZE);
    new_entry->valid = true;
    new_entry->dirty = true;
    
    cache_hash_add(cache, new_entry);
    lru_move_to_head(cache, new_entry);
    cache->cached_count++;
    
    pthread_mutex_unlock(&cache->lock);
    return 0;
}

/**
 * 刷新所有脏块
 */
int cache_flush(BlockCache *cache) {
    if (!cache) return -1;
    
    pthread_mutex_lock(&cache->lock);
    
    int flushed = 0;
    for (int i = 0; i < CACHE_BLOCK_COUNT; i++) {
        CacheEntry *entry = &cache->entries[i];
        if (entry->valid && entry->dirty) {
            if (cache->write_block) {
                cache->write_block(cache->io_ctx, entry->block_id, entry->data);
            }
            entry->dirty = false;
            flushed++;
        }
    }
    
    pthread_mutex_unlock(&cache->lock);
    
    LOG_D("Flushed %d dirty blocks", flushed);
    return 0;
}

/**
 * 刷新单个块
 */
int cache_flush_block(BlockCache *cache, uint32_t block_id) {
    if (!cache) return -1;
    
    pthread_mutex_lock(&cache->lock);
    
    CacheEntry *entry = cache_find(cache, block_id);
    if (entry && entry->dirty) {
        if (cache->write_block) {
            cache->write_block(cache->io_ctx, block_id, entry->data);
        }
        entry->dirty = false;
    }
    
    pthread_mutex_unlock(&cache->lock);
    return 0;
}

/**
 * 使缓存项失效
 */
int cache_invalidate(BlockCache *cache, uint32_t block_id) {
    if (!cache) return -1;
    
    pthread_mutex_lock(&cache->lock);
    
    CacheEntry *entry = cache_find(cache, block_id);
    if (entry) {
        // 如果是脏块，先写回
        if (entry->dirty && cache->write_block) {
            cache->write_block(cache->io_ctx, block_id, entry->data);
        }
        
        cache_hash_remove(cache, entry);
        entry->valid = false;
        entry->dirty = false;
        cache->cached_count--;
    }
    
    pthread_mutex_unlock(&cache->lock);
    return 0;
}

/**
 * 清空缓存
 */
void cache_clear(BlockCache *cache) {
    if (!cache) return;
    
    pthread_mutex_lock(&cache->lock);
    
    // 刷新所有脏块
    for (int i = 0; i < CACHE_BLOCK_COUNT; i++) {
        CacheEntry *entry = &cache->entries[i];
        if (entry->valid && entry->dirty && cache->write_block) {
            cache->write_block(cache->io_ctx, entry->block_id, entry->data);
        }
        entry->valid = false;
        entry->dirty = false;
    }
    
    // 清空哈希表
    memset(cache->hash_table, 0, sizeof(cache->hash_table));
    
    cache->lru_head = NULL;
    cache->lru_tail = NULL;
    cache->cached_count = 0;
    
    pthread_mutex_unlock(&cache->lock);
    
    LOG_I("Cache cleared");
}

/**
 * 获取缓存命中率
 */
double cache_hit_rate(BlockCache *cache) {
    if (!cache) return 0.0;
    
    uint64_t total = cache->hits + cache->misses;
    if (total == 0) return 0.0;
    
    return (double)cache->hits / total;
}

/**
 * 打印缓存统计
 */
void cache_print_stats(BlockCache *cache) {
    if (!cache) return;
    
    printf("=== Cache Statistics ===\n");
    printf("  Cached blocks: %d / %d\n", cache->cached_count, CACHE_BLOCK_COUNT);
    printf("  Hits:          %lu\n", cache->hits);
    printf("  Misses:        %lu\n", cache->misses);
    printf("  Hit rate:      %.2f%%\n", cache_hit_rate(cache) * 100);
    printf("========================\n");
}
