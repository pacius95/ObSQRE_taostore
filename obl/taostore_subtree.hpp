#ifndef TAOSTORE_SUBTREE_H
#define TAOSTORE_SUBTREE_H

#include "obl/types.h"
#include "obl/taostore_types.hpp"

#include <queue>
#include <unordered_map>

#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <pthread.h>

namespace obl
{
    class node
    {
    public:
        node *child_l;
        node *child_r;
        node *parent;
        //TODO bench with spinlock
        pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;
        obl_aes_gcm_128bit_tag_t mac;
        obl_aes_gcm_128bit_tag_t sibling_mac;
        std::uint64_t local_timestamp;
        std::int64_t l_index;
        block_t  *payload;

        node()
        {
            std::memset(mac, 0x00, sizeof(obl_aes_gcm_128bit_tag_t));
            std::memset(sibling_mac, 0x00, sizeof(obl_aes_gcm_128bit_tag_t));
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
        }
        node(size_t size, std::uint64_t timestamp, std::int64_t l_index):node()
        {
            payload = (block_t*) malloc(sizeof(uint8_t) * size);
            l_index = l_index;
            local_timestamp = timestamp;
        }

        int lock()
        {
            return pthread_mutex_lock(&lk);
        }
        int unlock()
        {
            return pthread_mutex_unlock(&lk);
        }
    };

    class taostore_subtree
    {

    public:
        std::queue<leaf_id> write_queue;
        std::unordered_map<leaf_id, node *> leaf_map; 

        node *root;
        pthread_rwlock_t tree_rw_lock = PTHREAD_RWLOCK_INITIALIZER;
        size_t node_size;

        taostore_subtree(size_t _node_size, std::uint8_t*_merkle_root, std::uint8_t* _data)
        {
            node_size = _node_size;
            init(_merkle_root, _data);
        }

        void init(std::uint8_t *_merkle_root, std::uint8_t* _data)
        {
            root = new node(node_size, 0, 0);
            root->parent = nullptr;
            memcpy (root->mac, _merkle_root, sizeof(obl_aes_gcm_128bit_tag_t));
            memcpy (root->payload, _data, node_size);
            // K leaf_map.reserve(K)
        }

        void insert_leaf_pointer (leaf_id path, node *_leaf) {
            //TODO cuncurrency check
                leaf_map[path] = _leaf;
        }
        void insert_write_queue ( leaf_id T) { 
            //TODO cuncurrency check
            write_queue.push (T);
        }

        leaf_id get_write_queue () { 
            leaf_id T = write_queue.front();
            write_queue.pop();
            return T;
        }

        uint8_t* get_merkle_root() { return root->mac; }

        int read_lock()
        {
            return pthread_rwlock_rdlock(&tree_rw_lock);
        }
        int write_lock()
        {
            return pthread_rwlock_wrlock(&tree_rw_lock);
        }
        int unlock()
        {
            return pthread_rwlock_unlock(&tree_rw_lock);
        }
    };
} // namespace obl
#endif //TAOSTORE_SUBTREE_H