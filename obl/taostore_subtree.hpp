#ifndef TAOSTORE_SUBTREE_H
#define TAOSTORE_SUBTREE_H

#include "obl/types.h"
#include "obl/taostore_types.hpp"
#include "obl/oram.h"
#include "obl/taoram.h"

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
        std::uint8_t lvl;
        //todo spinlock
        pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;
        obl_aes_gcm_128bit_tag_t mac;
        obl_aes_gcm_128bit_tag_t sibling_mac;
        block_t  *payload;

        node()
        {
            lvl = 0;
            std::memset(mac, 0x00, sizeof(obl_aes_gcm_128bit_tag_t));
            std::memset(sibling_mac, 0x00, sizeof(obl_aes_gcm_128bit_tag_t));
        }
        node(size_t size):node()
        {
            payload = (block_t*) malloc(sizeof(uint8_t) * size);
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
        node *root;
        pthread_rwlock_t tree_rw_lock = PTHREAD_RWLOCK_INITIALIZER;
        size_t node_size;

        //write_queue
        //hashmap dei nodi leaf

        taostore_subtree(size_t _node_size, std::uint8_t*_merkle_root, std::uint8_t* _data)
        {
            node_size = _node_size;
            init(_merkle_root, _data);
        }

        void init(std::uint8_t *_merkle_root, std::uint8_t* _data)
        {
            root = new node(node_size);
            memcpy (root->mac, _merkle_root, sizeof(obl_aes_gcm_128bit_tag_t));
            root->lvl = 0;
            root->parent = nullptr;
            memcpy (root->payload, _data, node_size);
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