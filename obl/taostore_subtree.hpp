#ifndef SUBTREE_HPP
#define SUBTREE_HPP
#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taoram.h"
#include "obl/flexible_array.hpp"

#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <pthread.h>
#include <sgx_spinlock.h>

namespace obl
{
    class node
    {
    public:
        node *child_l;
        node *child_r;
        node *parent;
        std::uint8_t lvl;
        pthread_spinlock_t lk;
        obl_aes_gcm_128bit_tag_t mac;
        obl_aes_gcm_128bit_tag_t sibling_mac;
        taostore_block_t  *payload;

        node()
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            lvl = 0;
            memcpy(mac, 0x00, sizeof(obl_aes_gcm_128bit_tag_t));
            memcpy(sibling_mac, 0x00, sizeof(obl_aes_gcm_128bit_tag_t));
        }
        node(size_t size):node()
        {
            payload = (taostore_block_t*) malloc(sizeof(uint8_t) * size);
        }

        int lock()
        {
            return pthread_spin_lock(&lk);
        }
        int unlock()
        {
            return pthread_spin_unlock(&lk);
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

        taostore_subtree(size_t _node_size, uint8_t*_merkle_root, uint8_t* _data)
        {
            node_size = _node_size;
            init(_merkle_root, _data);
        }

        void init(uint8_t *_merkle_root, uint8_t* _data)
        {
            root = new node(node_size);
            memcpy (root->mac, _merkle_root, (size_t) OBL_AESGCM_MAC_SIZE);
            root->lvl = 0;
            root->parent = nullptr;
            root->child_r = nullptr;
            root->child_l = nullptr;
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
#endif //SUBTREE_HPP