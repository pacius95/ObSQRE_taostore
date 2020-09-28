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
        taostore_block_t payload[];

        node()
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            lvl = 0;
        }
        node(size_t size)
        {
            payload = malloc(sizeof(uint8_t) * size);
        }

        lock()
        {
            pthread_spin_lock(lk);
        }
        unlock()
        {
            pthread_spin_unlock(lk);
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

        taostore_subtree(size_t _node_size, obl_aes_gcm_128bit_tag_t merkle_root, uint8_t* _data)
        {
            node_size = _node_size;
            init(merkle_root, _data);
        }

        init(obl_aes_gcm_128bit_tag_t merkle_root, uint8_t* _data)
        {
            root = new node(node_size);
            root->mac = merkle_root;
            root->lvl = 0;
            root->parent = nullptr;
            root->child_r = nullptr;
            root->child_l = nullptr;
            memcpy (root->payload, _data, node_size);
        }

        obl_aes_gcm_128bit_tag_t get_merkle_root() { return root->mac; }

        read_lock()
        {
            pthread_rwlock_rdlock(&tree_rw_lock);
        }
        write_lock()
        {
            pthread_rwlock_wrlock(&tree_rw_lock);
        }
        unlock()
        {
            pthread_rwlock_unlock(&tree_rw_lock);
        }
    };
} // namespace obl
#endif //SUBTREE_HPP