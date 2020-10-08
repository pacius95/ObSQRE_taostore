#ifndef TAOSTORE_SUBTREE_H
#define TAOSTORE_SUBTREE_H

#include "obl/types.h"
#include "obl/taostore_types.hpp"

#include <queue>
#include <unordered_map>
#include <map>

#include <cstdint>
#include <cstddef>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <iterator>
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
        std::uint64_t local_timestamp;
        std::int64_t l_index;
        auth_data_t *adata;
        block_t *payload;

        node()
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            local_timestamp = 0;
            l_index = 0;
            adata = new auth_data_t;
            std::memset(adata, 0x00, sizeof(auth_data_t));
        }
        node(size_t size, std::uint64_t timestamp, std::int64_t l_index)
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            l_index = l_index;
            local_timestamp = timestamp;
            adata = new auth_data_t;
            payload = (block_t *)new std::uint8_t[size];
            std::memset(adata, 0x00, sizeof(auth_data_t));
        }
        node(const node &_node, size_t size)
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            l_index = _node.l_index;
            local_timestamp = _node.local_timestamp;
            adata = _node.adata;
            payload = (block_t *)new std::uint8_t[size];
            std::memcpy(payload, _node.payload, size);
        }
        int lock()
        {
            return pthread_mutex_lock(&lk);
        }
        int unlock()
        {
            return pthread_mutex_unlock(&lk);
        }
        void set_auth(auth_data_t *_auth)
        {
            memcpy(adata, _auth, sizeof(auth_data_t));
        }
    };

    class taostore_subtree
    {

    public:
        std::queue<leaf_id> write_queue;

        std::map<leaf_id, node *> leaf_map; //used only in the tree copy
        obl_aes_gcm_128bit_tag_t merkle_root;
        node *root;
        pthread_rwlock_t tree_rw_lock = PTHREAD_RWLOCK_INITIALIZER;
        size_t node_size;
        std::uint8_t L;

        taostore_subtree()
        {
        }
        taostore_subtree(size_t _node_size, std::uint8_t *_merkle_root, std::uint8_t *_data, std::uint8_t L)
        {
            node_size = _node_size;
            L = L;
            init(_merkle_root, _data);
        }

        void init(std::uint8_t *_merkle_root, std::uint8_t *_data)
        {
            root = new node(node_size, 0, 0);
            memcpy(merkle_root, _merkle_root, sizeof(obl_aes_gcm_128bit_tag_t));
            memcpy(root->payload, _data, node_size);
            // K leaf_map.reserve(K)
        }

        void insert_leaf_pointer(leaf_id path, node *_leaf)
        {
            //TODO cuncurrency check
            leaf_map[path] = _leaf;
        }
        void insert_write_queue(leaf_id T)
        {
            //TODO cuncurrency check
            write_queue.push(T);
        }

        leaf_id get_pop_queue()
        {
            leaf_id T = write_queue.front();
            write_queue.pop();
            return T;
        }

        void copy_path(leaf_id *paths, int K, taostore_subtree *tree)
        {
            node *reference_node, *old_reference_node;
            node *reference_node_o, *old_reference_node_o;
            memcpy(root->adata, tree->root->adata, sizeof(auth_data_t));

            for (int i = 0; i < K; i++)
            { //iterate over paths
                old_reference_node = root;
                old_reference_node_o = tree->root;
                for (int j = 1; i <= L; i++)
                { //iterate on levels
                    reference_node = (paths[i] >> (i - 1)) & 1 ? old_reference_node->child_r : old_reference_node->child_l;
                    reference_node_o = (paths[i] >> (i - 1)) & 1 ? old_reference_node_o->child_r : old_reference_node_o->child_l;
                    if (reference_node == nullptr)
                    {
                        (paths[j] >> (i - 1)) & 1 ? old_reference_node->child_r = new node(*reference_node_o, node_size) : old_reference_node->child_l = new node(*reference_node_o, node_size);
                    }
                    reference_node->parent = old_reference_node;

                    old_reference_node = reference_node;
                    old_reference_node_o = reference_node_o;
                }
                insert_leaf_pointer(paths[i], reference_node);
            }
        };

        void update_valid(leaf_id *paths, int K)
        {
            node *reference_node, *old_reference_node;
            bool reachable;
            for (int i = 0; i < K; i++)
            { //iterate over paths
                reachable = true;
                old_reference_node = root;
                for (int j = 0; i < L; i++)
                {//iterate on levels
                    if (((paths[j] >> i) & 1) == 0) // if you take the left path
                    {
                        reference_node->adata->valid_r = reachable && reference_node->adata->valid_r; // this serves as initialization for initial dummy values
                        reachable = reachable && reference_node->adata->valid_l;        // this propagates reachability
                        reference_node->adata->valid_l = true;                          // this marks the path as already fetched, and thus valid
                    }
                    else
                    { // else
                        reference_node->adata->valid_l = reachable && reference_node->adata->valid_l;
                        reachable = reachable && reference_node->adata->valid_r;
                        reference_node->adata->valid_r = true;
                    }
                    old_reference_node = reference_node;
                    reference_node = (paths[i] >> i) & 1 ? old_reference_node->child_r : old_reference_node->child_l;
                }
                reference_node->adata->valid_l = false;
                reference_node->adata->valid_r = false;
            }
        };
        uint8_t *get_merkle_root() { return merkle_root; }

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