#ifndef TAOSTORE_SUBTREE_H
#define TAOSTORE_SUBTREE_H

#include "obl/types.h"
#include "obl/taostore_types.hpp"
#include "obl/oassert.h"

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

#ifdef SGX_ENCLAVE_ENABLED
#define flex flexible_array<bucket_t, sgx_host_allocator>
#else
#define flex flexible_array<bucket_t>
#endif
namespace obl
{
    struct node
    {
    public:
        node *child_l;
        node *child_r;
        node *parent;
        pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;
        std::uint64_t local_timestamp;
        auth_data_t adata;
        std::uint8_t *payload;

        node()
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            local_timestamp = 0;
            std::memset(&adata, 0x00, sizeof(auth_data_t));
        }
        node(size_t size) : node()
        {
            payload = new std::uint8_t[size];
        }
        node(size_t size, std::uint64_t timestamp) : node()
        {
            local_timestamp = timestamp;
            payload = new std::uint8_t[size];
        }

        ~node()
        {
            pthread_mutex_destroy(&lk);
            std::memset(&adata, 0x00, sizeof(auth_data_t));
            delete payload;
            child_l = nullptr;
            child_r = nullptr;
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
        std::queue<leaf_id> write_queue; //paths and leaf pointers
        pthread_rwlock_t tree_rw_lock = PTHREAD_RWLOCK_INITIALIZER;
        pthread_mutex_t write_q_lk = PTHREAD_MUTEX_INITIALIZER;
        size_t node_size;
        node *root;
        int L;

        taostore_subtree()
        {
            L = 0;
            root = nullptr;
        }
        void init(size_t _node_size, std::uint8_t *_data, int _L)
        {

            L = _L;
            node_size = _node_size;
            root = new node(node_size, 0);
            memcpy(root->payload, _data, node_size);
        }

        void insert_write_queue(leaf_id T)
        {
            pthread_mutex_lock(&write_q_lk);
            write_queue.push(T);
            pthread_mutex_unlock(&write_q_lk);
        }
        leaf_id *get_pop_queue(int K)
        {
            leaf_id *temp = new leaf_id[K];
            pthread_mutex_lock(&write_q_lk);
            for (int i = 0; i < K; i++)
            {
                temp[i] = write_queue.front();
                //fetch and pop
                write_queue.pop();
            }
            pthread_mutex_unlock(&write_q_lk);
            return temp;
        }

        std::map<leaf_id, node *> update_valid(leaf_id *_paths, int K, flex &tree)
        {
            node *reference_node, *old_reference_node;
            std::map<leaf_id, node *> nodes_map; //l_index and leaf_pointer
            bool reachable;
            leaf_id paths;
            leaf_id l_index;
            for (int i = 0; i < K; i++)
            { //iterate over paths
                reachable = true;
                reference_node = root;
                paths = _paths[i];
                l_index = 0;
                for (int j = 0; j < L && reference_node != nullptr; j++)
                {                         //iterate on levels
                    if ((paths >> j) & 1) // if you take the right path
                    {
                        reference_node->adata.valid_l = reachable && reference_node->adata.valid_l;
                        reachable = reachable && reference_node->adata.valid_r;
                        reference_node->adata.valid_r = true; // this marks the path as already fetched, and thus valid
                    }
                    else
                    {                                                                               // else
                        reference_node->adata.valid_r = reachable && reference_node->adata.valid_r; // this serves as initialization for initial dummy values
                        reachable = reachable && reference_node->adata.valid_l;                     // this propagates reachability
                        reference_node->adata.valid_l = true;
                    }
                    tree[l_index].reach_l = reference_node->adata.valid_l;
                    tree[l_index].reach_r = reference_node->adata.valid_r;
                    old_reference_node = reference_node;
                    reference_node = (paths >> j) & 1 ? old_reference_node->child_r : old_reference_node->child_l;

                    l_index = (l_index << 1) + 1 + ((paths >> j) & 1);
                }
                if (reference_node != nullptr)
                {
                    reference_node->adata.valid_l = false;
                    reference_node->adata.valid_r = false;
                    tree[l_index].reach_l = false;
                    tree[l_index].reach_r = false;
                    nodes_map[l_index] = reference_node;
                }
            }
            return nodes_map;
        }

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