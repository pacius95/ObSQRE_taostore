#ifndef TAOSTORE_SUBTREE_H
#define TAOSTORE_SUBTREE_H

#include "obl/types.h"
#include "obl/taostore_types.hpp"
#include "obl/oassert.h"
#include "concurrentqueue.h"

#include <queue>
#include <unordered_map>

#include <pthread.h>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <utility>
#include <memory>
#include <atomic>

#ifdef SGX_ENCLAVE_ENABLED
#define flex flexible_array<bucket_t, sgx_host_allocator>
#else
#define flex flexible_array<bucket_t>
#endif
namespace obl
{
    struct node
    {
        pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_t wb_lk = PTHREAD_MUTEX_INITIALIZER;
        auth_data_t adata;
        std::uint64_t local_timestamp;
        node *child_l;
        node *child_r;
        node *parent;
        std::uint8_t *payload;

        node()
        {
            local_timestamp = 0;
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            std::memset(&adata, 0x00, sizeof(auth_data_t));
        }
        node(std::size_t size) : node()
        {
            payload = new std::uint8_t[size];
        }
        node(std::size_t size, std::uint64_t timestamp) : node()
        {
            local_timestamp = timestamp;
            payload = new std::uint8_t[size];
        }

        ~node()
        {
            pthread_mutex_destroy(&lk);
            pthread_mutex_destroy(&wb_lk);
            delete child_l;
            delete child_r;
            delete[] payload;
        }
        int trylock()
        {
            return pthread_mutex_trylock(&lk);
        }
        int lock()
        {
            return pthread_mutex_lock(&lk);
        }
        int unlock()
        {
            return pthread_mutex_unlock(&lk);
        }

        int wb_trylock()
        {
            return pthread_mutex_trylock(&wb_lk);
        }
        int wb_lock()
        {
            return pthread_mutex_lock(&wb_lk);
        }
        int wb_unlock()
        {
            return pthread_mutex_unlock(&wb_lk);
        }
    };
    struct write_elem
    {
        leaf_id T;
        node *ptr;
    };
    class taostore_subtree
    {

    private:
        // std::queue<leaf_id> write_queue; //paths and leaf pointers
        moodycamel::ConcurrentQueue<leaf_id> write_queue;
        pthread_mutex_t write_q_lk = PTHREAD_MUTEX_INITIALIZER;
        node *root;
        std::atomic_int32_t nodes_count;
        int L;

    public:
        taostore_subtree()
        {
            L = 0;
            std::atomic_init(&nodes_count, 0);
            root = nullptr;
        }
        ~taostore_subtree()
        {
            pthread_mutex_destroy(&write_q_lk);
            delete root;
        }
        void newnode()
        {
            nodes_count++;
        }
        void removenode()
        {
            nodes_count--;
        }
        int get_nodes_count()
        {
            return nodes_count;
        }
        void init(size_t _node_size, std::uint8_t *_data, int _L)
        {
            L = _L;
            root = new node(_node_size);
            memcpy(root->payload, _data, _node_size);
        }
        node *getroot()
        {
            return root;
        }

        // void insert_write_queue(leaf_id T)
        // {
        //     pthread_mutex_lock(&write_q_lk);
        //     write_queue.push(T);
        //     pthread_mutex_unlock(&write_q_lk);
        // }
        void insert_write_queue(leaf_id T)
        {
            write_queue.enqueue(T);
        }
        // void get_pop_queue(int K, leaf_id *temp)
        // {
        //     pthread_mutex_lock(&write_q_lk);
        //     for (int i = 0; i < K; i++)
        //     {
        //         temp[i] = write_queue.front();
        //         //fetch and pop
        //         write_queue.pop();
        //     }
        //     pthread_mutex_unlock(&write_q_lk);
        // }
        void get_pop_queue(int K, leaf_id *temp)
        {
            write_queue.try_dequeue_bulk(temp, K);
        }

        void update_valid(leaf_id *_paths, int K, flex &tree, std::unordered_map<std::int64_t, node *> &nodes_map)
        {
            node *reference_node;
            node *old_reference_node;
            bool reachable;
            leaf_id paths;
            std::int64_t l_index;
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
                if (reference_node != nullptr && reference_node->wb_trylock() == 0)
                {
                    reference_node->adata.valid_l = false;
                    reference_node->adata.valid_r = false;
                    tree[l_index].reach_l = false;
                    tree[l_index].reach_r = false;
                    nodes_map[l_index] = reference_node;
                }
            }
        }
    };

} // namespace obl
#endif //TAOSTORE_SUBTREE_H