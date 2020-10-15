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

namespace obl
{ 
    class node
    {
    public:
        node *child_l;
        node *child_r;
        node *parent;
//        pthread_mutex_t lk = PTHREAD_MUTEX_INITIALIZER;
        pthread_spinlock_t lk;
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
            pthread_spin_init(&lk, PTHREAD_PROCESS_SHARED);
        }
        node(size_t size, std::uint64_t timestamp, std::int64_t l_index)
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            this->l_index = l_index;
            this->local_timestamp = timestamp;
            adata = new auth_data_t;
            payload = (block_t *)new std::uint8_t[size];
            std::memset(adata, 0x00, sizeof(auth_data_t));
            pthread_spin_init(&lk, PTHREAD_PROCESS_SHARED);        
        }

        node(const node &_node, size_t size)
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            this->l_index = _node.l_index;
            this->local_timestamp = _node.local_timestamp;
            adata = new auth_data_t(*_node.adata);
            payload = (block_t *)new std::uint8_t[size];
            std::memcpy(payload, _node.payload, size);
            pthread_spin_init(&lk, PTHREAD_PROCESS_SHARED);
  
        }

        ~node()
        {
            //pthread_mutex_destroy(&lk);
            assert (child_l == nullptr);
            assert (child_r == nullptr);
            pthread_spin_destroy(&lk);
            delete adata;
            delete payload;
        }
        int lock()
        {
            //return pthread_mutex_lock(&lk);
            return pthread_spin_lock(&lk);
        }
        int unlock()
        {
            //return pthread_mutex_unlock(&lk);
            return pthread_spin_unlock(&lk);
        }
        void set_auth(auth_data_t *_auth)
        {
            memcpy(adata, _auth, sizeof(auth_data_t));
        }
    };

    struct taostore_write_queue_element_t 
	{
		leaf_id T;
		node * n;
	};
	typedef taostore_write_queue_element_t write_queue_t;

    class taostore_subtree
    {

    public:
        std::queue<write_queue_t> write_queue; //paths and leaf pointers
        obl_aes_gcm_128bit_tag_t merkle_root;
        node *root;
        pthread_rwlock_t tree_rw_lock = PTHREAD_RWLOCK_INITIALIZER;
        pthread_spinlock_t write_q_lk;      //spin inizializer
        pthread_spinlock_t leaf_pointer_lk; //spin inizializer
        size_t node_size;
        int L;

        taostore_subtree(size_t _node_size, std::uint8_t *_merkle_root, std::uint8_t *_data, int L)
        {
            node_size = _node_size;
            this->L = L;
            init(_merkle_root, _data);
        }

        void init(std::uint8_t *_merkle_root, std::uint8_t *_data)
        {
            root = new node(node_size, 0, 0);
            memcpy(merkle_root, _merkle_root, sizeof(obl_aes_gcm_128bit_tag_t));
            memcpy(root->payload, _data, node_size);

            pthread_spin_init(&write_q_lk, PTHREAD_PROCESS_SHARED);
            pthread_spin_init(&leaf_pointer_lk, PTHREAD_PROCESS_SHARED);
        }

 /*
        void insert_leaf_pointer(leaf_id path, node *_leaf)
        {
            pthread_spin_lock(&leaf_pointer_lk);
            leaf_map[path] = _leaf;
            pthread_spin_unlock(&leaf_pointer_lk);
        }
        int remove_leaf_pointer(leaf_id path)
        {
            pthread_spin_lock(&leaf_pointer_lk);
            int ret = leaf_map.erase(path);
            pthread_spin_unlock(&leaf_pointer_lk);
            return ret;
        }
                void copy_path(write_queue_t *_paths, int K, taostore_subtree *tree)
        {
            node *reference_node, *old_reference_node;
            node *reference_node_o, *old_reference_node_o;
            memcpy(root->adata, tree->root->adata, sizeof(auth_data_t));
            std::int64_t l_index;
            leaf_id paths;

            for (int i = 0; i < K; i++)
            { //iterate over paths
                old_reference_node = root;
                old_reference_node_o = tree->root;
                l_index = 0;
                paths = _paths[i].T;
                for (int j = 1; j <= L && old_reference_node_o != nullptr; j++)
                { //iterate on levels

                    reference_node = (paths >> (j - 1)) & 1 ? old_reference_node->child_r : old_reference_node->child_l;
                    reference_node_o = (paths >> (j - 1)) & 1 ? old_reference_node_o->child_r : old_reference_node_o->child_l;
                    if (reference_node_o != nullptr && reference_node == nullptr)
                    {
                        (paths >> (j - 1)) & 1 ? old_reference_node->child_r = new node(*reference_node_o, node_size) : old_reference_node->child_l = new node(*reference_node_o, node_size);
                        reference_node = (paths >> (j - 1)) & 1 ? old_reference_node->child_r : old_reference_node->child_l;
                        reference_node->parent = old_reference_node;
                    }
                    old_reference_node = reference_node;
                    old_reference_node_o = reference_node_o;
                    l_index = (l_index << 1) + 1 + ((paths >> (j - 1)) & 1);
                }
                if (old_reference_node_o != nullptr)
                    insert_leaf_pointer(l_index, reference_node);
            }
        }
        */
        void insert_write_queue(write_queue_t T)
        {
            pthread_spin_lock(&write_q_lk);
            write_queue.push(T);
            pthread_spin_unlock(&write_q_lk);
        }
        write_queue_t* get_pop_queue(size_t K)
        {
            write_queue_t *temp = new write_queue_t[K];
            pthread_spin_lock(&write_q_lk);
            for (int i = 0; i < K; i++) {
			    temp[i] =  write_queue.front();; //fetch and pop
                write_queue.pop();
            }
            pthread_spin_unlock(&write_q_lk);
            return temp;
        }

        std::map<leaf_id, node *> update_valid(write_queue_t *_paths, int K)
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
                paths = _paths[i].T;
                l_index = 0;
                for (int j = 0; j < L && reference_node != nullptr; j++)
                { //iterate on levels
                    if ((paths >> j) & 1) // if you take the right path
                    {
                        reference_node->adata->valid_l = reachable && reference_node->adata->valid_l;
                        reachable = reachable && reference_node->adata->valid_r;
                        reference_node->adata->valid_r = true; // this marks the path as already fetched, and thus valid
                    }
                    else
                    {                                                                                 // else
                        reference_node->adata->valid_r = reachable && reference_node->adata->valid_r; // this serves as initialization for initial dummy values
                        reachable = reachable && reference_node->adata->valid_l;                      // this propagates reachability
                        reference_node->adata->valid_l = true;
                    }
                    old_reference_node = reference_node;
                    reference_node = (paths >> j) & 1 ? old_reference_node->child_r : old_reference_node->child_l;

                    l_index = (l_index << 1) + 1 + ((paths >> j) & 1);
                }
                if (reference_node != nullptr)
                {
                    reference_node->adata->valid_l = false;
                    reference_node->adata->valid_r = false;
                    nodes_map[l_index] = reference_node;
                }
            }
            return nodes_map;
        }
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