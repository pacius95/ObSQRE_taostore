#include "obl/taostore_subtree.h"

#ifdef SGX_ENCLAVE_ENABLED
    #include "obl/sgx_host_allocator.hpp"
    #define printf(a,b) ocall_stdout(a,b);
    #define flex flexible_array<bucket_t, sgx_host_allocator>
#else
    #define flex flexible_array<bucket_t>
#endif

namespace obl
{
        taostore_subtree::taostore_subtree()
        {
            L = 0;
            std::atomic_init(&nodes_count, 0);
            root = nullptr;
        }
        taostore_subtree::~taostore_subtree()
        {
            delete root;
        }
        void taostore_subtree::init(size_t _node_size, std::uint8_t *_data, int _L)
        {
            L = _L;
            root = new node(_node_size);
            memcpy(root->payload, _data, _node_size);
        }
        node * taostore_subtree::getroot()
        {
            return root;
        }

        void taostore_subtree::insert_write_queue(leaf_id T)
        {
            write_queue.enqueue(T);
        }

        void taostore_subtree::get_pop_queue(int K, leaf_id *temp)
        {
            write_queue.try_dequeue_bulk(temp, K);
        }

        void taostore_subtree::update_valid_2(leaf_id *_paths, int K, flex &tree, std::unordered_map<std::int64_t, node *> &nodes_map)
        {
            node *reference_node;
            node *old_reference_node;
            bool reachable;
            int j=0;
            leaf_id paths;
            std::int64_t l_index;
            for (int i = 0; i < K; i++)
            {
                reference_node = root;
                paths = _paths[i];
                l_index = 0;
                for (j = 0; j < L && reference_node != nullptr; j++)
                {                        
                    reference_node = (paths >> j) & 1 ? reference_node->child_r : reference_node->child_l;
                    l_index = (l_index << 1) + 1 + ((paths >> j) & 1);
                }
                if (j==L && reference_node != nullptr && reference_node->wb_trylock() == 0)
                    nodes_map[l_index] = reference_node;
            }
        }

        void taostore_subtree::update_valid(leaf_id *_paths, int K, flex &tree, std::unordered_map<std::int64_t, node *> &nodes_map)
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
                {//iterate on levels
                    if ((paths >> j) & 1) // if you take the right path
                    {
                        reference_node->adata.valid_l = reachable & reference_node->adata.valid_l;
                        reachable = reachable & reference_node->adata.valid_r;
                        reference_node->adata.valid_r = true; // this marks the path as already fetched, and thus valid
                    }
                    else
                    {                                                                               // else
                        reference_node->adata.valid_r = reachable & reference_node->adata.valid_r; // this serves as initialization for initial dummy values
                        reachable = reachable & reference_node->adata.valid_l;                     // this propagates reachability
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

} // namespace obl