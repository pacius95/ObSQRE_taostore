#ifndef TAOSTORE_SUBTREE_H
#define TAOSTORE_SUBTREE_H

#include "obl/taostore_types.hpp"
#include "obl/oassert.h"
#include "obl/flexible_array.hpp"
#include "concurrentqueue.h"

#include <queue>
#include <unordered_map>

#include <pthread.h>
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <utility>
#include <memory>
#include <atomic>

#ifdef SGX_ENCLAVE_ENABLED
    #include "obl/sgx_host_allocator.hpp"
    #define printf(a,b) ocall_stdout(a,b);
    #define flex flexible_array<bucket_t, sgx_host_allocator>
#else
    #define flex flexible_array<bucket_t>
#endif

namespace obl
{
    class taostore_subtree
    {

    private:
        moodycamel::ConcurrentQueue<leaf_id> write_queue;
        pthread_mutex_t write_q_lk = PTHREAD_MUTEX_INITIALIZER;
        node *root;
        std::atomic_int32_t nodes_count;
        int L;

    public:
        taostore_subtree();
        ~taostore_subtree();

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

        void init(size_t _node_size, std::uint8_t *_data, int _L);
        node *getroot();

        void insert_write_queue(leaf_id T);
        void get_pop_queue(int K, leaf_id *temp);
        void update_valid(leaf_id *_paths, int K, flex &tree, std::unordered_map<std::int64_t, node *> &nodes_map);
    };

} // namespace obl
#endif //TAOSTORE_SUBTREE_H