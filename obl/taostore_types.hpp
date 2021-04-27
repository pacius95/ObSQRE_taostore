#ifndef TAOSTORE_TYPES_H
#define TAOSTORE_TYPES_H

#include "obl/types.h"

#include <pthread.h>
#include <cstring>
#include <atomic>
#include <memory>
#include <cstdint>

namespace obl
{
    typedef std::int32_t leaf_id;
    typedef std::int32_t block_id;

    struct taostore_block_t
    {
        block_id bid;
        leaf_id lid;
        std::uint8_t payload[];
    };

    struct taostore_bucket_t
    {
        obl_aes_gcm_128bit_iv_t iv;
        bool reach_l, reach_r;
        obl_aes_gcm_128bit_tag_t mac __attribute__((aligned(8)));
        // since payload is going to be a multiple of 16 bytes, the struct will be memory aligned!
        std::uint8_t payload[];
    };

    struct taostore_request_t
    {
        std::uint8_t *data_in;
        leaf_id lif;
        leaf_id next_lif;
        std::uint8_t *data_out;
        block_id bid;
        bool res_ready;
        pthread_mutex_t cond_mutex;
        pthread_cond_t serializer_res_ready;
    };

    struct taostore_p_request_t
    {
        std::uint8_t *data_in;
        block_id bid;
        bool fake;
        bool handled;
        std::uint8_t *data_out;
        bool res_ready;
        std::int32_t id;
        pthread_mutex_t cond_mutex;
        pthread_cond_t serializer_res_ready;
    };

    typedef taostore_block_t block_t;
    typedef taostore_bucket_t bucket_t;
    typedef taostore_request_t request_t;
    typedef taostore_p_request_t request_p_t;

    struct node
    {
        pthread_rwlock_t lk = PTHREAD_RWLOCK_INITIALIZER;
        pthread_mutex_t wb_lk = PTHREAD_MUTEX_INITIALIZER;
        auth_data_t adata;
        std::shared_ptr<node> child_l;
        std::shared_ptr<node> child_r;
        std::shared_ptr<node> parent;
        std::atomic<bool> valid;
        std::uint8_t *payload;

        node()
        {
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            valid = false;
            std::memset(&adata, 0x00, sizeof(auth_data_t));
        }
        node(std::size_t size) : node()
        {
            payload = new std::uint8_t[size];
        }
        ~node()
        {
            delete[] payload;
            child_l = nullptr;
            child_r = nullptr;
            parent = nullptr;
            pthread_rwlock_destroy(&lk);
            pthread_mutex_destroy(&wb_lk);
        }
        int trylock()
        {
            return pthread_rwlock_trywrlock(&lk);
        }
        int lock()
        {
            return pthread_rwlock_wrlock(&lk);
        }
        int r_lock()
        {
            return pthread_rwlock_rdlock(&lk);
        }
        int unlock()
        {
            return pthread_rwlock_unlock(&lk);
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

} // namespace obl

#endif //TAOSTORE_TYPES_H