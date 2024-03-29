#ifndef MOSE_H
#define MOSE_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/flexible_array.hpp"
#include "obl/threadpool.h"
#include "obl/circuit.h"
#include "obl/taostore_factory.hpp"
#include "obl/taostore_circuit_2.h"
#include "obl/taostore_circuit_2_p.h"
#include "obl/taostore_p.h"

#include <atomic>

#include <wolfcrypt/aes.h>
#include <pthread.h>

#ifdef SGX_ENCLAVE_ENABLED
#include "obl/sgx_host_allocator.hpp"
#endif

namespace obl
{
    struct mose_args;
    struct shadow_mose_args_w;
    
    class mose : public tree_oram
    {
    private:
        std::size_t block_size;  // aligned block size
        std::size_t bucket_size; // aligned/padded encrypted bucket size

        unsigned int T_NUM;

        unsigned int *block_idx;
        threadpool_t *thpool;

        //global varbiable shared between threads:
        pthread_cond_t cond_sign = PTHREAD_COND_INITIALIZER;
        pthread_mutex_t cond_lock = PTHREAD_MUTEX_INITIALIZER;
        std::atomic_uint8_t barrier;

        unsigned int *chunk_sizes;
        unsigned int *chunk_idx;

        mose_args *args;

        block_id bid;
        leaf_id lif;
        std::uint8_t *data_in;
        std::uint8_t *data_out;
        leaf_id next_lif;

        tree_oram **rram;
        taostore_oram_parallel **shadow;

        //thpool methos
        static void access_wrap(void *object);
        void access_thread(int i);
        static void access_r_wrap(void *object);
        void access_r_thread(int i);
        static void access_w_wrap(void *object);
        void access_w_thread(int i);
        static void write_wrap(void *object);
        void write_thread(int i);

        static void shadow_access_wrap(void *object);
        void shadow_access_thread(shadow_mose_args_w* i);

    public:
        void set_position_map(unsigned int C);

        mose(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM);
        mose(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM, taostore_circuit_factory* fact);
        mose(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM, taostore_circuit_2_parallel_factory *fact);

        ~mose();
        
        void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);
        void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif);
        
        // split fetch and eviction phases of the access method
        void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out);
        void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif);

        // only write block into the stash and perfom evictions
        void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
    };

    class mose_factory : public oram_factory
    {
    private:
        unsigned int Z, S, T_NUM;

    public:
        mose_factory(unsigned int Z, unsigned int S, unsigned int T_NUM)
        {
            this->Z = Z;
            this->S = S;
            this->T_NUM = T_NUM;
        }

        tree_oram *spawn_oram(std::size_t N, std::size_t B)
        {
            if (B >= (1 << 10))
            {
                return new mose(N, B, Z, S, T_NUM);
            }
            else
            {
                return new circuit_oram(N, B, Z, S);
            }
        }
        bool is_taostore() { return false; }
    };
    class asynch_mose_factory : public oram_factory
    {
    private:
        unsigned int Z, S, T_NUM;
        taostore_circuit_factory* fact;

    public:
        asynch_mose_factory(unsigned int Z, unsigned int S, unsigned int T_NUM)
        {
            this->Z = Z;
            this->S = S;
            this->T_NUM = T_NUM;
            fact = new taostore_circuit_factory(Z,S,T_NUM);
        }

        tree_oram *spawn_oram(std::size_t N, std::size_t B)
        {
            T_NUM = fact->getT_NUM();
            if (B > (1 << 9))
            {
                return new mose(N, B, Z, S, T_NUM, fact);
            }
            else
            {
                return fact->spawn_oram(N,B);
            }
        }
        bool is_taostore() { return false; }
    };

    class shadow_mose_factory : public oram_factory
    {
    private:
        unsigned int Z, S, T_NUM, moseT_NUM;
        taostore_circuit_2_parallel_factory* fact;

    public:
        shadow_mose_factory(unsigned int Z, unsigned int S, unsigned int T_NUM, unsigned int moseT_NUM)
        {
            this->Z = Z;
            this->S = S;
            this->T_NUM = T_NUM;
            this->moseT_NUM = moseT_NUM;
            this->fact = new taostore_circuit_2_parallel_factory(Z,S,T_NUM);
        }

        tree_oram *spawn_oram(std::size_t N, std::size_t B)
        {
            {
                return new mose(N, B, Z, S, moseT_NUM, fact);
            }
        }
        bool is_taostore() { return true; }
    };
} // namespace obl

#endif // MOSE_H
