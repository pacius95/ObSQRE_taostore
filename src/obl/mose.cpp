#include "obl/mose.h"
#include "obl/circuit.h"
#include "obl/taostore_circuit_2.h"
#include "obl/taostore_circuit_2_p.h"
#include "obl/types.h"

#include "obl/oassert.h"

#include <cstdlib>
#include <cstring>

#define DUMMY -1
#define BOTTOM -2
#define QUEUE_SIZE 256
namespace obl
{
    struct mose_args
    {
        obl::mose *arg1;
        unsigned int i;
    };

    struct shadow_mose_args
    {
        obl::mose *arg1;
        pthread_cond_t &cond;
        pthread_mutex_t &mux;
        std::atomic_uint8_t barrier;
        block_id bid;
        std::uint8_t *data_in;
        std::uint8_t *data_out;
    };

    struct shadow_mose_args_w
    {
        shadow_mose_args *arg;
        unsigned int i;
    };

    mose::mose(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : tree_oram(N, B, Z)
    {
        // align structs to 8-bytes
        /*
			Since AES-GCM is basically an AES-CTR mode, and AES-CTR mode is a "stream-cipher",
			you actually don't need to pad everything to 16 bytes which is AES block size
		*/

        this->T_NUM = T_NUM;
        chunk_sizes = new unsigned int[T_NUM];
        chunk_idx = new unsigned int[T_NUM];

        //one thread (the first) will take care of the remainder of the division Z*block_size / T_NUM;
        //split Z*block_size in T_NUM chunk.
        //this is possible if GCM doesn't need 8 byte aligned data
        for (unsigned int i = 0; i < T_NUM; i++)
            chunk_sizes[i] = (this->B / T_NUM);
        // for (unsigned int i = 0; this->B % T_NUM; i++)
        //     chunk_sizes[i] += 1;
        chunk_sizes[0] += this->B % T_NUM;
        chunk_idx[0] = 0;
        for (unsigned int i = 1; i < T_NUM; i++)
            chunk_idx[i] = chunk_idx[i - 1] + chunk_sizes[i - 1];

        rram = new tree_oram *[T_NUM];

        args = new mose_args[T_NUM];
        for (unsigned int i = 0; i < T_NUM; i++)
            args[i] = {this, i};

        for (unsigned int i = 0; i < T_NUM; i++)
            rram[i] = new circuit_oram(N, chunk_sizes[i], Z, S);
            // rram[i] = new taostore_circuit_2(N, chunk_sizes[i], Z, S, 4);

        thpool = threadpool_create(T_NUM, QUEUE_SIZE, 0);
    }
    mose::mose(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM, taostore_circuit_factory *fact) : tree_oram(N, B, Z)
    {
        // align structs to 8-bytes
        /*
			Since AES-GCM is basically an AES-CTR mode, and AES-CTR mode is a "stream-cipher",
			you actually don't need to pad everything to 16 bytes which is AES block size
		*/
        if (B<(1<<9))
            this->T_NUM = 1;
        else if (B>=(1<<9) && B<(1<<11))
            this->T_NUM = 4;
        else if (B>=(1<<11) && B<(1<<13))
            this->T_NUM = 5;
        else
            this->T_NUM = 2;

        chunk_sizes = new unsigned int[this->T_NUM];
        chunk_idx = new unsigned int[this->T_NUM];

        //one thread (the first) will take care of the remainder of the division Z*block_size / T_NUM;
        //split Z*block_size in T_NUM chunk.
        //this is possible if GCM doesn't need 8 byte aligned data
        for (unsigned int i = 0; i < this->T_NUM; i++)
            chunk_sizes[i] = (this->B / this->T_NUM);
        // for (unsigned int i = 0; this->B % T_NUM; i++)
        //     chunk_sizes[i] += 1;
        chunk_sizes[0] += this->B % this->T_NUM;
        chunk_idx[0] = 0;
        for (unsigned int i = 1; i < this->T_NUM; i++)
            chunk_idx[i] = chunk_idx[i - 1] + chunk_sizes[i - 1];

        rram = new tree_oram *[this->T_NUM];

        args = new mose_args[this->T_NUM];
        for (unsigned int i = 0; i < this->T_NUM; i++)
            args[i] = {this, i};

        for (unsigned int i = 0; i < this->T_NUM; i++)
            // rram[i] = new circuit_oram(N, chunk_sizes[i], Z, S);
            rram[i] = fact->spawn_oram(N,chunk_sizes[i]);

        thpool = threadpool_create(T_NUM, QUEUE_SIZE, 0);
    }

    mose::mose(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM, taostore_circuit_2_parallel_factory *fact) : tree_oram(N, B, Z)
    {
        // align structs to 8-bytes
        /*
			Since AES-GCM is basically an AES-CTR mode, and AES-CTR mode is a "stream-cipher",
			you actually don't need to pad everything to 16 bytes which is AES block size
		*/

        this->T_NUM = T_NUM;
        chunk_sizes = new unsigned int[T_NUM];
        chunk_idx = new unsigned int[T_NUM];

        //one thread (the first) will take care of the remainder of the division Z*block_size / T_NUM;
        //split Z*block_size in T_NUM chunk.
        //this is possible if GCM doesn't need 8 byte aligned data
        for (unsigned int i = 0; i < T_NUM; i++)
            chunk_sizes[i] = (this->B / T_NUM);
        // for (unsigned int i = 0; this->B % T_NUM; i++)
        //     chunk_sizes[i] += 1;
        chunk_sizes[0] += this->B % T_NUM;
        chunk_idx[0] = 0;
        for (unsigned int i = 1; i < T_NUM; i++)
            chunk_idx[i] = chunk_idx[i - 1] + chunk_sizes[i - 1];

        shadow = new taostore_oram_parallel *[this->T_NUM];

        for (unsigned int i = 0; i < this->T_NUM; i++) 
            shadow[i] = (taostore_oram_parallel*) fact->spawn_oram(N,chunk_sizes[i]);
        

        thpool = threadpool_create(T_NUM, QUEUE_SIZE, 0);
    }

    void mose::set_position_map(unsigned int C){
        for (unsigned int i = 0; i < this->T_NUM; i++) 
            shadow[i]->set_position_map(C);
    }

    mose::~mose()
    {
        int err;
        err = threadpool_destroy(thpool, threadpool_graceful);
        assert(err == 0);
        pthread_cond_destroy(&cond_sign);
        pthread_mutex_destroy(&cond_lock);
        delete block_idx;
        delete chunk_sizes;
        delete chunk_idx;
        for (unsigned int i = 0; i < T_NUM; i++)
            delete rram[i];
    }

    void mose::access_wrap(void *object)
    {
        return ((mose_args *)object)->arg1->access_thread(((mose_args *)object)->i);
    }
    void mose::access_thread(int i)
    {
        if (data_in == nullptr)
            rram[i]->access(bid, lif, data_in, data_out + chunk_idx[i], next_lif);
        else
            rram[i]->access(bid, lif, data_in + chunk_idx[i], data_out + chunk_idx[i], next_lif);

        barrier++;
        if (barrier == T_NUM)
        {
            pthread_mutex_lock(&cond_lock);
            pthread_cond_signal(&cond_sign);
            pthread_mutex_unlock(&cond_lock);
        }
    }


    void mose::shadow_access_wrap(void *object)
    {
        return ((((shadow_mose_args_w *)object)->arg)->arg1)->shadow_access_thread((shadow_mose_args_w *)object);
    }

    void mose::shadow_access_thread(shadow_mose_args_w* args)
    {
        if (args->arg->data_in == nullptr)
            shadow[args->i]->access(args->arg->bid, args->arg->data_in, args->arg->data_out + chunk_idx[args->i]);
        else
            shadow[args->i]->access(args->arg->bid, args->arg->data_in + chunk_idx[args->i], args->arg->data_out + chunk_idx[args->i]);

        args->arg->barrier++;
        if (args->arg->barrier == T_NUM)
        {
            pthread_mutex_lock(&args->arg->mux);
            pthread_cond_signal(&args->arg->cond);
            pthread_mutex_unlock(&args->arg->mux);
        }
    }


    void mose::access_r_wrap(void *object)
    {
        return ((mose_args *)object)->arg1->access_r_thread(((mose_args *)object)->i);
    }
    void mose::access_r_thread(int i)
    {
        rram[i]->access_r(bid, lif, data_out + chunk_idx[i]);

        pthread_mutex_lock(&cond_lock);
        barrier++;
        if (barrier == T_NUM)
            pthread_cond_signal(&cond_sign);
        pthread_mutex_unlock(&cond_lock);
    }

    void mose::access_w_wrap(void *object)
    {
        return ((mose_args *)object)->arg1->access_w_thread(((mose_args *)object)->i);
    }
    void mose::access_w_thread(int i)
    {
        rram[i]->access_w(bid, lif, data_in + chunk_idx[i], next_lif);

        pthread_mutex_lock(&cond_lock);
        barrier++;
        if (barrier == T_NUM)
            pthread_cond_signal(&cond_sign);
        pthread_mutex_unlock(&cond_lock);
    }
    void mose::write_wrap(void *object)
    {
        return ((mose_args *)object)->arg1->write_thread(((mose_args *)object)->i);
    }
    void mose::write_thread(int i)
    {
        rram[i]->write(bid, data_in + chunk_idx[i], next_lif);

        barrier++;
        if (barrier == T_NUM)
        {
            pthread_mutex_lock(&cond_lock);
            pthread_cond_signal(&cond_sign);
            pthread_mutex_unlock(&cond_lock);
        }
    }
    void mose::access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif)
    {
        this->bid = bid;
        this->lif = lif;
        this->data_in = data_in;
        this->data_out = data_out;
        this->next_lif = next_lif;

        barrier = 0;
        for (unsigned int i = 0; i < T_NUM; i++)
        {
            threadpool_add(thpool, access_wrap, (void *)&args[i], 0);
        }
        pthread_mutex_lock(&cond_lock);
        while (barrier != T_NUM)
            pthread_cond_wait(&cond_sign, &cond_lock);
        pthread_mutex_unlock(&cond_lock);
    }


    void mose::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
    {   
        pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
        pthread_cond_t cond = PTHREAD_COND_INITIALIZER;    
        shadow_mose_args args = {this, cond, lock, {0}, bid, data_in, data_out};
        shadow_mose_args_w args_w[T_NUM];
        for (unsigned int i = 0; i < T_NUM; i++)
        {
            args_w[i] = {&args, i};
            threadpool_add(thpool, shadow_access_wrap, (void *)&args_w[i], 0);
        }
        pthread_mutex_lock(&lock);
        while (args.barrier != T_NUM)
            pthread_cond_wait(&cond, &lock);
        pthread_mutex_unlock(&lock);
    }
    void mose::access_r(block_id bid, leaf_id lif, std::uint8_t *data_out)
    {
        this->bid = bid;
        this->lif = lif;
        this->data_out = data_out;

        barrier = 0;
        for (unsigned int i = 0; i < T_NUM; i++)
        {
            threadpool_add(thpool, access_w_wrap, (void *)&args[i], 0);
        }
        pthread_mutex_lock(&cond_lock);
        while (barrier != T_NUM)
            pthread_cond_wait(&cond_sign, &cond_lock);
        pthread_mutex_unlock(&cond_lock);
    }

    void mose::access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif)
    {
        this->bid = bid;
        this->lif = lif;
        this->data_out = data_out;
        this->next_lif = next_lif;

        barrier = 0;
        for (unsigned int i = 0; i < T_NUM; i++)
        {
            threadpool_add(thpool, access_r_wrap, (void *)&args[i], 0);
        }
        pthread_mutex_lock(&cond_lock);
        while (barrier != T_NUM)
            pthread_cond_wait(&cond_sign, &cond_lock);
        pthread_mutex_unlock(&cond_lock);
    }

    void mose::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
    {
        this->bid = bid;
        this->data_in = data_in;
        this->next_lif = next_lif;

        barrier = 0;
        for (unsigned int i = 0; i < T_NUM; i++)
        {
            threadpool_add(thpool, write_wrap, (void *)&args[i], 0);
        }
        pthread_mutex_lock(&cond_lock);
        while (barrier != T_NUM)
            pthread_cond_wait(&cond_sign, &cond_lock);
        pthread_mutex_unlock(&cond_lock);
    }

} // namespace obl
