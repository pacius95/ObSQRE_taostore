#include "obl/mose.h"
#include "obl/circuit.h"
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
        mose *arg1;
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
        for (unsigned int i = 0; this->B % T_NUM; i++)
            chunk_sizes[i] += 1;

        chunk_idx[0] = 0;
        for (unsigned int i = 1; i < T_NUM; i++)
            chunk_idx[i] += chunk_idx[i - 1] + chunk_sizes[i - 1];

        rram = new tree_oram *[T_NUM];

        args = new mose_args[T_NUM];
        for (unsigned int i = 0; i < T_NUM; i++)
            args[i] = {this, i};

        for (unsigned int i = 0; i < T_NUM; i++)
            rram[i] = new circuit_oram(N, chunk_sizes[i], Z, S);

        thpool = threadpool_create(T_NUM, QUEUE_SIZE, 0);
    }

    mose::~mose()
    {
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
        pthread_mutex_lock(&cond_lock);
        barrier++;
        if (barrier == T_NUM)
            pthread_cond_signal(&cond_sign);
        pthread_mutex_unlock(&cond_lock);
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
