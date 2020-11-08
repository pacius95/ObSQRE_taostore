#ifndef TAOSTORE_PATH_ORAM_H
#define TAOSTORE_PATH_ORAM_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"
#include "obl/taostore_pos_map.h"
#include "obl/taostore_subtree.hpp"
#include "obl/threadpool.h"

#include <cstdint>
#include <cstddef>

#include <deque>
#include <set>

//threading libs
#include <iostream>
#include <atomic>
#include <vector>
#include <mutex>
#include <thread>
#include <pthread.h>
//#include <sgx_spinlock.h>
#include <wolfcrypt/aes.h>

#ifdef SGX_ENCLAVE_ENABLED
#include "obl/sgx_host_allocator.hpp"
#endif

namespace obl
{

	struct processing_thread_args;

	class taostore_path_oram : public tree_oram
	{
	private:
		std::size_t block_size;	 //aligned block size
		std::size_t bucket_size; //aligned/padded encrypted bucket size
		std::uint32_t K;
		unsigned int T_NUM;
		// stash
		flexible_array<block_t> stash;
		unsigned int S; // stash size
		unsigned int A; // det eviction

		taostore_subtree local_subtree;

// content of the ORAM
#ifdef SGX_ENCLAVE_ENABLED
		flexible_array<bucket_t, sgx_host_allocator> tree;
#else
		flexible_array<bucket_t> tree;
#endif
		//serialier
		pthread_t serializer_id;									 //serializer thread id
		pthread_mutex_t serializer_lck = PTHREAD_MUTEX_INITIALIZER;	 //lock della request structure
		pthread_cond_t serializer_cond = PTHREAD_COND_INITIALIZER;	 //cond associata al serializer
		pthread_mutex_t write_back_lock = PTHREAD_MUTEX_INITIALIZER; //for debugging (1 WB at time)
		pthread_mutex_t stash_lock = PTHREAD_MUTEX_INITIALIZER;
		pthread_mutex_t multi_set_lock = PTHREAD_MUTEX_INITIALIZER;
		pthread_mutex_t *mutex_level_i;

		threadpool_t *thpool;

		std::deque<request_t *> request_structure;

		std::multiset<leaf_id> path_req_multi_set;

		circuit_fake_factory *allocator;
		taostore_position_map *position_map;

		// crypto stuff
		obl_aes_gcm_128bit_tag_t merkle_root;
		void *_crypt_buffer;
		Aes *crypt_handle;

		bool oram_alive;
		std::atomic_int32_t thread_id;
		std::atomic_uint64_t evict_path;
		std::atomic_uint32_t path_counter;

		// private methods
		void init();

		static void *serializer_wrap(void *object);
		void *serializer();
		static void access_thread_wrap(void *object);
		void access_thread(request_t &_req);

		// static void eviction_thread_wrap(void *object);
		// void eviction_thread(void *_request);

		bool read_path(request_t &req, std::uint8_t *_fetched);
		bool fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake);
		void answer_request(request_t &req, std::uint8_t *fetched, bool found_in_path);
		void eviction(leaf_id path);
		void write_back(std::uint32_t c);

		// helper methods
		bool has_free_block(block_t *bl, int len);
		std::int64_t get_max_depth_bucket(block_t *bl, int len, leaf_id path);
		
		void multiset_lock(leaf_id path);
		void multiset_unlock ( leaf_id path);

	public:
		taostore_path_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S,unsigned int A, unsigned int T_NUM);
		~taostore_path_oram();

		//debug
		int printrec(node *t, int L, int l_index);
		void printstash();
		void printsubtree();
		void print_tree();

		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);
		void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif){};

		// split fetch and eviction phases of the access method
		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out){};
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif){};

		// only write block into the stash and perfom evictions
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class taostore_path_factory : public oram_factory
	{
	private:
		unsigned int Z, S, A, T_NUM;

	public:
		taostore_path_factory(unsigned int Z, unsigned int S, unsigned A, unsigned T_NUM)
		{
			this->Z = Z;
			this->S = S;
			this->A = A;
			this->T_NUM = T_NUM;
		}
		tree_oram *spawn_oram(std::size_t N, std::size_t B)
		{			
			// since path oram has the largest stash size, improve it
			unsigned int real_S = N < S ? N : S;
			return new taostore_path_oram(N, B, Z, real_S, A, T_NUM);
		}
	};
} // namespace obl

#endif // TAOSTORE_PATH_ORAM_H