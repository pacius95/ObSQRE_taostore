#ifndef TAOSTORE_ORAM_H
#define TAOSTORE_ORAM_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"
#include "obl/taostore_pos_map.h"
#include "obl/taostore_pos_map_notobl.h"
#include "obl/taostore_subtree.h"
#include "obl/threadpool.h"

#include <cstdint>
#include <cstddef>
#include <mutex>
#include <condition_variable>

#include <deque>
#include <set>

//threading libs
#include <iostream>
#include <atomic>
#include <vector>
#include <mutex>
#include <thread>
#include <pthread.h>
#include <wolfcrypt/aes.h>

#ifdef SGX_ENCLAVE_ENABLED
#include "obl/sgx_host_allocator.hpp"
#endif
namespace obl
{
	class taostore_oram : public tree_oram
	{
	protected:
		std::size_t block_size;	 //aligned block size
		std::size_t bucket_size; //aligned/padded encrypted bucket size
		std::uint32_t K;
		unsigned int T_NUM;
		// stash
		flexible_array<block_t> stash;
		unsigned int S; // stash size
		unsigned int ss;
		unsigned int SS;
		std::mutex *stash_locks;

		taostore_subtree local_subtree;

// content of the ORAM
#ifdef SGX_ENCLAVE_ENABLED
		flexible_array<bucket_t, sgx_host_allocator> tree;
#else
		flexible_array<bucket_t> tree;
#endif
		//serialier
		pthread_t serializer_id;									 //serializer thread id
		std::mutex serializer_lck;	 //lock della request structure
		std::condition_variable serializer_cond;	 //cond associata al serializer
		std::mutex write_back_lock; //for debugging (1 WB at time)
		std::mutex stash_lock;
		std::mutex multi_set_lock;
		std::mutex eviction_lock;
		std::mutex pos_map_lock;

		threadpool_t *thpool;

		std::deque<request_t *> request_structure;

		std::multiset<leaf_id> path_req_multi_set;

		circuit_fake_factory *allocator;
		taostore_position_map_notobl *position_map;

		// crypto stuff
		obl_aes_gcm_128bit_tag_t merkle_root;
		void *_crypt_buffer;
		Aes *crypt_handle;

		bool oram_alive;
		std::atomic_int32_t thread_id;
		std::atomic_uint32_t evict_path;
		std::atomic_uint64_t access_counter;

		// private methods
		void init();

		static void *serializer_wrap(void *object);
		void *serializer();
		static void access_thread_wrap(void *object);
		virtual void access_thread(request_t &_req) = 0;

		void read_path(request_t &req, std::uint8_t *_fetched);
		void answer_request(request_t &req, std::uint8_t *fetched);
		virtual void fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake) = 0;
		virtual void eviction(leaf_id path) = 0;
		virtual void write_back(std::uint32_t c) = 0;

		// helper methods
		bool has_free_block(block_t *bl, int len);
		std::int64_t get_max_depth_bucket(block_t *bl, int len, leaf_id path);

		void multiset_lock(leaf_id path);
		void multiset_unlock(leaf_id path);

	public:
		taostore_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM);
		virtual ~taostore_oram(){};

		//debug
		int printrec(std::shared_ptr<node> t, int L, int l_index);
		void printstash();
		void printsubtree();
		void print_tree();
		void printpath(leaf_id path);

		virtual void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out) = 0;
		void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif){};

		// split fetch and eviction phases of the access method
		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out){};
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif){};
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};
	struct processing_thread_args_wrap
	{
		taostore_oram *arg1;
		taostore_request_t &request;
	};
	class taostore_factory
	{
	public:
		virtual taostore_oram *spawn_oram(std::size_t N, std::size_t B, size_t T_NUM) = 0;
		virtual ~taostore_factory(){};
	};

} // namespace obl

#endif // TAOSTORE_ORAM_H
