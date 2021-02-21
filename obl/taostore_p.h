#ifndef TAOSTORE_ORAM_PARALLEL_H
#define TAOSTORE_ORAM_PARALLEL_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/circuit.h"
#include "obl/taostore_factory.hpp"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"
#include "obl/taostore_pos_map.h"
#include "obl/taostore_pos_map_notobl.h"
#include "obl/taostore_subtree.h"
#include "obl/threadpool.h"

#include <cstdint>
#include <cstddef>
#include <cstring>

#include <deque>
#include <unordered_set>

//threading libs
#include <atomic>
#include <pthread.h>

#include <wolfcrypt/aes.h>

#ifdef SGX_ENCLAVE_ENABLED
#include "obl/sgx_host_allocator.hpp"
#endif
namespace obl
{
	class taostore_oram_parallel : public tree_oram
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
		pthread_mutex_t *stash_locks;
		pthread_rwlock_t *stash_rw_locks;

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
		pthread_mutex_t multi_set_lock = PTHREAD_MUTEX_INITIALIZER;
		pthread_mutex_t wb_lock = PTHREAD_MUTEX_INITIALIZER;

		std::size_t subtree_node_size;
		threadpool_t *thpool;

		std::deque<request_p_t *> request_structure;

		std::unordered_multiset<leaf_id> path_req_multi_set;

		oram_factory *allocator;
		taostore_position_map_notobl *position_map;
		// taostore_position_map *position_map;

		// crypto stuff
		obl_aes_gcm_128bit_tag_t merkle_root;
		void *_crypt_buffer;
		Aes *crypt_handle;

		bool oram_alive;
		std::atomic_int32_t thread_id;
		std::atomic_int32_t evict_path;
		std::atomic_uint64_t access_counter;

		//path variables
		unsigned int A;
		std::atomic_uint64_t fetched_path_counter;

		// private methods
		void init();

		static void *serializer_wrap(void *object);
		void *serializer();
		static void access_thread_wrap(void *object);
		virtual void access_thread(request_p_t &_req) = 0;

		std::uint64_t read_path(request_p_t &req, std::uint8_t *_fetched);
		void answer_request(bool fake, block_id bid, std::int32_t id, std::uint8_t *_fetched);
		virtual std::uint64_t fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake) = 0;
		virtual std::uint64_t eviction(leaf_id path) = 0;
		virtual void write_back() = 0;

		// helper methods
		bool has_free_block(block_t *bl, int len);
		std::int64_t get_max_depth_bucket(block_t *bl, int len, leaf_id path);

		void multiset_lock(leaf_id path);
		void multiset_unlock(leaf_id path);

	public:
		taostore_oram_parallel(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM);
		~taostore_oram_parallel(){};

		//debug
		// int printrec(node *t, int L, int l_index);
		// void printstash();
		// void printsubtree();
		// void print_tree();
		// void printpath(leaf_id path);

		void wait_end();
		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);
		void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif){};

		// split fetch and eviction phases of the access method
		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out){};
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif){};

		// only write block into the stash and perfom evictions
		virtual void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif) = 0;
	};
	struct processing_thread_args_wrap_p
	{
		taostore_oram_parallel *arg1;
		request_p_t &request;
	};

} // namespace obl

#endif // TAOSTORE_ORAM_PARALLEL_H
