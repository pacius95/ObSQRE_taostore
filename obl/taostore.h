#ifndef TAOSTORE_ORAM_H
#define TAOSTORE_ORAM_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"
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
	struct taostore_request_t;
	struct processing_thread_args_wrap;

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
		pthread_mutex_t *stash_locks;
		std::size_t subtree_node_size;
		taostore_subtree local_subtree;

// content of the ORAM
#ifdef SGX_ENCLAVE_ENABLED
		flexible_array<bucket_t, sgx_host_allocator> tree;
#else
		flexible_array<bucket_t> tree;
#endif

		pthread_mutex_t multi_set_lock = PTHREAD_MUTEX_INITIALIZER;
		threadpool_t *thpool;

		std::unordered_multiset<leaf_id> path_req_multi_set;

		// crypto stuff
		obl_aes_gcm_128bit_tag_t merkle_root;
		void *_crypt_buffer;
		Aes *crypt_handle;

		std::atomic_int32_t evict_path;
		std::atomic_uint64_t access_counter;

		//path variables
		unsigned int A;
		std::atomic_uint64_t eviction_counter;

		// private methods
		void init();

		static void access_thread_wrap(void *object);
		virtual void access_thread(taostore_request_t &_req) = 0;
		static void access_write_thread_wrap(void *object);
		virtual void write_thread(taostore_request_t &_req) = 0;
		static void access_read_thread_wrap(void *object);
		virtual void read_thread(taostore_request_t &_req) = 0;

		static void writeback_thread_wrap(void *object);
		virtual std::uint64_t fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id path) = 0;
		virtual std::uint64_t eviction(leaf_id path) = 0;
		virtual void write_back() = 0;

		// helper methods
		bool has_free_block(block_t *bl, int len);
		std::int64_t get_max_depth_bucket(block_t *bl, int len, leaf_id path);
		
		void multiset_lock(leaf_id path);
		void multiset_unlock(leaf_id path);

	public:
		taostore_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM);
		~taostore_oram(){};

		void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif);

		// split fetch and eviction phases of the access method
		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out);
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif);

		// only write block into the stash and perfom evictions
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};
	struct processing_thread_args_wrap
	{
		taostore_oram *arg1;
		taostore_request_t &request;
	};

} // namespace obl

#endif // TAOSTORE_ORAM_H
