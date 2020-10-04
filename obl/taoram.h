#ifndef TAOSTORE_ORAM_H
#define TAOSTORE_ORAM_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/flexible_array.hpp"
#include "obl/taostore_pos_map.h"
#include "obl/taostore_subtree.hpp"

#include <cstdint>
#include <cstddef>

#include <deque>

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
	struct processing_thread_args_wrap;

	class taostore_oram : public tree_oram
	{
	private:
		std::size_t block_size;	 //aligned block size
		std::size_t bucket_size; //aligned/padded encrypted bucket size
		std::size_t subtree_bucket_size;

		// stash
		flexible_array<block_t> stash;
		unsigned int S; // stash size

		// content of the local subtree
		taostore_subtree *local_subtree;

// content of the ORAM
#ifdef SGX_ENCLAVE_ENABLED
		flexible_array<bucket_t, sgx_host_allocator> tree;
#else
		flexible_array<bucket_t> tree;
#endif
		//serialier data
		pthread_t serializer_id;
		pthread_mutex_t serializer_lck = PTHREAD_MUTEX_INITIALIZER;
		pthread_cond_t serializer_cond = PTHREAD_COND_INITIALIZER;

		std::deque<request_t *> request_structure;
		std::deque<request_t *>::iterator it;

		//stash locks
		//TODO spinlock
		pthread_mutex_t stash_lock = PTHREAD_MUTEX_INITIALIZER ;

		taostore_position_map *pos_map;

		// crypto stuff
		void *_crypt_buffer;
		Aes *crypt_handle;
		obl_aes_gcm_128bit_tag_t merkle_root;

		// this is used to authenticate and rebuild the merkle tree

		bool oram_alive;
		std::atomic_llong evict_path;
		std::atomic_llong paths;
		// private methods
		void init();

		// circuit ORAM eviction preprocessing
		void eviction(leaf_id path);

		static void *serializer_wrap(void *object);
		void *serializer();

		static void *processing_thread_wrap(void *object);
		void *processing_thread(void *_request);
		void read_path(request_t *req, std::uint8_t *_fetched);
		void fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path);
		void answer_request(request_t *req, std::uint8_t *_fetched);

		// helper methods
		void printrec(node* t, int L);
		bool has_free_block(block_t *bl, int len);
		std::int64_t get_max_depth_bucket(block_t *bl, int len, leaf_id path);

		// split operation variables
		std::int64_t leaf_idx_split;

	public:
		taostore_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S);
		~taostore_oram();

		//debug
		void printstash();
		void printsubtree();
		void set_pos_map(taostore_position_map *pos_map);
		
		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);
		void access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif){};

		// split fetch and eviction phases of the access method
		void access_r(block_id bid, leaf_id lif, std::uint8_t *data_out){};
		void access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif){};

		// only write block into the stash and perfom evictions
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class taostore_factory : public oram_factory
	{
	private:
		unsigned int Z, S;

	public:
		taostore_factory(unsigned int Z, unsigned int S)
		{
			this->Z = Z;
			this->S = S;
		}
		tree_oram *spawn_oram(std::size_t N, std::size_t B)
		{
			return new taostore_oram(N, B, Z, S);
		}
	};
} // namespace obl

#endif // TAOSTORE_ORAM_H
