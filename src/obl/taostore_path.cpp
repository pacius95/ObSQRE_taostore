#include "obl/utils.h"
#include "obl/taostore_path.h"
#include "obl/primitives.h"

#include "obl/oassert.h"

#include <map>
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <ctime>

//#include "sgx_trts.h"

#define DUMMY -1
#define BOTTOM -2
#define QUEUE_SIZE 256

namespace obl
{
	struct processing_thread_args_wrap
	{
		taostore_path_oram *arg1;
		taostore_request_t &request;
	};

	taostore_path_oram::taostore_path_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int A, unsigned int T_NUM) : tree_oram(N, B, Z)
	{
		// align structs to 8-bytes
		/*
			Since AES-GCM is basically an AES-CTR mode, and AES-CTR mode is a "stream-cipher",
			you actually don't need to pad everything to 16 bytes which is AES block size
		*/
		block_size = pad_bytes(sizeof(block_t) + this->B, 8);
		bucket_size = pad_bytes(sizeof(bucket_t) + this->Z * block_size, 8);

		// stash allocation
		this->S = S;
		stash.set_entry_size(block_size);
		stash.reserve(this->S);

		for (unsigned int i = 0; i < this->S; ++i)
			stash[i].bid = DUMMY;

		// ORAM tree allocation
		tree.set_entry_size(bucket_size);
		tree.reserve(capacity);

		this->T_NUM = T_NUM;
		this->K = next_two_power((1 << 25) / (bucket_size * L));
		this->A = A;
		init();
		oram_alive = true;

		pthread_create(&serializer_id, nullptr, serializer_wrap, (void *)this);
	}

	taostore_path_oram::~taostore_path_oram()
	{
		pthread_mutex_lock(&serializer_lck);
		oram_alive = false;
		pthread_cond_signal(&serializer_cond);
		pthread_mutex_unlock(&serializer_lck);

		threadpool_destroy(thpool, threadpool_graceful);

		std::memset(_crypt_buffer, 0x00, sizeof(Aes) + 16);

		std::memset(&stash[0], 0x00, block_size * S);

		free(_crypt_buffer);

		pthread_join(serializer_id, nullptr);

		pthread_mutex_destroy(&stash_lock);
		pthread_mutex_destroy(&multi_set_lock);
		pthread_cond_destroy(&serializer_cond);
		pthread_mutex_destroy(&serializer_lck);
		pthread_mutex_destroy(&write_back_lock);

		delete position_map;
	}

	void taostore_path_oram::init()
	{
		obl_aes_gcm_128bit_key_t master_key;
		obl_aes_gcm_128bit_iv_t iv;
		auth_data_t empty_auth;
		std::uint8_t empty_bucket[Z * block_size];

		std::atomic_init(&thread_id, 0);
		std::atomic_init(&evict_path, 0);
		std::atomic_init(&path_counter, 1);

		// generate random master key
		gen_rand(master_key, OBL_AESGCM_KEY_SIZE);

		// initialize aes handle
		crypt_handle = (Aes *)man_aligned_alloc(&_crypt_buffer, sizeof(Aes), 16);
		wc_AesGcmSetKey(crypt_handle, master_key, OBL_AESGCM_KEY_SIZE);

		// clear the authenticated data and the bucket
		std::memset(&empty_auth, 0x00, sizeof(auth_data_t));
		std::memset(empty_bucket, 0xff, Z * block_size);

		// generate random IV
		gen_rand(iv, OBL_AESGCM_IV_SIZE);

		wc_AesGcmEncrypt(crypt_handle,
						 tree[0].payload,
						 empty_bucket,
						 Z * block_size,
						 iv,
						 OBL_AESGCM_IV_SIZE,
						 merkle_root,
						 OBL_AESGCM_MAC_SIZE,
						 (std::uint8_t *)&empty_auth,
						 sizeof(auth_data_t));

		// now dump to the protected storage
		std::memcpy(tree[0].mac, merkle_root, sizeof(obl_aes_gcm_128bit_tag_t));
		std::memcpy(tree[0].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
		tree[0].reach_l = false;
		tree[0].reach_r = false;

		thpool = threadpool_create(T_NUM, QUEUE_SIZE, 0);

		allocator = new circuit_fake_factory(Z, S);
		position_map = new taostore_position_map(N, sizeof(int64_t), 5, allocator);
		local_subtree.init((size_t)Z * block_size, empty_bucket, L);
	}

	void *taostore_path_oram::serializer_wrap(void *object)
	{
		return ((taostore_path_oram *)object)->serializer();
	}

	void *taostore_path_oram::serializer()
	{
		while (oram_alive || request_structure.size() != 0)
		{
			pthread_mutex_lock(&serializer_lck);
			if (request_structure.size() == 0 || !request_structure.front()->handled || !request_structure.front()->data_ready)
				pthread_cond_wait(&serializer_cond, &serializer_lck);

			while (request_structure.size() != 0 && request_structure.front()->handled && request_structure.front()->data_ready)
			{
				pthread_mutex_lock(&request_structure.front()->cond_mutex);

				request_structure.front()->res_ready = true;
				pthread_cond_broadcast(&request_structure.front()->serializer_res_ready);
				pthread_mutex_unlock(&request_structure.front()->cond_mutex);

				request_structure.pop_front();
			}
			pthread_mutex_unlock(&serializer_lck);
		}
		return 0;
	}

	void taostore_path_oram::eviction(leaf_id path)
	{

		std::int64_t l_index = 0;
		flexible_array<block_t> fetched_path;
		fetched_path.set_entry_size(block_size);
		fetched_path.reserve((L + 1) * this->Z);

		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		block_t *bl;
		bool valid = true;
		int i = 0;

		node *reference_node, *old_ref_node;

		reference_node = local_subtree.root;

		multiset_lock(path);
		//START DEEPEST

		pthread_mutex_lock(&stash_lock);
		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			reference_node->local_timestamp = path_counter;
			old_ref_node = reference_node;
			memcpy((std::uint8_t *)&fetched_path[Z * i], reference_node->payload, block_size * Z);

			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
		}
		if (i <= L && reference_node == nullptr)
		{
			valid = (l_index & 1) ? old_ref_node->adata.valid_l : old_ref_node->adata.valid_r;
			if (valid)
			{
				std::uint8_t *src = tree[(l_index)].mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
		}
		while (i <= L && valid)
		{
			(l_index & 1) ? old_ref_node->child_l = new node(block_size * Z, path_counter) : old_ref_node->child_r = new node(block_size * Z, path_counter);
			reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
			reference_node->lock();
			reference_node->parent = old_ref_node;

			adata = &reference_node->adata;

			std::int64_t leftch = get_left(l_index);
			std::int64_t rightch = get_right(l_index);

			// this data will be authenticated data in the GCM mode
			// dump from encrypted bucket header
			adata->valid_l = tree[l_index].reach_l;
			adata->valid_r = tree[l_index].reach_r;

			// dump left and right child mac if valid, otherwise pad with 0s
			if (adata->valid_l)
				std::memcpy(adata->left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			if (adata->valid_r)
				std::memcpy(adata->right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			// if they are not valid, authentication data for the corresponding mac would be 0x00..0
			// however this was already covered by the memset before the loop

			// decrypt using the IV
			int dec = wc_AesGcmDecrypt(crypt_handle,
									   (std::uint8_t *)reference_node->payload,
									   tree[l_index].payload,
									   Z * block_size,
									   tree[l_index].iv,
									   OBL_AESGCM_IV_SIZE,
									   reference_mac,
									   OBL_AESGCM_MAC_SIZE,
									   (std::uint8_t *)adata,
									   sizeof(auth_data_t));

			// MAC mismatch is a critical error
			//assert(dec != AES_GCM_AUTH_E);
			assert(dec == 0);

			memcpy((std::uint8_t *)&fetched_path[Z * i], reference_node->payload, block_size * Z);
			old_ref_node = reference_node;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			valid = (l_index & 1) ? adata->valid_l : adata->valid_r;
			if (valid)
			{
				std::uint8_t *src = ((path >> i) & 1) ? adata->right_mac : adata->left_mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
			++i;
		}

		// fill the other buckets with "empty" blocks
		while (i <= L)
		{
			(l_index & 1) ? old_ref_node->child_l = new node(block_size * Z, path_counter) : old_ref_node->child_r = new node(block_size * Z, path_counter);
			reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
			reference_node->lock();
			reference_node->parent = old_ref_node;

			bl = (block_t *)reference_node->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				bl->bid = DUMMY;
				bl = (block_t *)((std::uint8_t *)bl + block_size);
			}
			memcpy((std::uint8_t *)&fetched_path[Z * i], reference_node->payload, block_size * Z);
			old_ref_node = reference_node;

			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}

		// perform in-place eviction of the current path
		for (int i = L - 1; i >= 0; i--) // for every bucket in the fetched path, from leaf to root
		{
			for (unsigned int z1 = 0; z1 < Z; z1++) // for every block in the source bucket
			{
				int under_ev = i * Z + z1;
				std::int64_t maxd = get_max_depth(fetched_path[under_ev].lid, path, L);
				for (int j = L; j > i; j--) // for every bucket from leaf to the one right under [i]
				{
					bool can_reside = maxd >= j;
					int offset = j * Z;

					for (unsigned int z2 = 0; z2 < Z; z2++) // for every block in the target bucket
					{
						bool free_slot = fetched_path[offset + z2].bid == DUMMY;
						swap(can_reside & free_slot, (std::uint8_t *)&fetched_path[under_ev], (std::uint8_t *)&fetched_path[offset + z2], block_size);
						can_reside &= !free_slot;
					}
				}
			}
		}
		for (unsigned int k = 0; k < S; k++) // for every block in the stash
		{
			std::int64_t maxd = get_max_depth(stash[k].lid, path, L);

			for (int i = L; i >= 0; i--) // for every bucket in the path (in reverse order)
			{
				bool can_reside = maxd >= i;
				int offset = i * Z;

				for (unsigned int j = 0; j < Z; j++) // for every block in a bucket
				{
					bool free_slot = fetched_path[offset + j].bid == DUMMY;
					swap(can_reside & free_slot, (std::uint8_t *)&stash[k], (std::uint8_t *)&fetched_path[offset + j], block_size);
					can_reside &= !free_slot;
				}
			}
		}
		pthread_mutex_unlock(&stash_lock);
		
		reference_node = local_subtree.root;
		for (i = 0; i <= L ; ++i)
		{
			memcpy(reference_node->payload, (std::uint8_t *)&fetched_path[Z * i], block_size * Z);

			reference_node->unlock();
			reference_node = i != L ? (path >> i) & 1 ? reference_node->child_r : reference_node->child_l : reference_node;
		}
		multiset_unlock(path);

		write_queue_t T = {path, reference_node};
		local_subtree.insert_write_queue(T);

	}
	void taostore_path_oram::multiset_lock(leaf_id path)
	{
		leaf_id l_index = 0;
		pthread_mutex_lock(&multi_set_lock);
		for (int i = 0; i < L; ++i)
		{
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			path_req_multi_set.insert(l_index);
		}
		pthread_mutex_unlock(&multi_set_lock);
	}

	void taostore_path_oram::multiset_unlock(leaf_id path)
	{
		leaf_id l_index = 0;
		pthread_mutex_lock(&multi_set_lock);
		for (int i = 0; i < L; ++i)
		{
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			path_req_multi_set.erase(path_req_multi_set.find(l_index));
		}
		pthread_mutex_unlock(&multi_set_lock);
	}

	void taostore_path_oram::access_thread_wrap(void *_object)
	{
		return ((processing_thread_args_wrap *)_object)->arg1->access_thread(((processing_thread_args_wrap *)_object)->request);
	}

	void taostore_path_oram::access_thread(request_t &_req)
	{
		std::uint8_t _fetched[block_size];
		std::uint32_t evict_leaf;
		std::uint32_t paths;
		bool found_in_path;

		found_in_path = read_path(_req, _fetched);

		answer_request(_req, _fetched, found_in_path);
		paths = std::atomic_fetch_add(&path_counter, 1);

		if (paths % A == 0)
		{
			evict_leaf = std::atomic_fetch_add(&evict_path, 1);
			eviction(evict_leaf);
			paths = std::atomic_fetch_add(&path_counter, 1);
		}

		if (paths % K == 0)
			write_back(paths / K);

		return;
	}

	bool taostore_path_oram::read_path(request_t &req, std::uint8_t *_fetched)
	{
		block_id bid;
		bool t = true;

		pthread_mutex_lock(&serializer_lck);
		for (auto &it : request_structure)
		{
			bool cond = it->bid == req.bid & it->handled == false & it->fake == false;
			replace(cond, (std::uint8_t *)&(req.fake), (std::uint8_t *)&t, sizeof(bool));
		}
		request_structure.push_back(&req);
		pthread_mutex_unlock(&serializer_lck);

		gen_rand((std::uint8_t *)&bid, sizeof(block_id));

		replace(!req.fake, (std::uint8_t *)&bid, (std::uint8_t *)&(req.bid), sizeof(block_id));

		leaf_id ev_lid;
		leaf_id path = position_map->access(bid, req.fake, &ev_lid);

		bool found_in_path = fetch_path(_fetched, bid, ev_lid, path, !req.fake);
		return found_in_path;
	}

	bool taostore_path_oram::fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool not_fake)
	{
		bool found_in_path = false;
		std::int64_t l_index = 0;
		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		bool valid = false;
		int i = 0;
		block_t *bl;

		block_t *fetched = (block_t *)_fetched;
		fetched->bid = DUMMY;

		node *reference_node;
		node *old_ref_node;

		reference_node = local_subtree.root;
		old_ref_node = local_subtree.root;

		multiset_lock(path);
		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			if (i != 0)
				old_ref_node->unlock();

			bl = (block_t *)reference_node->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				bool found = not_fake & bl->bid == bid;
				swap(found, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
				found_in_path = found_in_path | found;
			}
			reference_node->local_timestamp = path_counter;
			old_ref_node = reference_node;

			reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
		}

		if (i <= L && reference_node == nullptr)
		{
			valid = (l_index & 1) ? old_ref_node->adata.valid_l : old_ref_node->adata.valid_r;
			if (valid)
			{
				std::uint8_t *src = tree[l_index].mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
		}
		while (i <= L && valid)
		{
			(l_index & 1) ? old_ref_node->child_l = new node(block_size * Z, path_counter) : old_ref_node->child_r = new node(block_size * Z, path_counter);
			reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
			reference_node->parent = old_ref_node;

			reference_node->lock();
			old_ref_node->unlock();

			adata = &reference_node->adata;

			std::int64_t leftch = get_left(l_index);
			std::int64_t rightch = get_right(l_index);

			// this data will be authenticated data in the GCM mode
			// dump from encrypted bucket header
			adata->valid_l = tree[l_index].reach_l;
			adata->valid_r = tree[l_index].reach_r;

			// dump left and right child mac if valid, otherwise pad with 0s
			if (adata->valid_l)
				std::memcpy(adata->left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			if (adata->valid_r)
				std::memcpy(adata->right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			// if they are not valid, authentication data for the corresponding mac would be 0x00..0
			// however this was already covered by the memset before the loop

			// decrypt using the IV
			int dec = wc_AesGcmDecrypt(crypt_handle,
									   (std::uint8_t *)reference_node->payload,
									   tree[l_index].payload,
									   Z * block_size,
									   tree[l_index].iv,
									   OBL_AESGCM_IV_SIZE,
									   reference_mac,
									   OBL_AESGCM_MAC_SIZE,
									   (std::uint8_t *)adata,
									   sizeof(auth_data_t));

			assert(dec == 0);

			bl = (block_t *)reference_node->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				bool found = not_fake & bl->bid == bid;
				swap(found, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
				found_in_path = found_in_path | found;
			}

			old_ref_node = reference_node;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			valid = (l_index & 1) ? adata->valid_l : adata->valid_r;
			if (valid)
			{
				std::uint8_t *src = ((path >> i) & 1) ? adata->right_mac : adata->left_mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
			++i;
		}

		// fill the other buckets with "empty" blocks
		while (i <= L)
		{
			(l_index & 1) ? old_ref_node->child_l = new node(block_size * Z, path_counter) : old_ref_node->child_r = new node(block_size * Z, path_counter);
			reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
			reference_node->parent = old_ref_node;

			reference_node->lock();
			old_ref_node->unlock();

			bl = (block_t *)reference_node->payload;

			for (unsigned int j = 0; j < Z; ++j)
			{
				bl->bid = DUMMY;
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}

			old_ref_node = reference_node;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}
		old_ref_node->unlock();

		multiset_unlock(path);

		fetched->lid = new_lid;
		// fetched->bid = bid;

		write_queue_t T = {path, old_ref_node};
		local_subtree.insert_write_queue(T);
		return found_in_path;
	}

	void taostore_path_oram::answer_request(request_t &req, std::uint8_t *_fetched, bool found_in_path)
	{
		block_t *fetched = (block_t *)_fetched;
		std::uint8_t out_block[B];
		bool t = true;
		bool update_stash = found_in_path;
		// backup data read from the fetched path and update with any data in.
		std::memcpy(out_block, fetched->payload, B);

		pthread_mutex_lock(&serializer_lck);
		for (auto &it : request_structure)
		{
			replace(it->id == req.id, (std::uint8_t *)&(it->handled), (std::uint8_t *)&t, sizeof(bool));
			if (it->data_in != nullptr)
			{
				replace(!req.fake & (it->bid == req.bid), fetched->payload, it->data_in, B);
				bool update_stash = update_stash | (!req.fake & (it->bid == req.bid));
			}
		}
		bool already_evicted = false;
		pthread_mutex_lock(&stash_lock);

		for (unsigned int i = 0; i < S; i++)
		{
			block_id bid = req.bid;
			block_id sbid = stash[i].bid;
			leaf_id slid = stash[i].lid;
			block_id next_sbid;
			leaf_id next_lif = fetched->lid;

			bool target_block = (sbid == bid) | (sbid == DUMMY);

			replace(!req.fake & bid == sbid, out_block, stash[i].payload, B);
			replace(!req.fake & update_stash & target_block, stash[i].payload, fetched->payload, B);

			// overwrite leaf-id of all target blocks
			stash[i].lid = ternary_op(!req.fake & target_block, next_lif, slid);

			// properly overwrite block ids
			next_sbid = ternary_op(!req.fake & update_stash & already_evicted & (bid == sbid), -1, sbid);
			next_sbid = ternary_op(!req.fake & update_stash & !already_evicted & target_block, bid, sbid);
			stash[i].bid = next_sbid;

			already_evicted = req.fake | already_evicted | target_block;
		}
		assert(already_evicted);
		pthread_mutex_unlock(&stash_lock);

		for (auto &it : request_structure)
		{
			replace(!req.fake & (it->bid == req.bid), it->data_out, out_block, B);
			replace(!req.fake & (it->bid == req.bid), (std::uint8_t *)&(it->data_ready), (std::uint8_t *)&t, sizeof(bool));
			if (it->data_in != nullptr)
				replace(!req.fake & (it->bid == req.bid), out_block, it->data_in, B);
		}

		pthread_cond_broadcast(&serializer_cond);
		pthread_mutex_unlock(&serializer_lck);
	}

	void taostore_path_oram::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		std::uint8_t _data_out[block_size];
		std::int32_t _id = std::atomic_fetch_add(&thread_id, 1);
		request_t _req = {data_in, bid, false, false, _data_out, false, false, _id, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

		struct processing_thread_args_wrap obj_wrap = {this, _req};

		int err = threadpool_add(thpool, access_thread_wrap, (void *)&obj_wrap, 0);
		assert(err == 0);

		//wait on the conditional var
		pthread_mutex_lock(&_req.cond_mutex);
		while (!_req.res_ready)
		{
			pthread_cond_wait(&_req.serializer_res_ready, &_req.cond_mutex);
		}
		pthread_mutex_unlock(&_req.cond_mutex);

		std::memcpy(data_out, _data_out, B);
	}

	void taostore_path_oram::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t *)_fetched;

		// build the block to write!
		fetched->bid = bid;
		fetched->lid = next_lif;
		std::memcpy(fetched->payload, data_in, B);

		// evict the created block to the stash
		bool already_evicted = false;
		for (unsigned int i = 0; i < S; ++i)
		{
			block_id sbid = stash[i].bid;
			swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}

		assert(already_evicted);

		std::uint64_t evict_leaf = (std::uint64_t)std::atomic_fetch_add(&evict_path, 1);
		eviction(2 * evict_leaf);
		eviction(2 * evict_leaf + 1);

		if (evict_path % K)
			write_back(evict_path / K);

		return;
	}

	void taostore_path_oram::write_back(std::uint32_t c)
	{
		std::map<leaf_id, node *> nodes_level_i[L + 1];
		leaf_id l_index;
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;
		node *reference_node;

		write_queue_t *_paths;

		_paths = local_subtree.get_pop_queue(K);
		pthread_mutex_lock(&write_back_lock);
		nodes_level_i[L] = local_subtree.update_valid(_paths, K);

		for (int i = L; i > 0; --i)
		{
			for (auto &itx : nodes_level_i[i])
			{
				l_index = itx.first;
				reference_node = itx.second;
				// generate a new random IV
				gen_rand(iv, OBL_AESGCM_IV_SIZE);

				// save encrypted payload
				wc_AesGcmEncrypt(crypt_handle,
								 tree[l_index].payload,
								 (std::uint8_t *)reference_node->payload,
								 Z * block_size,
								 iv,
								 OBL_AESGCM_IV_SIZE,
								 mac,
								 OBL_AESGCM_MAC_SIZE,
								 (std::uint8_t *)&reference_node->adata,
								 sizeof(auth_data_t));

				// save "mac" + iv + reachability flags
				std::memcpy(tree[l_index].mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
				std::memcpy(tree[l_index].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
				tree[l_index].reach_l = reference_node->adata.valid_l;
				tree[l_index].reach_r = reference_node->adata.valid_r;

				node *parent = reference_node->parent;
				// update the mac for the parent for the evaluation of its mac
				nodes_level_i[i - 1][get_parent(l_index)] = parent;

				std::uint8_t *target_mac = (l_index & 1) ? parent->adata.left_mac : parent->adata.right_mac;
				std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));

				// pthread_spin_lock(&multi_set_lock);
				pthread_mutex_lock(&multi_set_lock);
				if (reference_node->local_timestamp <= c * K &&
					reference_node->child_r == nullptr && reference_node->child_l == nullptr &&
					path_req_multi_set.find(l_index) == path_req_multi_set.end())
				{
					if (l_index & 1)
						parent->child_l = nullptr;
					else
						parent->child_r = nullptr;
					delete reference_node;
				}
				pthread_mutex_unlock(&multi_set_lock);
			}
		}
		pthread_mutex_unlock(&write_back_lock);
		delete _paths;
	}

	void taostore_path_oram::printstash()
	{
		for (unsigned int i = 0; i < S; ++i)
			std::cerr << "stash " << i << "bid: " << (block_id)stash[i].bid << "lid :" << (leaf_id)stash[i].lid << " data: " << (std::uint64_t) * ((std::uint64_t *)stash[i].payload) << std::endl;
	}
	void taostore_path_oram::printsubtree()
	{
		int i;
		i = printrec(local_subtree.root, L, 0);
		std::cerr << "-------------" << i << "----------------" << std::endl;
	}
	int taostore_path_oram::printrec(node *t, int l, int l_index)
	{
		int i = 0;
		block_t *bl = (block_t *)t->payload;
		for (unsigned int i = 0; i < Z; ++i)
		{
			std::cerr << "node l_index:" << l_index << "bid: " << bl->bid << "lid :" << bl->lid << " data: " << (std::uint64_t) * ((std::uint64_t *)bl->payload) << std::endl;
			bl = (block_t *)((std::uint8_t *)bl + block_size);
		}
		std::cerr << "mac destro: " << (std::uint64_t) * ((std::uint64_t *)t->adata.right_mac) << "mac sinistro: " << (std::uint64_t) * ((std::uint64_t *)t->adata.left_mac) << std::endl;

		if (l == 0)
			return 1;
		else
		{
			if (t->child_l != nullptr)
				i += printrec(t->child_l, l - 1, get_left(l_index));
			if (t->child_r != nullptr)
				i += printrec(t->child_r, l - 1, get_right(l_index));
		}
		return i;
	}
	void taostore_path_oram::print_tree()
	{
		leaf_id l_index = 0;
		auth_data_t adata;
		block_t *payload = (block_t *)new uint8_t[Z * block_size];

		obl_aes_gcm_128bit_key_t mac;
		obl_aes_gcm_128bit_iv_t iv;
		block_t *bl;
		for (l_index = 0; l_index < ((1 << (L + 1)) - 1); l_index++)
		{

			std::memset(&adata, 0x00, sizeof(auth_data_t));

			memcpy(iv, tree[l_index].iv, sizeof(obl_aes_gcm_128bit_iv_t));
			memcpy(mac, tree[l_index].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			std::int64_t leftch = get_left(l_index);
			std::int64_t rightch = get_right(l_index);

			// this data will be authenticated data in the GCM mode
			// dump from encrypted bucket header
			adata.valid_l = tree[l_index].reach_l;
			adata.valid_r = tree[l_index].reach_r;

			// dump left and right child mac if valid, otherwise pad with 0s
			if (adata.valid_l)
				std::memcpy(adata.left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			if (adata.valid_r)
				std::memcpy(adata.right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			// if they are not valid, authentication data for the corresponding mac would be 0x00..0
			// however this was already covered by the memset before the loop

			// decrypt using the IV
			int dec = wc_AesGcmDecrypt(crypt_handle,
									   (std::uint8_t *)payload,
									   tree[l_index].payload,
									   Z * block_size,
									   iv,
									   OBL_AESGCM_IV_SIZE,
									   mac,
									   OBL_AESGCM_MAC_SIZE,
									   (std::uint8_t *)&adata,
									   sizeof(auth_data_t));

			if (dec != 0)
			{
				std::cerr << "mmmmm" << std::endl;
			}

			bl = payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				std::cerr << "l_index:" << l_index << "bid: " << bl->bid << "lid :" << bl->lid << " data: " << (std::uint64_t) * ((std::uint64_t *)bl->payload) << "mac: " << (std::uint64_t) * ((std::uint64_t *)mac) << "mac sinistro: " << (std::uint64_t) * ((std::uint64_t *)adata.left_mac) << "mac destro: " << (std::uint64_t) * ((std::uint64_t *)adata.right_mac) << std::endl;
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}
		}
	}

} // namespace obl