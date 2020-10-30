#include "obl/utils.h"
#include "obl/taostore.h"
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
	struct processing_thread_args
	{
		taostore_request_t &request;
		block_id bid;
	};
	struct processing_thread_args_wrap
	{
		taostore_oram *arg1;
		processing_thread_args *arg2;
	};

	taostore_oram::taostore_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : tree_oram(N, B, Z)
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
		this->K = next_two_power((1 << 25) / (bucket_size * L * 3));

		init();
		oram_alive = true;
		// threadpool_add(thpool, serializer_wrap, (void *)this, 0);
		pthread_create(&serializer_id, nullptr, serializer_wrap, (void *)this);
	}

	taostore_oram::~taostore_oram()
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
		//TODO cleanup
	}

	void taostore_oram::init()
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

		// pthread_spin_init(&multi_set_lock, PTHREAD_PROCESS_SHARED);
		// pthread_spin_init(&stash_lock, PTHREAD_PROCESS_SHARED);

		thpool = threadpool_create(T_NUM, QUEUE_SIZE, 0);

		allocator = new circuit_fake_factory(Z, S);
		position_map = new taostore_position_map(N, sizeof(int64_t), 5, allocator);
		local_subtree.init((size_t)Z * block_size, empty_bucket, L);
	}

	void *taostore_oram::serializer_wrap(void *object)
	{
		return ((taostore_oram *)object)->serializer();
	}

	void *taostore_oram::serializer()
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

	bool taostore_oram::has_free_block(block_t *bl, int len)
	{
		bool free_block = false;

		for (int i = 0; i < len; ++i)
		{
			free_block |= bl->bid == DUMMY;
			bl = (block_t *)((std::uint8_t *)bl + block_size);
		}

		return free_block;
	}

	std::int64_t taostore_oram::get_max_depth_bucket(block_t *bl, int len, leaf_id path)
	{
		std::int64_t max_d = -1;

		for (int i = 0; i < len; ++i)
		{
			int candidate = get_max_depth(bl->lid, path, L);
			block_id bid = bl->bid;
			max_d = ternary_op((candidate > max_d) & (bid != DUMMY), candidate, max_d);
			bl = (block_t *)((std::uint8_t *)bl + block_size);
		}

		return max_d;
	}

	void taostore_oram::eviction(leaf_id path)
	{

		std::int64_t l_index = 0;
		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		block_t *bl;
		bool valid = true;
		int i = 0;

		//evict array helper
		std::int64_t longest_jump_down[L + 2]; // counting root = 0 and stash = -1 and L additional levels
		std::int64_t closest_src_bucket[L + 2];
		std::int64_t next_dst_bucket[L + 2];

		// allow -1 indexing for stash
		std::int64_t *ljd = longest_jump_down + 1;
		std::int64_t *csb = closest_src_bucket + 1;
		std::int64_t *ndb = next_dst_bucket + 1;

		std::int64_t _closest_src_bucket = -1;
		std::int64_t goal = -1;

		node *reference_node, *old_ref_node;

		pthread_mutex_lock(&multi_set_lock);
		for (i = 0; i < L; ++i)
		{
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			path_req_multi_set.insert(l_index);
		}
		pthread_mutex_unlock(&multi_set_lock);

		reference_node = local_subtree.root;
		old_ref_node = local_subtree.root;
		l_index = 0;

		local_subtree.write_lock();

		pthread_mutex_lock(&stash_lock);
		goal = get_max_depth_bucket(&stash[0], S, path);
		ljd[-1] = goal;
		csb[-1] = BOTTOM;

		//START DEEPEST
		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			reference_node->local_timestamp = path_counter;

			csb[i] = ternary_op(goal >= i, _closest_src_bucket, BOTTOM);
			std::int64_t jump = get_max_depth_bucket((block_t *)reference_node->payload, Z, path);
			ljd[i] = jump;
			_closest_src_bucket = ternary_op(jump >= goal, i, _closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);

			old_ref_node = reference_node;

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
			reference_node->parent = old_ref_node;

			reference_node->lock();
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

			csb[i] = ternary_op(goal >= i, _closest_src_bucket, BOTTOM);
			std::int64_t jump = get_max_depth_bucket((block_t *)reference_node->payload, Z, path);
			ljd[i] = jump;
			_closest_src_bucket = ternary_op(jump >= goal, i, _closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);

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

			bl = (block_t *)reference_node->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				bl->bid = DUMMY;
				bl = (block_t *)((std::uint8_t *)bl + block_size);
			}

			csb[i] = ternary_op(goal >= i, _closest_src_bucket, BOTTOM);
			std::int64_t jump = get_max_depth_bucket((block_t *)reference_node->payload, Z, path);
			ljd[i] = jump;
			_closest_src_bucket = ternary_op(jump >= goal, i, _closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);

			old_ref_node = reference_node;

			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}

		//END DEEPEST
		//a questo punto tutto il ramo è stato scaricato e l'albero è stato tutto il tempo lockato
		//posso fare target come nell circuit pari pari

		//START TARGET

		reference_node = old_ref_node; //pointer alla foglia

		std::int64_t src = BOTTOM;
		std::int64_t dst = BOTTOM;

		for (int i = L; i >= 0; i--)
		{
			bool has_dummy = has_free_block((block_t *)reference_node->payload, Z);
			bool reached_bucket = src == i;

			// you reached the correct bucket up in the path if src == i
			ndb[i] = ternary_op(reached_bucket, dst, BOTTOM);
			dst = ternary_op(reached_bucket, BOTTOM, dst);
			src = ternary_op(reached_bucket, BOTTOM, src);

			/*
				dst == -2 => no deeper bucket is going to be filled
				csb[i] != -2 => someone in the upper path can fill this bucket
				has_dummy => is there a free block?
				ndb[i] != -2 => or will be a block evicted?
			*/
			std::int64_t closest_src = csb[i];
			bool new_dst = (closest_src != BOTTOM) & (((dst == BOTTOM) & has_dummy) | (ndb[i] != BOTTOM));

			dst = ternary_op(new_dst, i, dst);
			src = ternary_op(new_dst, closest_src, src);

			reference_node = i ? reference_node->parent : reference_node;
		}

		// now the stash
		bool stash_reached_bucket = src == DUMMY;
		ndb[-1] = ternary_op(stash_reached_bucket, dst, BOTTOM);

		//END TARGET

		//START EVICTION

		std::uint8_t _hold[block_size];
		block_t *hold = (block_t *)_hold;
		hold->bid = DUMMY;

		bool fill_hold = ndb[-1] != BOTTOM;

		for (unsigned int i = 0; i < S; ++i)
		{
			bool deepest_block = (get_max_depth(stash[i].lid, path, L) == ljd[-1]) & fill_hold & (stash[i].bid != DUMMY);
			swap(deepest_block, _hold, (std::uint8_t *)&stash[i], block_size);
		}
		pthread_mutex_unlock(&stash_lock);
		local_subtree.unlock();
		
		dst = ndb[-1];

		for (int i = 0; i <= L; ++i)
		{
			std::int64_t next_dst = ndb[i];

			// necessary to evict hold if it is not dummy and it reached its maximum depth
			bool necessary_eviction = (i == dst) & (hold->bid != DUMMY);
			dst = ternary_op(necessary_eviction, BOTTOM, dst);

			bool swap_hold_with_valid = next_dst != BOTTOM;
			dst = ternary_op(swap_hold_with_valid, next_dst, dst);
			block_t *bl = (block_t *)reference_node->payload;
			//bool already_swapped = false;
			for (unsigned int j = 0; j < Z; ++j)
			{
				bool deepest_block = (get_max_depth(bl->lid, path, L) == ljd[i]) & (bl->bid != DUMMY);

				swap(
					(!swap_hold_with_valid & necessary_eviction & (bl->bid == DUMMY)) | (swap_hold_with_valid & deepest_block),
					_hold, (std::uint8_t *)bl, block_size);

				bl = (block_t *)((std::uint8_t *)bl + block_size);
			}
			reference_node->unlock();
			reference_node = i != L ? (path >> i) & 1 ? reference_node->child_r : reference_node->child_l : reference_node;
		}
		l_index = 0;

		pthread_mutex_lock(&multi_set_lock);
		for (i = 0; i < L; ++i)
		{
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			path_req_multi_set.erase(path_req_multi_set.find(l_index));
		}
		pthread_mutex_unlock(&multi_set_lock);

		write_queue_t T = {path, reference_node};
		local_subtree.insert_write_queue(T);

		//END EVICTION
	}

	void taostore_oram::processing_thread_wrap(void *_object)
	{
		return ((processing_thread_args_wrap *)_object)->arg1->processing_thread((void *)((processing_thread_args_wrap *)_object)->arg2);
	}

	void taostore_oram::processing_thread(void *_object)
	{
		processing_thread_args *object = (processing_thread_args *)_object;

		std::uint8_t _fetched[block_size];
		std::uint32_t evict_leaf;
		std::uint32_t paths;

		read_path(object->request, _fetched);

		answer_request(object->request, _fetched);

		evict_leaf = std::atomic_fetch_add(&evict_path, 1);
		eviction(2 * evict_leaf);
		eviction(2 * evict_leaf + 1);

		paths = std::atomic_fetch_add(&path_counter, 1);

		if ((paths % K) == 0)
			write_back(paths / K);

		return;
	}

	void taostore_oram::read_path(request_t &req, std::uint8_t *_fetched)
	{
		block_id bid;
		bool t = true;

		pthread_mutex_lock(&serializer_lck);
		for (auto &it : request_structure)
		{
			bool cond = it->bid == req.bid && it->handled == false && it->fake == false;
			replace(cond, (std::uint8_t *)&(req.fake), (std::uint8_t *)&t, sizeof(bool));
		}
		request_structure.push_back(&req);
		pthread_mutex_unlock(&serializer_lck);

		gen_rand((std::uint8_t *)&bid, sizeof(block_id));

		replace(!req.fake, (std::uint8_t *)&bid, (std::uint8_t *)&(req.bid), sizeof(block_id));

		leaf_id ev_lid;
		leaf_id path = position_map->access(bid, req.fake, &ev_lid);

		fetch_path(_fetched, bid, ev_lid, path, !req.fake);
	}

	void taostore_oram::fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool not_fake)
	{
		// always start from root
		std::int64_t l_index = 0;
		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		bool valid = false;
		int i = 0;
		block_t *bl;

		block_t *fetched = (block_t *)_fetched;
		fetched->bid = DUMMY;

		pthread_mutex_lock(&multi_set_lock);
		for (i = 0; i < L; ++i)
		{
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			path_req_multi_set.insert(l_index);
		}
		pthread_mutex_unlock(&multi_set_lock);

		l_index = 0;
		node *reference_node;
		node *old_ref_node;

		reference_node = local_subtree.root;
		old_ref_node = local_subtree.root;

		local_subtree.read_lock();
		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			if (i != 0)
				old_ref_node->unlock();

			bl = (block_t *)reference_node->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				swap(not_fake && bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
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
				swap(not_fake && bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
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

		l_index = 0;
		pthread_mutex_lock(&multi_set_lock);
		for (i = 0; i < L; ++i)
		{
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			path_req_multi_set.erase(path_req_multi_set.find(l_index));
		}
		pthread_mutex_unlock(&multi_set_lock);

		pthread_mutex_lock(&stash_lock);
		for (unsigned int i = 0; i < S; ++i)
		{
			block_id sbid = stash[i].bid;
			swap(not_fake && bid == sbid, _fetched, (std::uint8_t *)&stash[i], block_size);
		}
		fetched->lid = new_lid;
		fetched->bid = bid;

		write_queue_t T = {path, old_ref_node};
		local_subtree.insert_write_queue(T);
	}

	void taostore_oram::answer_request(request_t &req, std::uint8_t *_fetched)
	{
		block_t *fetched = (block_t *)_fetched;
		bool t = true;
		pthread_mutex_lock(&serializer_lck);
		for (auto &it : request_structure)
		{
			replace(it->id == req.id, (std::uint8_t *)&(it->handled), (std::uint8_t *)&t, sizeof(bool));
			replace(!req.fake & (it->bid == req.bid), it->data_out, (std::uint8_t *)fetched->payload, B);
			replace(!req.fake & (it->bid == req.bid), (std::uint8_t *)&(it->data_ready), (std::uint8_t *)&t, sizeof(bool));
			if (it->data_in != nullptr)
				replace(!req.fake & (it->bid == req.bid), (std::uint8_t *)fetched->payload, it->data_in, B);
		}
		pthread_cond_broadcast(&serializer_cond);
		pthread_mutex_unlock(&serializer_lck);

		bool already_evicted = false;
		for (unsigned int i = 0; i < S; ++i)
		{
			block_id sbid = stash[i].bid;
			swap(!req.fake & !already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[i], block_size);
			already_evicted = req.fake | already_evicted | (sbid == DUMMY);
		}
		assert(already_evicted);
		pthread_mutex_unlock(&stash_lock);
		local_subtree.unlock();
	}

	void taostore_oram::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		std::uint8_t _data_out[block_size];
		std::int32_t _id = std::atomic_fetch_add(&thread_id, 1);
		request_t _req = {data_in, bid, false, false, _data_out, false, false, _id, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

		struct processing_thread_args obj = {_req, bid};
		struct processing_thread_args_wrap obj_wrap = {this, &obj};

		int err = threadpool_add(thpool, processing_thread_wrap, (void *)&obj_wrap, 0);
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

	void taostore_oram::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
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

	/*	WRITEBACK CON COPIA ALBERO (NON FUNZIONANTE PER RIPORTO MAC QUANDO CANCELLO DATI
void taostore_oram::write_back(std::uint32_t c) 
	{
		
		write_queue_t _paths[3 * K];
		
		for (int i = 0; i < 3 * K; ++i)
			_paths[i] = local_subtree->get_pop_queue(); //fetch and pop

		//writelock subtree
		local_subtree->write_lock();

	
		taostore_subtree tmp_tree((size_t)Z * block_size, local_subtree->merkle_root, (uint8_t *)local_subtree->root->payload, L);

		local_subtree->update_valid(_paths, 3 * K);

		tmp_tree.copy_path(_paths, 3 * K, local_subtree);

		//use the leaf
		//local_subtree->unlock();

		leaf_id l_index;
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;

		std::map<leaf_id, node *> nodes_level_i[L + 1];
		std::map<leaf_id, node *>::iterator itx;
		nodes_level_i[L] = tmp_tree.leaf_map;

		for (int i = L; i >= 0; i--)
		{
			for (itx = nodes_level_i[i].begin(); itx != nodes_level_i[i].end(); itx++)
			{
				// generate a new random IV
				gen_rand(iv, OBL_AESGCM_IV_SIZE);

				l_index = itx->second->l_index;
				// save encrypted payload
				wc_AesGcmEncrypt(crypt_handle,
								 tree[l_index].payload,
								 (std::uint8_t *)itx->second->payload,
								 Z * block_size,
								 iv,
								 OBL_AESGCM_IV_SIZE,
								 mac,
								 OBL_AESGCM_MAC_SIZE,
								 (std::uint8_t *)itx->second->adata,
								 sizeof(auth_data_t));

				// save "mac" + iv + reachability flags
				std::memcpy(tree[l_index].mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
				std::memcpy(tree[l_index].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
				tree[l_index].reach_l = itx->second->adata->valid_l;
				tree[l_index].reach_r = itx->second->adata->valid_r;
				if (i > 0)
				{
					node *n = itx->second->parent;
					// update the mac for the parent for the evaluation of its mac
					std::uint8_t *target_mac = (l_index & 1) ? n->adata->left_mac : n->adata->right_mac;
					//l_index & 1 == 1 -> sono figlio sinistro; destro
					std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
					nodes_level_i[i - 1][get_parent(l_index)] = n;
					// move to the bucket in the upper level
				}
			}
			nodes_level_i[i].clear();
		}

		// now dump the last mac to the merkle_root!
		std::memcpy(local_subtree->merkle_root, mac, sizeof(obl_aes_gcm_128bit_tag_t));

		for (itx = tmp_tree.leaf_map.begin(); itx != tmp_tree.leaf_map.end(); itx++)
			nodes_level_i[L][itx->first] = local_subtree->leaf_map[itx->first];

		node *reference_node;
		for (int i = L; i > 0; i--)
		{
			for (itx = nodes_level_i[i].begin(); itx != nodes_level_i[i].end(); itx++)
			{
				l_index = itx->first;
				reference_node = itx->second;
				if ((reference_node->local_timestamp <= c * K))
				{
					nodes_level_i[i - 1][get_parent(l_index)] = reference_node->parent;
					if (l_index & 1)
						reference_node->parent->child_l = nullptr;
					else
						reference_node->parent->child_r = nullptr;

					delete reference_node;
					if (i == L)
						local_subtree->leaf_map.erase(l_index);
				}
			}
			nodes_level_i[i].clear();
		}
		local_subtree->unlock();
	}
*/
	// void taostore_oram::write_back(std::uint32_t c)
	// {
	// 	std::map<leaf_id, node *> nodes_level_i[L + 1];
	// 	leaf_id l_index;
	// 	obl_aes_gcm_128bit_iv_t iv;
	// 	obl_aes_gcm_128bit_tag_t mac;
	// 	node *reference_node;

	// 	write_queue_t *_paths;

	// 	_paths = local_subtree.get_pop_queue(3 * K);
	// 	pthread_mutex_lock(&write_back_lock);
	// 	nodes_level_i[L] = local_subtree.update_valid(_paths, 3 * K);

	// 	for (int i = L; i > 0; --i)
	// 	{
	// 		for (auto &itx : nodes_level_i[i])
	// 		{
	// 			l_index = itx.first;
	// 			reference_node = itx.second;
	// 			// generate a new random IV
	// 			pthread_mutex_lock(&multi_set_lock);
	// 			if (reference_node->local_timestamp <= c * K &&
	// 				reference_node->child_r == nullptr && reference_node->child_l == nullptr &&
	// 				path_req_multi_set.find(l_index) == path_req_multi_set.end())
	// 			{
	// 				node *parent = reference_node->parent;
	// 				// update the mac for the parent for the evaluation of its mac

	// 				gen_rand(iv, OBL_AESGCM_IV_SIZE);

	// 				// save encrypted payload
	// 				wc_AesGcmEncrypt(crypt_handle,
	// 								 tree[l_index].payload,
	// 								 (std::uint8_t *)reference_node->payload,
	// 								 Z * block_size,
	// 								 iv,
	// 								 OBL_AESGCM_IV_SIZE,
	// 								 mac,
	// 								 OBL_AESGCM_MAC_SIZE,
	// 								 (std::uint8_t *)&reference_node->adata,
	// 								 sizeof(auth_data_t));

	// 				// save "mac" + iv + reachability flags
	// 				std::memcpy(tree[l_index].mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
	// 				std::memcpy(tree[l_index].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
	// 				tree[l_index].reach_l = reference_node->adata.valid_l;
	// 				tree[l_index].reach_r = reference_node->adata.valid_r;

	// 				nodes_level_i[i - 1][get_parent(l_index)] = parent;

	// 				std::uint8_t *target_mac = (l_index & 1) ? parent->adata.left_mac : parent->adata.right_mac;
	// 				std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));

	// 				if (l_index & 1)
	// 					parent->child_l = nullptr;
	// 				else
	// 					parent->child_r = nullptr;
	// 				delete reference_node;
	// 			}
	// 			pthread_mutex_unlock(&multi_set_lock);
	// 		}
	// 	}

	// 	pthread_mutex_unlock(&write_back_lock);

	// 	delete _paths;
	// }

	void taostore_oram::write_back(std::uint32_t c)
	{
		std::map<leaf_id, node *> nodes_level_i[L + 1];
		leaf_id l_index;
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;
		node *reference_node;

		write_queue_t *_paths;

		_paths = local_subtree.get_pop_queue(3 * K);
		pthread_mutex_lock(&write_back_lock);
		nodes_level_i[L] = local_subtree.update_valid(_paths, 3 * K);

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
		/*		reference_node = local_subtree.root;
		gen_rand(iv, OBL_AESGCM_IV_SIZE);

		// save encrypted payload
		wc_AesGcmEncrypt(crypt_handle,
						 tree[0].payload,
						 (std::uint8_t *)reference_node->payload,
						 Z * block_size,
						 iv,
						 OBL_AESGCM_IV_SIZE,
						 mac,
						 OBL_AESGCM_MAC_SIZE,
						 (std::uint8_t *)&reference_node->adata,
						 sizeof(auth_data_t));

		// save "mac" + iv + reachability flags
		std::memcpy(tree[0].mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
		std::memcpy(tree[0].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
		tree[0].reach_l = reference_node->adata.valid_l;
		tree[0].reach_r = reference_node->adata.valid_r;

		std::memcpy(merkle_root, mac, sizeof(obl_aes_gcm_128bit_tag_t));*/
		pthread_mutex_unlock(&write_back_lock);
		delete _paths;
	}

	void taostore_oram::printstash()
	{
		for (unsigned int i = 0; i < S; ++i)
			std::cerr << "stash " << i << "bid: " << (block_id)stash[i].bid << "lid :" << (leaf_id)stash[i].lid << " data: " << (std::uint64_t) * ((std::uint64_t *)stash[i].payload) << std::endl;
	}
	void taostore_oram::printsubtree()
	{
		int i;
		i = printrec(local_subtree.root, L, 0);
		std::cerr << "-------------" << i << "----------------" << std::endl;
	}
	int taostore_oram::printrec(node *t, int l, int l_index)
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
	void taostore_oram::print_tree()
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