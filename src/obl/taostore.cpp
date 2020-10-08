#include "obl/utils.h"
#include "obl/taostore.h"
#include "obl/primitives.h"

#include "obl/oassert.h"

#include <map>
#include <cstdlib>
#include <iostream>
#include <cstring>

//#include "sgx_trts.h"
#define DUMMY -1
#define BOTTOM -2
#define K 8

namespace obl
{
	struct processing_thread_args
	{
		taostore_request_t *request;
		block_id bid;
	};
	struct processing_thread_args_wrap
	{
		taostore_oram *arg1;
		processing_thread_args *arg2;
	};

	taostore_oram::taostore_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S) : tree_oram(N, B, Z)
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

		for (unsigned int i = 0; i < this->S; i++)
			stash[i].bid = DUMMY;

		// ORAM tree allocation
		tree.set_entry_size(bucket_size);
		tree.reserve(capacity);

		init();
		oram_alive = true;
		pthread_create(&serializer_id, nullptr, serializer_wrap, (void *)this);
	}

	taostore_oram::~taostore_oram()
	{
		std::memset(_crypt_buffer, 0x00, sizeof(Aes) + 16);

		std::memset(&stash[0], 0x00, block_size * S);
		// std::memset(&fetched_path[0], 0x00, block_size * (L + 1) * Z);

		free(_crypt_buffer);

		//i have to put dummy data in req structure
		pthread_mutex_lock(&serializer_lck);
		oram_alive = false;
		pthread_cond_signal(&serializer_cond);
		pthread_mutex_unlock(&serializer_lck);

		pthread_join(serializer_id, nullptr);
	}

	void taostore_oram::init()
	{
		obl_aes_gcm_128bit_key_t master_key;
		obl_aes_gcm_128bit_iv_t iv;

		obl_aes_gcm_128bit_tag_t merkle_root;
		auth_data_t empty_auth;
		std::uint8_t empty_bucket[Z * block_size];

		std::atomic_init(&evict_path, 0);
		std::atomic_init(&path_counter, 0);
		std::atomic_init(&pthread_alive, 0);

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

		allocator = new circuit_fake_factory(Z, S);
		position_map = new taostore_position_map(N, sizeof(int64_t), 5, allocator);
		local_subtree = new taostore_subtree((size_t)Z * block_size, merkle_root, empty_bucket, L);
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
				pthread_mutex_lock(request_structure.front()->cond_mutex);
				request_structure.front()->res_ready = true;
				pthread_cond_broadcast(request_structure.front()->serializer_res_ready);
				pthread_mutex_unlock(request_structure.front()->cond_mutex);
				request_structure.pop_front();
			}
			pthread_mutex_unlock(&serializer_lck);
		}
		return 0;
	}

	bool taostore_oram::has_free_block(block_t *bl, int len)
	{
		bool free_block = false;

		for (int i = 0; i < len; i++)
		{
			free_block |= bl->bid == DUMMY;
			bl = (block_t *)((std::uint8_t *)bl + block_size);
		}

		return free_block;
	}

	std::int64_t taostore_oram::get_max_depth_bucket(block_t *bl, int len, leaf_id path)
	{
		std::int64_t max_d = -1;

		for (int i = 0; i < len; i++)
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

		//TODO implement PATHREQUESTMULTISET
		std::int64_t l_index = 0;
		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		bool in_subtree = true;
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

		local_subtree->write_lock();
		reference_node = local_subtree->root;

		goal = get_max_depth_bucket(&stash[0], S, path);
		ljd[-1] = goal;
		csb[-1] = BOTTOM;

		//START DEEPEST
		for (i = 0; i <= L && in_subtree; i++)
		{
			csb[i] = ternary_op(goal >= i, _closest_src_bucket, BOTTOM);
			std::int64_t jump = get_max_depth_bucket(reference_node->payload, Z, path);
			ljd[i] = jump;
			_closest_src_bucket = ternary_op(jump >= goal, i, _closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);

			old_ref_node = reference_node;
			reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;

			if (reference_node == nullptr)
			{
				in_subtree = false;
				valid = (path >> i) & 1 ? tree[l_index].reach_r : tree[l_index].reach_l;
				l_index = (l_index << 1) + 1 + ((path >> i) & 1);

				if (valid)
				{
					std::uint8_t *src = tree[l_index].mac;
					std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
				}
			}
		}

		//TODO test the valid case (after writeBack)
		while (i <= L && valid)
		{
			(path >> (i - 1)) & 1 ? old_ref_node->child_r = new node(block_size * Z, path_counter, l_index) : old_ref_node->child_l = new node(block_size * Z, path_counter, l_index);
			reference_node = (path >> (i - 1)) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
			reference_node->parent = old_ref_node;

			adata = reference_node->adata;

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
			std::int64_t jump = get_max_depth_bucket(reference_node->payload, Z, path);
			ljd[i] = jump;
			_closest_src_bucket = ternary_op(jump >= goal, i, _closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);

			old_ref_node = reference_node;

			valid = (path >> i) & 1 ? adata->valid_r : adata->valid_l;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			if (valid)
			{
				std::uint8_t *src = ((path >> i) & 1) ? adata->right_mac : adata->left_mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
			i++;
		}

		// fill the other buckets with "empty" blocks
		while (i <= L)
		{
			(path >> (i - 1)) & 1 ? old_ref_node->child_r = new node(block_size * Z, path_counter, l_index) : old_ref_node->child_l = new node(block_size * Z, path_counter, l_index);
			reference_node = (path >> (i - 1)) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
			reference_node->parent = old_ref_node;

			for (unsigned int j = 0; j < Z; j++)
				((block_t *)((std::uint8_t *)reference_node->payload + block_size * j))->bid = DUMMY;

			csb[i] = ternary_op(goal >= i, _closest_src_bucket, BOTTOM);
			std::int64_t jump = get_max_depth_bucket(reference_node->payload, Z, path);
			ljd[i] = jump;
			_closest_src_bucket = ternary_op(jump >= goal, i, _closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);

			old_ref_node = reference_node;

			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			i++;
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
			bool has_dummy = has_free_block(reference_node->payload, Z);
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

			reference_node = i ? reference_node->parent : reference_node; //non farlo quando si è al root
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

		for (unsigned int i = 0; i < S; i++)
		{
			bool deepest_block = (get_max_depth(stash[i].lid, path, L) == ljd[-1]) & fill_hold & (stash[i].bid != DUMMY);
			swap(deepest_block, _hold, (std::uint8_t *)&stash[i], block_size);
		}

		dst = ndb[-1];

		for (int i = 0; i <= L; i++)
		{
			std::int64_t next_dst = ndb[i];

			// necessary to evict hold if it is not dummy and it reached its maximum depth
			bool necessary_eviction = (i == dst) & (hold->bid != DUMMY);
			dst = ternary_op(necessary_eviction, BOTTOM, dst);

			bool swap_hold_with_valid = next_dst != BOTTOM;
			dst = ternary_op(swap_hold_with_valid, next_dst, dst);
			block_t *bl = reference_node->payload;
			//bool already_swapped = false;
			for (unsigned int j = 0; j < Z; j++)
			{
				bool deepest_block = (get_max_depth(bl->lid, path, L) == ljd[i]) & (bl->bid != DUMMY);

				swap(
					(!swap_hold_with_valid & necessary_eviction & (bl->bid == DUMMY)) | (swap_hold_with_valid & deepest_block),
					_hold, (std::uint8_t *)bl, block_size);

				bl = (block_t *)((std::uint8_t *)bl + block_size);
			}
			reference_node->local_timestamp = path_counter;
			reference_node = i != L ? (path >> i) & 1 ? reference_node->child_r : reference_node->child_l : reference_node;
		}

		//puntatore alle foglie
		local_subtree->insert_leaf_pointer(access_counter, reference_node);

		local_subtree->unlock();
		//END EVICTION
	}

	void *taostore_oram::processing_thread_wrap(void *_object)
	{
		return ((processing_thread_args_wrap *)_object)->arg1->processing_thread((void *)((processing_thread_args_wrap *)_object)->arg2);
	}

	void *taostore_oram::processing_thread(void *_object)
	{
		pthread_alive++;
		processing_thread_args *object = (processing_thread_args *)_object;
		request_t *request = object->request;
		std::uint8_t _fetched[block_size];

		read_path(request, _fetched);
		answer_request(request, _fetched);

		std::uint64_t evict_leaf = (std::uint64_t)std::atomic_fetch_add(&evict_path, 1);
		eviction(2 * evict_leaf);
		eviction(2 * evict_leaf + 1);
		//TODO paths counter in buckets

		local_subtree->insert_write_queue(2 * evict_leaf);
		local_subtree->insert_write_queue(2 * evict_leaf + 1);

		std::uint64_t paths = (std::uint64_t)std::atomic_fetch_add(&path_counter, 1);

		if (paths % K)
			write_back(paths / K);

		pthread_alive--;
		return 0;
	}

	void taostore_oram::read_path(request_t *req, std::uint8_t *_fetched)
	{

		block_id bid;
		bool t = true;

		pthread_mutex_lock(&serializer_lck);
		for (it = request_structure.begin(); it < request_structure.end(); it++)
		{
			bool cond = (*it)->bid == req->bid && (*it)->handled == false && (*it)->fake == false;
			replace(cond, (std::uint8_t *)&(req->fake), (std::uint8_t *)&t, sizeof(bool));
		}
		request_structure.push_back(req);
		pthread_mutex_unlock(&serializer_lck);

		gen_rand((std::uint8_t *)&bid, sizeof(block_id));
		replace(!req->fake, (std::uint8_t *)&bid, (std::uint8_t *)&(req->bid), sizeof(block_id));

		leaf_id ev_lid;
		leaf_id path = position_map->access(bid, req->fake, &ev_lid);

		fetch_path(_fetched, bid, ev_lid, path);
	}

	void taostore_oram::fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path)
	{
		// always start from root
		std::int64_t l_index = 0;
		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		bool in_subtree = true;
		bool valid = true;
		int i = 0;

		block_t *fetched = (block_t *)_fetched;
		fetched->bid = DUMMY;

		//TODO implement PATHREQUESTMULTISET
		node *reference_node;
		node *old_ref_node;

		local_subtree->read_lock();
		reference_node = local_subtree->root;

		block_t *bl;

		for (i = 0; i <= L && in_subtree; i++)
		{
			reference_node->lock();
			if (i != 0)
				old_ref_node->unlock();

			bl = reference_node->payload;
			for (unsigned int j = 0; j < Z; j++)
			{
				block_id fpbid = bl->bid;
				swap(fpbid == bid, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}
			reference_node->local_timestamp = path_counter;

			old_ref_node = reference_node;
			reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;

			if (reference_node == nullptr)
			{
				in_subtree = false;
				valid = (path >> i) & 1 ? tree[l_index].reach_r : tree[l_index].reach_l;
				l_index = (l_index << 1) + 1 + ((path >> i) & 1);

				if (valid)
				{
					std::uint8_t *src = tree[l_index].mac;
					std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
				}
			}
		}

		//TODO check if aesgcm works
		while (i <= L && valid)
		{
			(path >> (i - 1)) & 1 ? old_ref_node->child_r = new node(block_size * Z, path_counter, l_index) : old_ref_node->child_l = new node(block_size * Z, path_counter, l_index);
			reference_node = (path >> (i - 1)) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
			reference_node->parent = old_ref_node;

			reference_node->lock();
			old_ref_node->unlock();

			adata = reference_node->adata;

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

			bl = reference_node->payload;
			for (unsigned int j = 0; j < Z; j++)
			{
				block_id fpbid = bl->bid;
				swap(fpbid == bid, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}

			old_ref_node = reference_node;

			valid = (path >> i) & 1 ? adata->valid_r : adata->valid_l;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			if (valid)
			{
				std::uint8_t *src = ((path >> i) & 1) ? adata->right_mac : adata->left_mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
			i++;
		}

		// fill the other buckets with "empty" blocks
		while (i <= L)
		{
			(path >> (i - 1)) & 1 ? old_ref_node->child_r = new node(block_size * Z, path_counter, l_index) : old_ref_node->child_l = new node(block_size * Z, path_counter, l_index);
			reference_node = (path >> (i - 1)) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
			reference_node->parent = old_ref_node;

			reference_node->lock();
			old_ref_node->unlock();

			bl = reference_node->payload;

			for (unsigned int j = 0; j < Z; j++)
			{
				bl->bid = DUMMY;
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}

			old_ref_node = reference_node;

			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}

		local_subtree->insert_leaf_pointer(path, old_ref_node);

		pthread_mutex_lock(&stash_lock);
		old_ref_node->unlock();
		for (unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(bid == sbid, _fetched, (std::uint8_t *)&stash[i], block_size);
		}

		fetched->lid = new_lid;
		fetched->bid = bid;

		pthread_mutex_unlock(&stash_lock);
		local_subtree->unlock();
		local_subtree->insert_write_queue(path);
	}

	void taostore_oram::answer_request(request_t *req, std::uint8_t *_fetched)
	{
		block_t *fetched = (block_t *)_fetched;
		bool t = true;
		pthread_mutex_lock(&serializer_lck);
		for (it = request_structure.begin(); it < request_structure.end(); it++)
		{
			replace(*(*it)->thread_id == pthread_self(), (std::uint8_t *)&((*it)->handled), (std::uint8_t *)&t, sizeof(bool));
			replace(!req->fake && (*it)->bid == req->bid, (*it)->data_out, (std::uint8_t *)fetched->payload, B);
			//NON VA BENE PERCHÈ DATA_IN È NULLPTR
			replace(!req->fake && (*it)->bid == req->bid, (std::uint8_t *)&((*it)->data_ready), (std::uint8_t *)&t, sizeof(bool));
			if ((*it)->data_in != nullptr)
				replace(!req->fake && (*it)->bid == req->bid, (std::uint8_t *)fetched->payload, (*it)->data_in, B);
		}

		//TODO per adesso faccio cosi, poi dopo quando modifico w/r lock cambio
		local_subtree->read_lock();
		pthread_mutex_lock(&stash_lock);

		bool already_evicted = false;
		for (unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}

		if (!already_evicted)
			printstash();

		assert(already_evicted);
		pthread_mutex_unlock(&stash_lock);
		local_subtree->unlock();
		pthread_cond_broadcast(&serializer_cond);
		pthread_mutex_unlock(&serializer_lck);
	}

	void taostore_oram::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		pthread_mutex_t _cond_mutex = PTHREAD_MUTEX_INITIALIZER;
		pthread_cond_t _serializer_res_ready = PTHREAD_COND_INITIALIZER;
		pthread_t proces;
		std::uint8_t _data_out[B];

		request_t _req = {data_in, bid, false, false, _data_out, false, false, &proces, &_cond_mutex, &_serializer_res_ready};
		struct processing_thread_args obj = {&_req, bid};
		struct processing_thread_args_wrap obj_wrap = {this, &obj};
		pthread_create(&proces, nullptr, processing_thread_wrap, (void *)&obj_wrap);
		pthread_detach(proces);
		//wait on the conditional var
		pthread_mutex_lock(&_cond_mutex);
		while (!_req.res_ready)
		{ // or even "while" instead of "if"
			pthread_cond_wait(&_serializer_res_ready, &_cond_mutex);
		}
		pthread_mutex_unlock(&_cond_mutex);

		std::memcpy(data_out, (std::uint8_t *)_data_out, B);
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
		for (unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}

		assert(already_evicted);

		std::uint64_t evict_leaf = (std::uint64_t)std::atomic_fetch_add(&evict_path, 1);
		eviction(2 * evict_leaf);
		eviction(2 * evict_leaf + 1);

		local_subtree->insert_write_queue(2 * evict_leaf);
		local_subtree->insert_write_queue(2 * evict_leaf + 1);

		if (evict_path % K)
			write_back(evict_path / K);

		return;
	}

	void taostore_oram::write_back(std::uint32_t c)
	{
		leaf_id paths[3 * K];
		for (int i = 0; i < K; i++)
			paths[i] = local_subtree->get_pop_queue(); //fetch and pop

		//writelock subtree
		local_subtree->write_lock();

		taostore_subtree tmp_tree((size_t)Z * block_size, local_subtree->merkle_root, (uint8_t *)local_subtree->root->payload, L);

		tmp_tree.copy_path(paths, 3*K, local_subtree);
		
		//use the leaf
		local_subtree->unlock();
		
		tmp_tree.update_valid(paths, 3*K); 

		leaf_id path;
		std::int64_t leaf;
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;
		bool reachable = true;

		std::map<leaf_id, node *> nodes_level_i[L + 1];
		std::map<leaf_id, node *>::iterator itx;
		nodes_level_i[L] = tmp_tree.leaf_map;

		for (int i = L; i >= 0; i--)
		{
			for (itx = nodes_level_i[i].begin(); itx != nodes_level_i[i].end(); itx++)
			{
				// generate a new random IV
				gen_rand(iv, OBL_AESGCM_IV_SIZE);

				// save encrypted payload
				wc_AesGcmEncrypt(crypt_handle,
								 tree[leaf].payload,
								 (std::uint8_t *)itx->second->payload,
								 Z * block_size,
								 iv,
								 OBL_AESGCM_IV_SIZE,
								 mac,
								 OBL_AESGCM_MAC_SIZE,
								 (std::uint8_t *)itx->second->adata,
								 sizeof(auth_data_t));

				// save "mac" + iv + reachability flags
				std::memcpy(tree[leaf].mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
				std::memcpy(tree[leaf].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
				tree[leaf].reach_l = itx->second->adata->valid_l;
				tree[leaf].reach_r = itx->second->adata->valid_r;
				if (i > 0)
				{

					node *n = itx->second->parent;
					// update the mac for the parent for the evaluation of its mac
					std::uint8_t *target_mac = ((itx->first >> (i - 1)) & 1) ? n->adata->right_mac : n->adata->left_mac;
					std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));

					nodes_level_i[i - 1][get_parent(itx->first)] = n;
					// move to the bucket in the upper level
				}
			}
		}
		// now dump the last mac to the merkle_root!
		std::memcpy(merkle_root, mac, sizeof(obl_aes_gcm_128bit_tag_t));
		//TODO(with server timestamp c)
		//TODO delete from subtree the buckets no more necessary
	}


	void taostore_oram::printstash()
	{
		for (unsigned int i = 0; i < S; i++)
			std::cerr << "stash " << i << "bid: " << (block_id)stash[i].bid << "lid :" << (leaf_id)stash[i].lid << " data: " << (std::uint64_t) * ((std::uint64_t *)stash[i].payload) << std::endl;
	}
	void taostore_oram::printsubtree()
	{
		printrec(local_subtree->root, L);
	}
	void taostore_oram::printrec(node *t, int l)
	{
		block_t *bl = t->payload;
		for (int i = 0; i < Z; i++)
		{
			std::cerr << "node lvl:" << L - l << "bid: " << bl->bid << "lid :" << bl->lid << " data: " << (std::uint64_t) * ((std::uint64_t *)bl->payload) << std::endl;
			bl = (block_t *)((std::uint8_t *)bl + block_size);
		}

		if (l == 0)
			return;
		else
		{
			printrec(t->child_l, l - 1);
			printrec(t->child_r, l - 1);
		}
	}

} // namespace obl