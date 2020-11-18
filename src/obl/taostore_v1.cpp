#include "obl/utils.h"
#include "obl/primitives.h"
#include "obl/taostore_v1.h"

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

	void taostore_oram_v1::eviction(leaf_id path)
	{

		std::int64_t l_index = 0;
		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		block_t *bl;
		bool valid = false;
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
		std::int64_t goal_t = -1;

		node *reference_node, *old_ref_node;
		reference_node = local_subtree.root;
		old_ref_node = local_subtree.root;

		multiset_lock(path);

		for (unsigned int i = 0; i < SS - 1; ++i)
		{
			pthread_mutex_lock(&stash_locks[i]);
			goal_t = get_max_depth_bucket(&stash[i * ss], ss, path);
			goal = ternary_op(goal > goal_t, goal, goal_t);
		}
		pthread_mutex_lock(&stash_locks[SS - 1]);
		goal_t = get_max_depth_bucket(&stash[(SS - 1) * ss], S % ss, path);
		goal = ternary_op(goal > goal_t, goal, goal_t);

		ljd[-1] = goal;
		csb[-1] = BOTTOM;

		//START DEEPEST
		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			reference_node->local_timestamp = access_counter;

			csb[i] = ternary_op(goal >= i, _closest_src_bucket, BOTTOM);
			std::int64_t jump = get_max_depth_bucket((block_t *)reference_node->payload, Z, path);
			ljd[i] = jump;
			_closest_src_bucket = ternary_op(jump >= goal, i, _closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);

			old_ref_node = reference_node;

			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
		}
		if (i <= L)
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
			(l_index & 1) ? old_ref_node->child_l = new node(block_size * Z, access_counter) : old_ref_node->child_r = new node(block_size * Z, access_counter);
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
			(l_index & 1) ? old_ref_node->child_l = new node(block_size * Z, access_counter) : old_ref_node->child_r = new node(block_size * Z, access_counter);
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

		for (unsigned int i = 0; i < SS - 1; ++i)
		{
			for (unsigned int j = 0; j < ss; ++j)
			{
				bool deepest_block = (get_max_depth(stash[i * ss + j].lid, path, L) == ljd[-1]) & fill_hold & (stash[i * ss + j].bid != DUMMY);
				swap(deepest_block, _hold, (std::uint8_t *)&stash[i * ss + j], block_size);
			}
			pthread_mutex_unlock(&stash_locks[i]);
		}
		for (unsigned int i = 0; i < S % ss; ++i)
		{
			bool deepest_block = (get_max_depth(stash[(SS - 1) * ss + i].lid, path, L) == ljd[-1]) & fill_hold & (stash[(SS - 1) * ss + i].bid != DUMMY);
			swap(deepest_block, _hold, (std::uint8_t *)&stash[(SS - 1) * ss + i], block_size);
		}
		pthread_mutex_unlock(&stash_locks[SS - 1]);

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
		multiset_unlock(path);

		write_queue_t T = {path, reference_node};
		local_subtree.insert_write_queue(T);

		//END EVICTION
	}

	void taostore_oram_v1::access_thread(request_t &_req)
	{

		std::uint8_t _fetched[block_size];
		std::uint32_t evict_leaf;
		std::uint32_t paths;

		read_path(_req, _fetched);

		answer_request(_req, _fetched);

		evict_leaf = std::atomic_fetch_add(&evict_path, 1);

		eviction(2 * evict_leaf);
		eviction(2 * evict_leaf + 1);

		paths = std::atomic_fetch_add(&access_counter, 1);

		if ((3 * paths) % K == 0)
			write_back((3 * paths) / K);

		return;
	}

	void taostore_oram_v1::fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool not_fake)
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
		fetched->lid = DUMMY;

		node *reference_node;
		node *old_ref_node;

		reference_node = local_subtree.root;
		old_ref_node = local_subtree.root;

		multiset_lock(path);

		pthread_mutex_lock(&stash_locks[0]);
		for (unsigned int i = 0; i < SS - 1; ++i)
		{
			for (unsigned int j = 0; j < ss; ++j)
			{
				block_id sbid = stash[i * ss + j].bid;
				swap(not_fake && bid == sbid, _fetched, (std::uint8_t *)&stash[i * ss + j], block_size);
			}
			pthread_mutex_lock(&stash_locks[i + 1]);
			pthread_mutex_unlock(&stash_locks[i]);
		}
		for (unsigned int i = 0; i < S % ss; ++i)
		{
			block_id sbid = stash[(SS - 1) * ss + i].bid;
			swap(not_fake && bid == sbid, _fetched, (std::uint8_t *)&stash[(SS - 1) * ss + i], block_size);
		}
		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			if (i != 0)
				old_ref_node->unlock();
			else
				pthread_mutex_unlock(&stash_locks[SS - 1]);

			bl = (block_t *)reference_node->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				swap(not_fake & bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}
			reference_node->local_timestamp = access_counter;
			old_ref_node = reference_node;

			reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
		}

		if (i <= L)
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
			(l_index & 1) ? old_ref_node->child_l = new node(block_size * Z, access_counter) : old_ref_node->child_r = new node(block_size * Z, access_counter);
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
			(l_index & 1) ? old_ref_node->child_l = new node(block_size * Z, access_counter) : old_ref_node->child_r = new node(block_size * Z, access_counter);
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
		fetched->bid = bid;

		write_queue_t T = {path, old_ref_node};
		local_subtree.insert_write_queue(T);
	}

	void taostore_oram_v1::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		std::uint8_t _data_out[B];
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

	void taostore_oram_v1::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
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

} // namespace obl
