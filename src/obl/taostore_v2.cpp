#include "obl/utils.h"
#include "obl/taostore_v2.h"
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

	void taostore_oram_v2::eviction(leaf_id path)
	{
		std::int64_t l_index = 0;
		std::vector<std::shared_ptr<node>> fetched_path;
		fetched_path.reserve(L + 1);

		// for (int i = 0; i < L + 1; i++)
		// 	fetched_path.emplace_back((block_size * Z));

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

		std::shared_ptr<node>reference_node;
		std::shared_ptr<node>old_ref_node;
		reference_node = local_subtree.getroot();
		old_ref_node = local_subtree.getroot();

		// multiset_lock(path);

		local_subtree.read_lock();
		download_path(path, fetched_path);

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
		while (i <= L)
		{
			(l_index & 1) ? old_ref_node->child_l = fetched_path[i] : old_ref_node->child_r = fetched_path[i];
			reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
			reference_node->parent = old_ref_node;

			reference_node->lock();

			csb[i] = ternary_op(goal >= i, _closest_src_bucket, BOTTOM);

			std::int64_t jump = get_max_depth_bucket((block_t *)reference_node->payload, Z, path);
			ljd[i] = jump;

			_closest_src_bucket = ternary_op(jump >= goal, i, _closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);

			reference_node->local_timestamp = access_counter;

			old_ref_node = reference_node;
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
		// multiset_unlock(path);
		local_subtree.unlock();

		fetched_path.clear();
		local_subtree.insert_write_queue(path);

		//END EVICTION
	}

	void taostore_oram_v2::access_thread(request_t &_req)
	{
		std::uint8_t _fetched[block_size];
		std::int32_t evict_leaf;
		std::uint64_t paths;

		read_path(_req, _fetched);

		answer_request(_req.fake, _req.bid, _req.id, _fetched);

		evict_leaf = evict_path++;

		eviction(2 * evict_leaf);
		eviction(2 * evict_leaf + 1);

		paths = access_counter++;

		if (paths % K == 0)
			write_back(paths / K);
	}

	// void taostore_oram_v2::download_path(leaf_id path, std::vector<std::shared_ptr<node>> fetched_path)
	// {
	// 	// always start from root
	// 	std::int64_t l_index = 0;
	// 	block_t *bl;
	// 	int i;

	// 	// start verifying the mac stored in the root, from the SAFE part of the memory
	// 	obl_aes_gcm_128bit_tag_t reference_mac;
	// 	/*
	// 		the additional method init (to be refined in the SGX deployment) actually inits
	// 		the root node in a proper way, storing the correct "accessed" flags inside
	// 		the root bucket. So the mac there contained in the root will always be valid
	// 	*/
	// 	bool reachable = (path & 1) ? tree[l_index].reach_r : tree[l_index].reach_l;
	// 	// evaluate the next encrypted bucket index in the binary heap
	// 	l_index = (l_index << 1) + 1 + ((path)&1);

	// 	if (reachable)
	// 	{
	// 		std::uint8_t *src = tree[l_index].mac;
	// 		std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
	// 	}

	// 	for (i = 1; i <= L && reachable; i++)
	// 	{

	// 		std::int64_t leftch = get_left(l_index);
	// 		std::int64_t rightch = get_right(l_index);

	// 		// this data will be authenticated data in the GCM mode
	// 		// dump from encrypted bucket header
	// 		fetched_path[i]->adata.valid_l = tree[l_index].reach_l;
	// 		fetched_path[i]->adata.valid_r = tree[l_index].reach_r;

	// 		// dump left and right child mac if valid, otherwise pad with 0s
	// 		if (fetched_path[i]->adata.valid_l)
	// 			std::memcpy(fetched_path[i]->adata.left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

	// 		if (fetched_path[i]->adata.valid_r)
	// 			std::memcpy(fetched_path[i]->adata.right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

	// 		// if they are not valid, authentication data for the corresponding mac would be 0x00..0
	// 		// however this was already covered by the memset before the loop

	// 		// decrypt using the IV
	// 		wc_AesGcmDecrypt(crypt_handle,
	// 						 fetched_path[i]->payload,
	// 						 tree[l_index].payload,
	// 						 Z * block_size,
	// 						 tree[l_index].iv,
	// 						 OBL_AESGCM_IV_SIZE,
	// 						 reference_mac,
	// 						 OBL_AESGCM_MAC_SIZE,
	// 						 (std::uint8_t *)&fetched_path[i]->adata,
	// 						 sizeof(auth_data_t));

	// 		// MAC mismatch is a critical error
	// 		//assert(dec != AES_GCM_AUTH_E);
	// 		// assert(dec == 0);

	// 		/*
	// 			NB: this doesn't need to be oblivious since an attacker might always see
	// 			the sequences of accesses to the buckets and understand whether or not a
	// 			bucket has already been accessed
	// 			NB 2: fetch this from data which was dumped and authenticated, and taken
	// 			from PROTECTED MEMORY. This should avoid some kind of attacks
	// 		*/
	// 		reachable = (path >> i) & 1 ? fetched_path[i]->adata.valid_r : fetched_path[i]->adata.valid_l;
	// 		// evaluate the next encrypted bucket index in the binary heap
	// 		l_index = (l_index << 1) + 1 + ((path >> i) & 1);

	// 		if (reachable)
	// 		{
	// 			std::uint8_t *src = ((path >> i) & 1) ? fetched_path[i]->adata.right_mac : fetched_path[i]->adata.left_mac;
	// 			std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
	// 		}
	// 	}

	// 	// fill the other buckets with "empty" blocks
	// 	while (i <= L)
	// 	{

	// 		bl = (block_t *)fetched_path[i]->payload;
	// 		for (unsigned int j = 0; j < Z; ++j)
	// 		{
	// 			bl->bid = DUMMY;
	// 			bl = (block_t *)((std::uint8_t *)bl + block_size);
	// 		}
	// 		++i;
	// 	}
	// }

	void taostore_oram_v2::download_path(leaf_id path, std::vector<std::shared_ptr<node>> &fetched_path)
	{
		// always start from root
		std::int64_t l_index = 0;
		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		bool valid = false;
		int i = 0;
		block_t *bl;

		std::shared_ptr<node>reference_node = local_subtree.getroot();
		std::shared_ptr<node>old_ref_node = local_subtree.getroot();

		fetched_path.reserve(L + 1);

		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			fetched_path.emplace_back(nullptr);

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
			fetched_path.emplace_back(std::make_shared<node>(block_size * Z));

			adata = &fetched_path[i]->adata;
			std::int64_t leftch = get_left(l_index);
			std::int64_t rightch = get_right(l_index);

			// this data will be authenticated data in the GCM mode
			// dump from encrypted bucket header
			adata->valid_l = tree[l_index].reach_l;
			adata->valid_r = tree[l_index].reach_r;

			// dump left and right child mac if valid, otherwise pad with 0s
			if (adata->valid_l)
				std::memcpy(fetched_path[i]->adata.left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			if (adata->valid_r)
				std::memcpy(fetched_path[i]->adata.right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			// if they are not valid, authentication data for the corresponding mac would be 0x00..0
			// however this was already covered by the memset before the loop

			// decrypt using the IV
			wc_AesGcmDecrypt(crypt_handle,
							 fetched_path[i]->payload,
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
			// assert(dec == 0);

			/*
				NB: this doesn't need to be oblivious since an attacker might always see
				the sequences of accesses to the buckets and understand whether or not a
				bucket has already been accessed
				NB 2: fetch this from data which was dumped and authenticated, and taken
				from PROTECTED MEMORY. This should avoid some kind of attacks
			*/
			// evaluate the next encrypted bucket index in the binary heap
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
			fetched_path.push_back(std::make_shared<node>(block_size * Z));
			bl = (block_t *)fetched_path[i]->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				bl->bid = DUMMY;
				bl = (block_t *)((std::uint8_t *)bl + block_size);
			}
			++i;
		}
	}

	void taostore_oram_v2::fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool not_fake)
	{
		// always start from root
		std::int64_t l_index = 0;
		int i = 0;
		block_t *bl;
		block_t *fetched = (block_t *)_fetched;
		fetched->bid = DUMMY;
		fetched->lid = DUMMY;

		std::vector<std::shared_ptr<node>> fetched_path;

		//fetch_path della circuit.
		std::shared_ptr<node>reference_node;
		std::shared_ptr<node>old_ref_node;
		old_ref_node = local_subtree.getroot();
		reference_node = local_subtree.getroot();

		// multiset_lock(path);

		local_subtree.read_lock();
		download_path(path, fetched_path);

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
				swap(not_fake && bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}
			reference_node->local_timestamp = access_counter;
			old_ref_node = reference_node;

			reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;

			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
		}

		while (i <= L)
		{
			(l_index & 1) ? old_ref_node->child_l = fetched_path[i] : old_ref_node->child_r = fetched_path[i];
			reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
			reference_node->parent = old_ref_node;

			reference_node->lock();
			old_ref_node->unlock();

			bl = (block_t *)reference_node->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				swap(not_fake && bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}

			reference_node->local_timestamp = access_counter;
			old_ref_node = reference_node;

			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}

		old_ref_node->unlock();
		local_subtree.unlock();
		// multiset_unlock(path);

		fetched->lid = new_lid;
		fetched->bid = bid;

		fetched_path.clear();
		local_subtree.insert_write_queue(path);
	}

	void taostore_oram_v2::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
	{
		std::uint8_t _fetched[block_size];
		std::uint32_t evict_leaf;
		std::uint64_t paths;

		block_t *fetched = (block_t *)_fetched;

		// build the block to write!
		fetched->bid = bid;
		fetched->lid = next_lif;
		std::memcpy(fetched->payload, data_in, B);

		// evict the created block to the stash
		bool already_evicted = false;

		pthread_mutex_lock(&stash_locks[0]);
		for (unsigned int i = 0; i < SS - 1; ++i)
		{
			for (unsigned int j = 0; j < ss; ++j)
			{
				block_id sbid = stash[i * ss + j].bid;
				swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[i * ss + j], block_size);
				already_evicted = already_evicted | (sbid == DUMMY);
			}
			pthread_mutex_lock(&stash_locks[i + 1]);
			pthread_mutex_unlock(&stash_locks[i]);
		}
		for (unsigned int i = 0; i < S % ss; ++i)
		{
			block_id sbid = stash[(SS - 1) * ss + i].bid;
			swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[(SS - 1) * ss + i], block_size);
			already_evicted = already_evicted | (sbid == DUMMY);
		}
		pthread_mutex_unlock(&stash_locks[SS - 1]);
		assert(already_evicted);

		evict_leaf = evict_path++;

		eviction(2 * evict_leaf);
		eviction(2 * evict_leaf + 1);

		paths = access_counter++;

		if (paths % K == 0)
			write_back(paths / K);
	}

	void taostore_oram_v2::write_back(std::uint32_t c)
	{
		std::map<std::int64_t, std::shared_ptr<node>> nodes_level_i[L + 1];
		leaf_id l_index;
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;
		std::shared_ptr<node>reference_node;
		std::shared_ptr<node>parent;

		leaf_id * _paths = new leaf_id[3*K];

		local_subtree.get_pop_queue(3 * K, _paths);
		pthread_mutex_lock(&write_back_lock);
		local_subtree.update_valid(_paths, 3 * K, tree, nodes_level_i[L]);

		local_subtree.write_lock();
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
								 reference_node->payload,
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

				// update the mac for the parent for the evaluation of its mac
				std::uint8_t *target_mac = (l_index & 1) ? reference_node->parent->adata.left_mac : reference_node->parent->adata.right_mac;
				std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));

				parent = reference_node->parent;
				// pthread_mutex_lock(&multi_set_lock);
				if (reference_node->local_timestamp <= c * K &&
					reference_node->child_r == nullptr && reference_node->child_l == nullptr)
				{
					if (l_index & 1)
						parent->child_l = nullptr;
					else
						parent->child_r = nullptr;
					// parent->unlock();
					nodes_level_i[i - 1][get_parent(l_index)] = parent;
					reference_node = nullptr;
				}
				// pthread_mutex_unlock(&multi_set_lock);
			}
		}
		local_subtree.unlock();
		pthread_mutex_unlock(&write_back_lock);
		delete [] _paths;
	}

} // namespace obl