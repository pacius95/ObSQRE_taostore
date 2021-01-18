#include "obl/utils.h"
#include "obl/primitives.h"
#include "obl/taostore_circuit_1.h"

#include "obl/oassert.h"

#define DUMMY -1
#define BOTTOM -2
#define QUEUE_SIZE 256

namespace obl
{

    std::uint64_t taostore_circuit_1::eviction(leaf_id path)
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

        node *reference_node;
        node *old_ref_node;
        reference_node = local_subtree.getroot();
        old_ref_node = local_subtree.getroot();

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
            (l_index & 1) ? old_ref_node->child_l = new node(block_size * Z) : old_ref_node->child_r = new node(block_size * Z);
            reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
            local_subtree.newnode();
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
                                       reference_node->payload,
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
            (l_index & 1) ? old_ref_node->child_l = new node(block_size * Z) : old_ref_node->child_r = new node(block_size * Z);
            reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
            local_subtree.newnode();
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
        // multiset_unlock(path);

        local_subtree.insert_write_queue(path);
        return access_counter++;
        //END EVICTION
    }

    void taostore_circuit_1::access_thread(request_t &_req)
    {
        std::uint8_t _fetched[block_size];
        block_t* fetched = (block_t*) _fetched;

        leaf_id evict_leaf;
        bool already_evicted = false;
        std::uint64_t access_counter_1;
        std::uint64_t access_counter_2;
        std::uint64_t access_counter_3;

        access_counter_1 = fetch_path(_fetched, _req.bid, _req.lif);

        memcpy(_req.data_out, fetched->payload, B);
        if (_req.data_in != nullptr)
            memcpy(fetched->payload, _req.data_in, B);


        fetched->bid = _req.bid;
        fetched->lid = _req.next_lif;
        
        pthread_mutex_lock(&_req.cond_mutex);
        _req.res_ready = true;
        pthread_mutex_unlock(&_req.cond_mutex);
        pthread_cond_signal(&_req.serializer_res_ready);

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

        access_counter_2 = eviction(2 * evict_leaf);
        access_counter_3 = eviction(2 * evict_leaf + 1);

        if (access_counter_1 % K == 0 || access_counter_2 % K == 0 || access_counter_3 % K == 0)
            write_back();
    }

    std::uint64_t taostore_circuit_1::fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id path)
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

        reference_node = local_subtree.getroot();
        old_ref_node = local_subtree.getroot();

        // multiset_lock(path);

        pthread_mutex_lock(&stash_locks[0]);
        for (unsigned int i = 0; i < SS - 1; ++i)
        {
            for (unsigned int j = 0; j < ss; ++j)
            {
                block_id sbid = stash[i * ss + j].bid;
                swap(bid == sbid, _fetched, (std::uint8_t *)&stash[i * ss + j], block_size);
            }
            pthread_mutex_lock(&stash_locks[i + 1]);
            pthread_mutex_unlock(&stash_locks[i]);
        }
        for (unsigned int i = 0; i < S % ss; ++i)
        {
            block_id sbid = stash[(SS - 1) * ss + i].bid;
            swap(bid == sbid, _fetched, (std::uint8_t *)&stash[(SS - 1) * ss + i], block_size);
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
                swap(bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
                bl = ((block_t *)((std::uint8_t *)bl + block_size));
            }
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
            (l_index & 1) ? old_ref_node->child_l = new node(block_size * Z) : old_ref_node->child_r = new node(block_size * Z);
            reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
            local_subtree.newnode();
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
                                       reference_node->payload,
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
                swap(bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
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
            (l_index & 1) ? old_ref_node->child_l = new node(block_size * Z) : old_ref_node->child_r = new node(block_size * Z);
            reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
            reference_node->parent = old_ref_node;
            local_subtree.newnode();

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

        local_subtree.insert_write_queue(path);
        return access_counter++;
    }

    void taostore_circuit_1::write_thread(request_t &_req)
    {
        std::uint8_t _fetched[block_size];
        block_t* fetched = (block_t*) _fetched;

        leaf_id evict_leaf;
        bool already_evicted = false;
        std::uint64_t access_counter_1;
        std::uint64_t access_counter_2;

        fetched->bid = _req.bid;
        fetched->lid = _req.next_lif;
        memcpy(fetched->payload, _req.data_in, B);

        pthread_mutex_lock(&_req.cond_mutex);
        _req.res_ready = true;
        pthread_mutex_unlock(&_req.cond_mutex);
        pthread_cond_signal(&_req.serializer_res_ready);

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

        access_counter_1 = eviction(2 * evict_leaf);
        access_counter_2 = eviction(2 * evict_leaf + 1);

        if (access_counter_1 % K == 0 || access_counter_2 % K == 0)
            write_back();
    }


	void taostore_circuit_1::write_back()
	{
		std::unordered_map<std::int64_t, node *> nodes_level_i[L + 1];
		std::int64_t l_index;
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;
		node *reference_node;
		node *parent;
		leaf_id *_paths = new leaf_id[K];
		int tmp = K;
		bool flag = false;

		// printf("%d\n",local_subtree.get_nodes_count());
		assert(local_subtree.get_nodes_count() * (sizeof(node)+bucket_size) < 2 << 25);
		nodes_level_i[L].reserve(K);
		local_subtree.get_pop_queue(K, _paths);
		local_subtree.update_valid(_paths, K, tree, nodes_level_i[L]);
		for (int i = L; i > 0; --i)
		{
			tmp = tmp / 2;
			nodes_level_i[i - 1].reserve(tmp);
			for (auto &itx : nodes_level_i[i])
			{
				flag = false;
				l_index = itx.first;
				reference_node = itx.second;
				parent = reference_node->parent;

				if (reference_node->trylock() == 0)
				{
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
					std::uint8_t *target_mac = (l_index & 1) ? parent->adata.left_mac : parent->adata.right_mac;
					std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
					if (parent->trylock() == 0){
						if (reference_node->child_r == nullptr && reference_node->child_l == nullptr)
						{
							if (l_index & 1)
								parent->child_l = nullptr;
							else
								parent->child_r = nullptr;
							reference_node->wb_unlock();
							flag = true;
						}
						parent->unlock();
					}
					reference_node->unlock();
				}
				if (flag)
				{
					if (parent->wb_trylock() == 0)
						nodes_level_i[i - 1][get_parent(l_index)] = parent;
					delete reference_node;
					local_subtree.removenode();
				}
				else
					reference_node->wb_unlock();
			}
			nodes_level_i[i].clear();
		}
		// pthread_mutex_unlock(&write_back_lock);
		delete[] _paths;
	}

} // namespace obl
