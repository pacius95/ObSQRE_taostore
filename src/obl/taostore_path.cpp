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

	taostore_path_oram::taostore_path_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int A, unsigned int T_NUM) : taostore_oram(N, B, Z, S, T_NUM)
	{
		this->A = A;
	}

	void taostore_path_oram::eviction(leaf_id path)
	{

		std::int64_t l_index = 0;

		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		block_t *bl, *bl_ev;
		bool valid = false;
		int i = 0;

		node *reference_node, *old_ref_node;

		reference_node = local_subtree.root;

		multiset_lock(path);
		pthread_mutex_lock(&stash_lock);
		std::cerr << "--------------------------------------------------" << std::endl;

		printstash();
		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			reference_node->local_timestamp = path_counter;
			old_ref_node = reference_node;

			reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
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
			old_ref_node = reference_node;

			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}
		node *leaf_pointer = old_ref_node;
		node *iterator;
		// reference_node = local_subtree.root;
		reference_node = leaf_pointer->parent;
		//- fetch del path
		//- locko dal root alla leaf
		//- faccio in place eviction rilasciando il lock dal root ala leaf
		//- prendo il lock dello stash e prendo e rilascio i lock dell'albero

		for (int i = L - 1; i >= 0; i--) // for every bucket in the fetched path, from leaf to root
		{
			bl_ev = (block_t *)reference_node->payload;
			for (unsigned int z1 = 0; z1 < Z; z1++) // for every block in the source bucket
			{
				std::int64_t maxd = get_max_depth(bl_ev->lid, path, L);
				iterator = leaf_pointer;
				for (int j = L; j > i; j--) // for every bucket from leaf to the one right under [i]
				{
					bool can_reside = maxd >= j;
					bl = (block_t *)iterator->payload;
					for (unsigned int z2 = 0; z2 < Z; z2++) // for every block in the target bucket
					{
						bool free_slot = bl->bid == DUMMY;
						swap(can_reside & free_slot, (std::uint8_t *)bl, (std::uint8_t *)bl_ev, block_size);
						can_reside &= !free_slot;

						bl = (block_t *)((std::uint8_t *)bl + block_size);
					}
					iterator = iterator->parent;
				}
				bl_ev = (block_t *)((std::uint8_t *)bl + block_size);
			}
			// reference_node->unlock();
			// reference_node = ((path >> i) & 1) ? reference_node->child_r : reference_node->child_l;
			reference_node = reference_node->parent;
		}
		// reference_node->unlock();
		// reference_node = local_subtree.root;
		// for (int i = 0; i < L; i++)
		// {
		// 	reference_node->unlock();
		// 	reference_node = ((path >> i) & 1) ? reference_node->child_r : reference_node->child_l;
		// }
		// reference_node->unlock();
		// pthread_mutex_lock(&stash_lock);

		// reference_node = local_subtree.root;
		// for (int i = 0; i < L; i++)
		// {
		// 	reference_node->lock();
		// 	reference_node = ((path >> i) & 1) ? reference_node->child_r : reference_node->child_l;
		// }
		// reference_node->lock();

		for (unsigned int k = 0; k < S; k++) // for every block in the stash
		{
			std::int64_t maxd = get_max_depth(stash[k].lid, path, L);
			iterator = leaf_pointer;

			for (int i = L; i >= 0; i--) // for every bucket in the path (in reverse order)
			{
				bool can_reside = maxd >= i;
				bl = (block_t *)iterator->payload;

				for (unsigned int j = 0; j < Z; j++) // for every block in a bucket
				{
					bool free_slot = bl->bid == DUMMY;
					swap(can_reside & free_slot, (std::uint8_t *)&stash[k], (std::uint8_t *)bl, block_size);
					can_reside &= !free_slot;
					bl = (block_t *)((std::uint8_t *)bl + block_size);
				}
				iterator = iterator->parent;
			}
		}
		std::cerr << "--------------------------------------------------" << std::endl;
		printstash();
		pthread_mutex_unlock(&stash_lock);

		reference_node = local_subtree.root;
		for (int i = 0; i < L; i++)
		{
			reference_node->unlock();
			reference_node = ((path >> i) & 1) ? reference_node->child_r : reference_node->child_l;
		}
		reference_node->unlock();

		multiset_unlock(path);

		write_queue_t T = {path, reference_node};
		local_subtree.insert_write_queue(T);
	}

	void taostore_path_oram::access_thread(request_t &_req)
	{
		std::uint8_t _fetched[block_size];
		leaf_id evict_leaf;
		leaf_id paths;

		read_path(_req, _fetched);

		answer_request(_req, _fetched);
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

	void taostore_path_oram::read_path(request_t &req, std::uint8_t *_fetched)
	{
		block_id bid;
		leaf_id ev_lid;
		gen_rand((std::uint8_t *)&bid, sizeof(block_id));

		pthread_mutex_lock(&serializer_lck);
		for (auto it : request_structure)
		{
			bool cond = it->bid == req.bid & it->handled == false & it->fake == false;
			req.fake = req.fake | cond;
		}
		request_structure.push_back(&req);

		bid = ternary_op(req.fake, bid, req.bid);
		pthread_mutex_unlock(&serializer_lck);

		leaf_id path = position_map->access(bid, req.fake, &ev_lid);
		fetch_path(_fetched, bid, ev_lid, path, !req.fake);
	}

	void taostore_path_oram::fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool not_fake)
	{
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

		pthread_mutex_lock(&stash_lock);
		for (unsigned int i = 0; i < S; ++i)
		{
			block_id sbid = stash[i].bid;
			swap(not_fake && bid == sbid, _fetched, (std::uint8_t *)&stash[i], block_size);
		}
		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			if (i != 0)
				old_ref_node->unlock();
			else
				pthread_mutex_unlock(&stash_lock);

			bl = (block_t *)reference_node->payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				swap(not_fake & bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}
			reference_node->local_timestamp = path_counter;
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

		multiset_unlock(path);

		fetched->lid = new_lid;
		fetched->bid = bid;

		write_queue_t T = {path, old_ref_node};
		local_subtree.insert_write_queue(T);
	}

	void taostore_path_oram::answer_request(request_t &req, std::uint8_t *_fetched)
	{
		block_t *fetched = (block_t *)_fetched;
		bool hit;
		pthread_mutex_lock(&stash_lock);
		pthread_mutex_lock(&serializer_lck);
		for (auto it : request_structure)
		{
			hit = !req.fake & (it->bid == req.bid);
			//update flags
			it->handled = it->handled | it->id == req.id;
			it->data_ready = it->data_ready | hit;
			replace(hit, it->data_out, fetched->payload, B);
			if (it->data_in != nullptr)
				replace(hit, fetched->payload, it->data_in, B);
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

} // namespace obl