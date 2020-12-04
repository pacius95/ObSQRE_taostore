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
		std::atomic_init(&fetched_path_counter, (std::uint64_t)1);
		this->K = next_two_power((1 << 25) / (bucket_size * L));
	}

	taostore_path_oram::~taostore_path_oram()
	{
		threadpool_destroy(thpool, threadpool_graceful);
		{
			std::unique_lock<std::mutex>serializer_lock;
			oram_alive = false;
			serializer_cond.notify_one();
		}
		pthread_join(serializer_id, nullptr);

		std::memset(_crypt_buffer, 0x00, sizeof(Aes) + 16);

		std::memset(&stash[0], 0x00, block_size * S);

		free(_crypt_buffer);

		delete position_map;
		delete stash_locks;
		local_subtree.root = nullptr;
		//TODO cleanup
	}

	void taostore_path_oram::eviction(leaf_id path)
	{

		std::int64_t l_index = 0;
		obl_aes_gcm_128bit_tag_t reference_mac;
		auth_data_t *adata;
		block_t *bl, *bl_ev;
		bool valid = false;
		int i = 0;

		std::shared_ptr<node> reference_node;
		std::shared_ptr<node> old_ref_node;
		old_ref_node = local_subtree.root;
		reference_node = local_subtree.root;

		multiset_lock(path);

		for (i = 0; i <= L && reference_node != nullptr; ++i)
		{
			reference_node->lock();
			reference_node->local_timestamp = access_counter;
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
			(l_index & 1) ? old_ref_node->child_l = std::shared_ptr<node>(new node(block_size * Z, access_counter)) : old_ref_node->child_r = std::shared_ptr<node>(new node(block_size * Z, access_counter));
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
			(l_index & 1) ? old_ref_node->child_l = std::shared_ptr<node>(new node(block_size * Z, access_counter)) : old_ref_node->child_r = std::shared_ptr<node>(new node(block_size * Z, access_counter));
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
		std::shared_ptr<node> leaf_pointer = old_ref_node;
		std::shared_ptr<node> iterator;

		//versione che non fa overflow (come la path deterministica)
		reference_node = leaf_pointer->parent;
		leaf_pointer->unlock();

		for (int i = L - 1; i >= 0; i--) // for every bucket in the fetched path, from root to leaf
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
				bl_ev = (block_t *)((std::uint8_t *)bl_ev + block_size);
			}
			reference_node->unlock();
			reference_node = reference_node->parent;
		}

		for (unsigned int i = 0; i < SS - 1; ++i)
		{
			stash_locks[i].lock();
			for (unsigned int j = 0; j < ss; ++j)
			{
				unsigned int k = i * ss + j;

				std::int64_t maxd = get_max_depth(stash[k].lid, path, L);
				iterator = leaf_pointer;
				for (int h = L; h >= 0; h--) // for every bucket in the path (in NORMAL order)
				{
					iterator->lock();
					bool can_reside = maxd >= h;
					bl = (block_t *)iterator->payload;

					for (unsigned int z = 0; z < Z; z++) // for every block in a bucket
					{
						bool free_slot = bl->bid == DUMMY;
						swap(can_reside & free_slot, (std::uint8_t *)&stash[k], (std::uint8_t *)bl, block_size);
						can_reside &= !free_slot;
						bl = (block_t *)((std::uint8_t *)bl + block_size);
					}
					iterator->unlock();
					iterator = iterator->parent;
				}
			}
			stash_locks[i].unlock();
		}

		stash_locks[SS - 1].lock();
		for (unsigned int i = 0; i < S % ss; ++i)
		{
			unsigned int k = (SS - 1) * ss + i;

			std::int64_t maxd = get_max_depth(stash[k].lid, path, L);
			iterator = leaf_pointer;
			for (int j = L; j >= 0; j--) // for every bucket in the path (in reverse order)
			{
				iterator->lock();
				bool can_reside = maxd >= j;
				bl = (block_t *)iterator->payload;

				for (unsigned int z = 0; z < Z; z++) // for every block in a bucket
				{
					bool free_slot = bl->bid == DUMMY;
					swap(can_reside & free_slot, (std::uint8_t *)&stash[k], (std::uint8_t *)bl, block_size);
					can_reside &= !free_slot;
					bl = (block_t *)((std::uint8_t *)bl + block_size);
				}
				iterator->unlock();
				iterator = iterator->parent;
			}
		}
		stash_locks[SS - 1].unlock();

		multiset_unlock(path);

		local_subtree.insert_write_queue(path);

		/* 	versione che fa overflow

		reference_node = local_subtree.root;
		for (int i = 0; i <= L - 1; i++) // for every bucket in the fetched path, from root to leaf
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
				bl_ev = (block_t *)((std::uint8_t *)bl_ev + block_size);
			}
			reference_node->unlock();
			reference_node = ((path >> i) & 1) ? reference_node->child_r : reference_node->child_l;
		}
		reference_node->unlock();

		for (unsigned int i = 0; i < SS - 1; ++i)
		{
			pthread_mutex_lock(&stash_locks[i]);
			for (unsigned int j = 0; j < ss; ++j)
			{
				unsigned int k = i * ss + j;

				std::int64_t maxd = get_max_depth(stash[k].lid, path, L);
				// iterator = leaf_pointer;
				iterator = local_subtree.root;
				for (int h = 0; h <= L; h++) // for every bucket in the path (in NORMAL order)
				{
					iterator->lock();
					bool can_reside = maxd >= h;
					bl = (block_t *)iterator->payload;

					for (unsigned int z = 0; z < Z; z++) // for every block in a bucket
					{
						bool free_slot = bl->bid == DUMMY;
						swap(can_reside & free_slot, (std::uint8_t *)&stash[k], (std::uint8_t *)bl, block_size);
						can_reside &= !free_slot;
						bl = (block_t *)((std::uint8_t *)bl + block_size);
					}
					iterator->unlock();
					iterator = ((path >> h) & 1) ? iterator->child_r : iterator->child_l;
				}
			}
			pthread_mutex_unlock(&stash_locks[i]);
		}

		pthread_mutex_lock(&stash_locks[SS - 1]);
		for (unsigned int i = 0; i < S % ss; ++i)
		{
			unsigned int k = (SS - 1) * ss + i;

			std::int64_t maxd = get_max_depth(stash[k].lid, path, L);
			// iterator = leaf_pointer;
			iterator = local_subtree.root;
			for (int j = 0; j <= L; j++) // for every bucket in the path (in reverse order)
			{
				iterator->lock();
				bool can_reside = maxd >= j;
				bl = (block_t *)iterator->payload;

				for (unsigned int z = 0; z < Z; z++) // for every block in a bucket
				{
					bool free_slot = bl->bid == DUMMY;
					swap(can_reside & free_slot, (std::uint8_t *)&stash[k], (std::uint8_t *)bl, block_size);
					can_reside &= !free_slot;
					bl = (block_t *)((std::uint8_t *)bl + block_size);
				}
				iterator->unlock();
				iterator = ((path >> j) & 1) ? iterator->child_r : iterator->child_l;
			}
		}
		pthread_mutex_unlock(&stash_locks[SS - 1]);

		multiset_unlock(path);

		local_subtree.insert_write_queue(path);*/
	}

	void taostore_path_oram::access_thread(request_t &_req)
	{
		std::uint8_t _fetched[block_size];
		leaf_id evict_leaf;
		uint64_t paths;
		uint64_t fetched_counter;
		uint64_t fetched_counter_2 = 1;

		read_path(_req, _fetched);

		answer_request(_req, _fetched);
		paths = std::atomic_fetch_add(&access_counter, (std::uint64_t)1);
		fetched_counter = std::atomic_fetch_add(&fetched_path_counter, (std::uint64_t)1);

		if (paths % A == 0)
		{
			evict_leaf = std::atomic_fetch_add(&evict_path, (std::uint32_t)1);
			eviction(evict_leaf);
			fetched_counter_2 = std::atomic_fetch_add(&fetched_path_counter, (std::uint64_t)1);
		}

		if (fetched_counter % K == 0)
			write_back(fetched_counter / K);
		if (fetched_counter_2 % K == 0)
			write_back(fetched_counter_2 / K);
		return;
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

		std::shared_ptr<node> reference_node;
		std::shared_ptr<node> old_ref_node;

		reference_node = local_subtree.root;
		old_ref_node = local_subtree.root;

		multiset_lock(path);

		stash_locks[0].lock();
		for (unsigned int i = 0; i < SS - 1; ++i)
		{
			for (unsigned int j = 0; j < ss; ++j)
			{
				block_id sbid = stash[i * ss + j].bid;
				swap(not_fake && bid == sbid, _fetched, (std::uint8_t *)&stash[i * ss + j], block_size);
			}
			stash_locks[i + 1].lock();
			stash_locks[i].unlock();
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
				stash_locks[SS - 1].unlock();

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
			(l_index & 1) ? old_ref_node->child_l = std::shared_ptr<node>(new node(block_size * Z, access_counter)) : old_ref_node->child_r = std::shared_ptr<node>(new node(block_size * Z, access_counter));
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
			(l_index & 1) ? old_ref_node->child_l = std::shared_ptr<node>(new node(block_size * Z, access_counter)) : old_ref_node->child_r = std::shared_ptr<node>(new node(block_size * Z, access_counter));
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

		local_subtree.insert_write_queue(path);
	}

	void taostore_path_oram::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		std::uint8_t _data_out[B];
		std::int32_t _id = std::atomic_fetch_add(&thread_id, 1);
		request_t _req = {data_in, bid, false, false, _data_out, false, false, _id};

		struct processing_thread_args_wrap obj_wrap = {this, _req};

		int err = threadpool_add(thpool, access_thread_wrap, (void *)&obj_wrap, 0);
		assert(err == 0);

		//wait on the conditional var
		{
			std::unique_lock<std::mutex> lck(_req.cond_mutex);
			while (!_req.res_ready)
			{
				_req.serializer_res_ready.wait(lck);
			}
		}
		std::memcpy(data_out, _data_out, B);
	}
	void taostore_path_oram::write_back(std::uint32_t c)
	{
		std::map<leaf_id, std::shared_ptr<node>> nodes_level_i[L + 1];
		leaf_id l_index;
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;
		std::shared_ptr<node> reference_node;

		leaf_id *_paths = new leaf_id[K];

		write_back_lock.lock();
		_paths = local_subtree.get_pop_queue(3 * K);
		nodes_level_i[L] = local_subtree.update_valid(_paths, K, tree);

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

				std::shared_ptr<node> parent = reference_node->parent;
				// update the mac for the parent for the evaluation of its mac

				std::uint8_t *target_mac = (l_index & 1) ? reference_node->parent->adata.left_mac : reference_node->parent->adata.right_mac;
				std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
				{
					std::lock_guard<std::mutex> lock(multi_set_lock);
					if (reference_node->local_timestamp <= c * K &&
						reference_node->child_r == nullptr && reference_node->child_l == nullptr &&
						path_req_multi_set.find(l_index) == path_req_multi_set.end())
					{
						nodes_level_i[i - 1][get_parent(l_index)] = reference_node->parent;
						if (l_index & 1)
							reference_node->parent->child_l = nullptr;
						else
							reference_node->parent->child_r = nullptr;
					}
				}
			}
		}
		write_back_lock.unlock();
		delete _paths;
	}

} // namespace obl