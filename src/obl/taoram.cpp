#include "obl/taoram.h"
#include "obl/utils.h"
#include "obl/primitives.h"

#include "obl/oassert.h"

#include <cstdlib>
#include <cstring>
#include "sgx_trts.h"
#define DUMMY -1
#define BOTTOM -2

namespace obl
{
	struct processing_thread_args
	{
		taostore_request_t *request;
		block_id *bid;
	};
	struct processing_thread_args_wrap
	{
		taostore_oram *arg1;
		processing_thread_args *arg2;
	};
	struct taostore_block_t
	{
		block_id bid;
		leaf_id lid;
		std::uint8_t payload[];
	};

	struct taostore_bucket_t
	{
		obl_aes_gcm_128bit_iv_t iv;
		bool reach_l, reach_r;
		obl_aes_gcm_128bit_tag_t mac __attribute__((aligned(8)));
		// since payload is going to be a multiple of 16 bytes, the struct will be memory aligned!
		uint8_t payload[];
	};

	struct taostore_request_t
	{
		std::uint8_t *data_in;
		block_id bid;
		bool fake;
		bool handled;
		std::uint8_t *data_out;
		bool res_ready;
		bool data_ready;
		pthread_t *thread_id;
		pthread_mutex_t *cond_mutex;
		pthread_cond_t *serializer_res_ready;
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

		// SUBTREE allocation
		local_subtree.set_entry_size(bucket_size);

		subtree_lock = new pthread_spinlock_t[L + 1];

		// allocate data struct for integrity checking
		adata = new auth_data_t[L + 1];

		init();
		pthread_create(&serializer_id, nullptr, serializer_wrap, (void *)this);
	}

	taostore_oram::~taostore_oram()
	{
		std::memset(_crypt_buffer, 0x00, sizeof(Aes) + 16);

		std::memset(&stash[0], 0x00, block_size * S);
		// std::memset(&fetched_path[0], 0x00, block_size * (L + 1) * Z);

		free(_crypt_buffer);
		delete[] adata;

		//todo:
		//set oram_alive = 0
		//wait serializer to die.
	}

	void taostore_oram::init()
	{
		obl_aes_gcm_128bit_key_t master_key;
		obl_aes_gcm_128bit_iv_t iv;

		obl_aes_gcm_128bit_tag_t merkle_root;
		auth_data_t empty_auth;
		std::uint8_t empty_bucket[Z * block_size];

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

		local_subtree = new taostore_subtree((size_t)Z * block_size, merkle_root, empty_bucket);
	}

	void *taostore_oram::serializer_wrap(void *object)
	{
		return ((taostore_oram *)object)->serializer();
	}

	void *taostore_oram::serializer()
	{
		while (oram_alive && request_structure.size() != 0)
		{
			pthread_mutex_lock(&serializer_lck);
			if (request_structure.size() == 0)
				pthread_cond_wait(&serializer_cond, &serializer_lck);
			//condition is false
			while (!request_structure.front()->handled || !request_structure.front()->data_ready)
			{
				pthread_cond_wait(&serializer_cond, &serializer_lck);
				//if condition true
				if (request_structure.front()->handled && request_structure.front()->data_ready)
				{
					pthread_mutex_lock(request_structure.front()->cond_mutex);
					request_structure.front()->res_ready = true;
					pthread_cond_signal(request_structure.front()->serializer_res_ready);
					pthread_mutex_unlock(request_structure.front()->cond_mutex);
					request_structure.pop_front();
				}
			}
			if (request_structure.size() != 0)
			{
				if (request_structure.front()->handled && request_structure.front()->data_ready)
				{
					pthread_mutex_lock(request_structure.front()->cond_mutex);
					request_structure.front()->res_ready = true;
					pthread_cond_signal(request_structure.front()->serializer_res_ready);
					pthread_mutex_unlock(request_structure.front()->cond_mutex);
					request_structure.pop_front();
				}
			}
			pthread_mutex_unlock(&serializer_lck);
		}
	}
	void taostore_oram::set_pos_map(taostore_position_map *pos_map)
	{
		this->pos_map = pos_map;
	}

	std::int64_t taostore_oram::fetch_path(leaf_id path, flexible_array<block_t> *_fetched_path, auth_data_t *_adata)
	{
		// fetched_path (1 for each thread, not shared)
		flexible_array<block_t> fetched_path = *_fetched_path;
		// fetched_path allocation
		fetched_path.set_entry_size(block_size);
		fetched_path.reserve((L + 1) * Z);
		auth_data_t *adata = _adata;

		// always start from root
		std::int64_t l_index = 0;
		int i;

		// start verifying the mac stored in the root, from the SAFE part of the memory
		obl_aes_gcm_128bit_tag_t reference_mac;
		std::memcpy(reference_mac, merkle_root, sizeof(obl_aes_gcm_128bit_tag_t)); // drop the & since not needed

		/*
			the additional method init (to be refined in the SGX deployment) actually inits
			the root node in a proper way, storing the correct "accessed" flags inside
			the root bucket. So the mac there contained in the root will always be valid
		*/
		bool reachable = true;

		std::memset(adata, 0x00, sizeof(auth_data_t) * (L + 1));

		for (i = 0; i <= L && reachable; i++)
		{
			std::int64_t leftch = get_left(l_index);
			std::int64_t rightch = get_right(l_index);

			// this data will be authenticated data in the GCM mode
			// dump from encrypted bucket header
			adata[i].valid_l = tree[l_index].reach_l;
			adata[i].valid_r = tree[l_index].reach_r;

			// dump left and right child mac if valid, otherwise pad with 0s
			if (adata[i].valid_l)
				std::memcpy(adata[i].left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			if (adata[i].valid_r)
				std::memcpy(adata[i].right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			// if they are not valid, authentication data for the corresponding mac would be 0x00..0
			// however this was already covered by the memset before the loop

			// decrypt using the IV
			int dec = wc_AesGcmDecrypt(crypt_handle,
									   (std::uint8_t *)&fetched_path[Z * i],
									   tree[l_index].payload,
									   Z * block_size,
									   tree[l_index].iv,
									   OBL_AESGCM_IV_SIZE,
									   reference_mac,
									   OBL_AESGCM_MAC_SIZE,
									   (std::uint8_t *)&adata[i],
									   sizeof(auth_data_t));

			// MAC mismatch is a critical error
			//assert(dec != AES_GCM_AUTH_E);
			assert(dec == 0);

			/*
				NB: this doesn't need to be oblivious since an attacker might always see
				the sequences of accesses to the buckets and understand whether or not a
				bucket has already been accessed
				NB 2: fetch this from data which was dumped and authenticated, and taken
				from PROTECTED MEMORY. This should avoid some kind of attacks
			*/
			reachable = (path >> i) & 1 ? adata[i].valid_r : adata[i].valid_l;
			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);

			if (reachable)
			{
				/*
					NB: this isn't oblivious as well since you are just publicly traversing
					the ORAM tree
				*/
				std::uint8_t *src = ((path >> i) & 1) ? adata[i].right_mac : adata[i].left_mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
		}

		// fill the other buckets with "empty" blocks
		while (i <= L)
		{
			int base = Z * i;

			for (unsigned int j = 0; j < Z; j++)
				fetched_path[base + j].bid = DUMMY;

			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}

		return get_parent(l_index);
	}

	void taostore_oram::wb_path(leaf_id path, std::int64_t leaf)
	{
		obl_aes_gcm_128bit_iv_t iv;
		obl_aes_gcm_128bit_tag_t mac;
		bool reachable = true;

		// update the reachability flags
		for (int i = 0; i < L; i++)
		{
			if (((path >> i) & 1) == 0) // if you take the left path
			{
				adata[i].valid_r = reachable && adata[i].valid_r; // this serves as initialization for initial dummy values
				reachable = reachable && adata[i].valid_l;		  // this propagates reachability
				adata[i].valid_l = true;						  // this marks the path as already fetched, and thus valid
			}
			else
			{ // else
				adata[i].valid_l = reachable && adata[i].valid_l;
				reachable = reachable && adata[i].valid_r;
				adata[i].valid_r = true;
			}
		}

		// leaves have always unreachable children
		adata[L].valid_l = false;
		adata[L].valid_r = false;

		for (int i = L; i >= 0; i--)
		{
			// generate a new random IV
			gen_rand(iv, OBL_AESGCM_IV_SIZE);

			// save encrypted payload
			wc_AesGcmEncrypt(crypt_handle,
							 tree[leaf].payload,
							 (std::uint8_t *)&fetched_path[Z * i],
							 Z * block_size,
							 iv,
							 OBL_AESGCM_IV_SIZE,
							 mac,
							 OBL_AESGCM_MAC_SIZE,
							 (std::uint8_t *)&adata[i],
							 sizeof(auth_data_t));

			// save "mac" + iv + reachability flags
			std::memcpy(tree[leaf].mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
			std::memcpy(tree[leaf].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));
			tree[leaf].reach_l = adata[i].valid_l;
			tree[leaf].reach_r = adata[i].valid_r;

			// update the mac for the parent for the evaluation of its mac
			if (i > 0)
			{
				/*
					NB: this isn't oblivious as the attacker knows which path you are performing
					the eviction!
				*/
				std::uint8_t *P = ((path >> (i - 1)) & 1) ? adata[i - 1].right_mac : adata[i - 1].left_mac;
				std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
			}

			// move to the bucket in the upper level
			leaf = get_parent(leaf);
		}

		// now dump the last mac to the merkle_root!
		std::memcpy(merkle_root, mac, sizeof(obl_aes_gcm_128bit_tag_t));
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

	void taostore_oram::deepest(leaf_id path)
	{
		// allow -1 indexing for stash
		std::int64_t *ljd = longest_jump_down + 1;
		std::int64_t *csb = closest_src_bucket + 1;

		std::int64_t closest_src_bucket = -1;
		std::int64_t goal = -1;

		goal = get_max_depth_bucket(&stash[0], S, path);
		ljd[-1] = goal;
		csb[-1] = BOTTOM;

		for (int i = 0; i <= L; i++)
		{
			csb[i] = ternary_op(goal >= i, closest_src_bucket, BOTTOM);

			std::int64_t jump = get_max_depth_bucket(&fetched_path[Z * i], Z, path);
			ljd[i] = jump;

			closest_src_bucket = ternary_op(jump >= goal, i, closest_src_bucket);
			goal = ternary_op(jump >= goal, jump, goal);
		}
	}

	void taostore_oram::target()
	{

		std::int64_t *ndb = next_dst_bucket + 1;
		std::int64_t *csb = closest_src_bucket + 1;

		std::int64_t src = BOTTOM;
		std::int64_t dst = BOTTOM;

		for (int i = L; i >= 0; i--)
		{
			bool has_dummy = has_free_block(&fetched_path[Z * i], Z);
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
		}

		// now the stash
		bool stash_reached_bucket = src == DUMMY;
		ndb[-1] = ternary_op(stash_reached_bucket, dst, BOTTOM);
	}

	void taostore_oram::eviction(leaf_id path)
	{
		// arrays needed for eviction
		std::int64_t *longest_jump_down = new std::int64_t[L + 2]; // counting root = 0 and stash = -1 and L additional levels
		std::int64_t *closest_src_bucket = new std::int64_t[L + 2];
		std::int64_t *next_dst_bucket = new std::int64_t[L + 2];

		std::int64_t dst;

		std::int64_t *ljd = longest_jump_down + 1;
		std::int64_t *ndb = next_dst_bucket + 1;

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

			//bool already_swapped = false;
			for (unsigned int j = 0; j < Z; j++)
			{
				bool deepest_block = (get_max_depth(fetched_path[Z * i + j].lid, path, L) == ljd[i]) & (fetched_path[Z * i + j].bid != DUMMY);

				swap(
					(!swap_hold_with_valid & necessary_eviction & (fetched_path[Z * i + j].bid == DUMMY)) | (swap_hold_with_valid & deepest_block),
					_hold, (std::uint8_t *)&fetched_path[Z * i + j], block_size);
			}
		}
	}

	void taostore_oram::evict(leaf_id path)
	{
		std::int64_t leaf = fetch_path(path);

		deepest(path);
		target();
		eviction(path);

		wb_path(path, leaf);
	}

	void *taostore_oram::processing_thread_wrap(void *_object)
	{
		return ((processing_thread_args_wrap *)_object)->arg1->processing_thread((void *)((processing_thread_args_wrap *)_object)->arg2);
	}

	void *taostore_oram::processing_thread(void *_object)
	{
		processing_thread_args *object = (processing_thread_args *)_object;
		request_t *request = object->request;
		read_path(request, object->bid);
		//answer-req
		//eviction
	}
	bool taostore_oram::read_path(request_t *req, block_id *_bid)
	{

		bool t = true;
		pthread_mutex_lock(&serializer_lck);
		for (it = request_structure.begin(); it < request_structure.end(); it++)
		{
			bool cond = (*it)->bid == req->bid && (*it)->handled == false && (*it)->fake == false;
			replace(cond, (std::uint8_t *)&(req->fake), (std::uint8_t *)&t, sizeof(bool));
		}
		request_structure.push_back(req);
		pthread_mutex_unlock(&serializer_lck);
		block_id bid;
		sgx_read_rand((unsigned char *)&bid, sizeof(block_id));
		replace(req->fake, (std::uint8_t *)&bid, (std::uint8_t *)_bid, sizeof(block_id));

		leaf_id ev_lid;
		leaf_id path = pos_map->access(bid, req->fake, &ev_lid);

		// auth_data_t *adata = new auth_data_t[L+1];
		;

		// always start from root
		std::int64_t l_index = 0;
		int i;
		obl_aes_gcm_128bit_tag_t reference_mac;

		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t *)_fetched;

		fetched->bid = DUMMY;

		bool reachable = true;
		bool valid = true std::memcpy(reference_mac, reference_node->mac, sizeof(obl_aes_gcm_128bit_tag_t)); // drop the & since not needed

		//root mac is not verified, it is kept in sgx memory all the time
		node *reference_node, *old_ref_node;
		int i = 0;
		local_subtree->read_lock();
		reference_node = local_subtree->root;
		while (i <= L && reachable)
		{
			reference_node->lock();

			for (unsigned int j = 0; j < Z; j++)
			{
				block_id fpbid = reference_node->payload[j].bid;
				swap(fpbid == bid, _fetched, (std::uint8_t *)&freference_node->payload[j], block_size);
			}

			old_ref_node = reference_node;
			reference_node = (path >> i) & 1 ? old_ref_node.child_r : old_ref_node.child_l;

			if (reference_node == nullptr)
			{
				reachable = false;
				reference_node = new node(block_size);
				reference_node->parent = old_ref_node;
				//set mac

				valid = (path >> i) & 1 ? tree[l_index].valid_r : tree[l_index].valid_l;
				// evaluate the next encrypted bucket index in the binary heap

				if (valid)
				{
					//sibling mac to add maybe
					std::memcpy(reference_node->mac, ((path >> i) & 1) ? tree[l_index].right_mac : tree[l_index].left_mac, sizeof(obl_aes_gcm_128bit_tag_t));
				}
				l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			}
			else
			{
			}
			i++;
		}

		for (i <= L && valid; i++)
		{
			reference_node->lock();
			old_ref_node.unlock
			std::int64_t leftch = get_left(l_index);
			std::int64_t rightch = get_right(l_index);

			// this data will be authenticated data in the GCM mode
			// dump from encrypted bucket header
			adata[i].valid_l = tree[l_index].reach_l;
			adata[i].valid_r = tree[l_index].reach_r;

			// dump left and right child mac if valid, otherwise pad with 0s
			if (adata[i].valid_l)
				std::memcpy(adata[i].left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			if (adata[i].valid_r)
				std::memcpy(adata[i].right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

			// if they are not valid, authentication data for the corresponding mac would be 0x00..0
			// however this was already covered by the memset before the loop

			// decrypt using the IV
			int dec = wc_AesGcmDecrypt(crypt_handle,
									   (std::uint8_t *)&fetched_path[Z * i],
									   tree[l_index].payload,
									   Z * block_size,
									   tree[l_index].iv,
									   OBL_AESGCM_IV_SIZE,
									   reference_mac,
									   OBL_AESGCM_MAC_SIZE,
									   (std::uint8_t *)&adata[i],
									   sizeof(auth_data_t));

			// MAC mismatch is a critical error
			//assert(dec != AES_GCM_AUTH_E);
			assert(dec == 0);

			/*
				NB: this doesn't need to be oblivious since an attacker might always see
				the sequences of accesses to the buckets and understand whether or not a
				bucket has already been accessed
				NB 2: fetch this from data which was dumped and authenticated, and taken
				from PROTECTED MEMORY. This should avoid some kind of attacks
			*/
			reachable = (path >> i) & 1 ? adata[i].valid_r : adata[i].valid_l;
			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);

			if (reachable)
			{
				/*
					NB: this isn't oblivious as well since you are just publicly traversing
					the ORAM tree
				*/
				std::uint8_t *src = ((path >> i) & 1) ? adata[i].right_mac : adata[i].left_mac;
				std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
			}
		}

		// fill the other buckets with "empty" blocks
		while (i <= L)
		{
			int base = Z * i;

			for (unsigned int j = 0; j < Z; j++)
				fetched_path[base + j].bid = DUMMY;

			// evaluate the next encrypted bucket index in the binary heap
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			++i;
		}

		return get_parent(l_index);

		std::uint8_t _fetched[block_size];
		block_t *fetched = (block_t *)_fetched;

		fetched->bid = DUMMY;

		// search for the requested block by traversing the local subtree buckets
		//sgx_read_lock tree (eviction and wb take writelock here)
		//lock_livello 0 (stash)
		for (unsigned int i = 0; i < S; i++)
		{
			block_id sbid = stash[i].bid;
			swap(bid == sbid, _fetched, (std::uint8_t *)&stash[i], block_size);
		}

		for (int i = 0; i <= L; i++)
			//lock livello i + 1 (root)
			//unlock livello i
			//getpathdirection(i);
			//subtree.getchild(direction);
			//if null, set child = fetched[i];
			//unlock livello L + 1
			//sgx_read_unlock tree (eviction and wb take writelock here)

			std::memcpy(data_out, fetched->payload, B);
	}

	void taostore_oram::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		pthread_mutex_t _cond_mutex = PTHREAD_MUTEX_INITIALIZER;
		pthread_cond_t _serializer_res_ready = PTHREAD_COND_INITIALIZER;
		pthread_t proces;
		std::uint8_t _data_out[B];
		request_t _req = {data_in, bid, false, false, _data_out, false, false, &proces, &_cond_mutex, &_serializer_res_ready};
		struct processing_thread_args obj = {&_req, &bid};
		struct processing_thread_args_wrap obj_wrap = {this, &obj};
		pthread_create(&proces, nullptr, processing_thread_wrap, (void *)&obj);
		//wait on the conditional var
		pthread_mutex_lock(&_cond_mutex);
		while (!_req.res_ready)
		{ // or even "while" instead of "if"
			pthread_cond_wait(&_serializer_res_ready, &_cond_mutex);
		}
		pthread_mutex_unlock(&_cond_mutex);

		std::memcpy(data_out, _data_out, B);

		delete[] & _req;
		pthread_cond_destroy(&_serializer_res_ready);
		pthread_mutex_destroy(&_cond_mutex);
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

		evict(2 * access_counter);
		evict(2 * access_counter + 1);

		++access_counter;
	}

} // namespace obl