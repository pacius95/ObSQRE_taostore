#include "obl/utils.h"
#include "obl/taostore.h"
#include "obl/primitives.h"
#include "obl/taostore_subtree.h"

#include "obl/oassert.h"

#ifdef SGX_ENCLAVE_ENABLED
// #define printf(a, b) (ocall_stdout(a, b));
#endif

#define DUMMY -1
#define BOTTOM -2

namespace obl
{

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

		// ORAM tree allocation
		tree.set_entry_size(bucket_size);
		tree.reserve(capacity);

		for (unsigned int i = 0; i < this->S; ++i)
			stash[i].bid = DUMMY;

		this->ss = Z;
		this->SS = (S / ss) + 1;
		stash_locks = new pthread_mutex_t[SS];
		for (unsigned int i = 0; i < SS; i++)
			pthread_mutex_init(&stash_locks[i], nullptr);

		this->T_NUM = T_NUM;
		this->subtree_node_size = bucket_size + sizeof(node);
		if ((subtree_node_size * L * T_NUM) > ENCLAVE_MEM)
			this->K = 1;
		else 
			this->K = next_two_power(ENCLAVE_MEM / (subtree_node_size * L * T_NUM));
		init();
	}

	void taostore_oram::init()
	{
		obl_aes_gcm_128bit_key_t master_key;
		obl_aes_gcm_128bit_iv_t iv;
		auth_data_t empty_auth;
		std::uint8_t empty_bucket[Z * block_size];

		std::atomic_init(&evict_path, 0);
		std::atomic_init(&access_counter, (std::uint64_t)1);

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

		local_subtree.init(block_size * Z, empty_bucket, L);
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

	void taostore_oram::multiset_lock(leaf_id path)
	{

		std::int64_t l_index = 0;
		pthread_mutex_lock(&multi_set_lock);
		for (int i = 0; i < L; ++i)
		{
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
			path_req_multi_set.insert(l_index);
		}
		pthread_mutex_unlock(&multi_set_lock);
	}

	void taostore_oram::multiset_unlock(leaf_id path)
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

	void taostore_oram::access_thread_wrap(void *_object)
	{
		return ((processing_thread_args_wrap *)_object)->arg1->access_thread(((processing_thread_args_wrap *)_object)->request);
	}

	void taostore_oram::access_write_thread_wrap(void *_object)
	{
		return ((processing_thread_args_wrap *)_object)->arg1->write_thread(((processing_thread_args_wrap *)_object)->request);
	}

	void taostore_oram::access_read_thread_wrap(void *_object)
	{
		return ((processing_thread_args_wrap *)_object)->arg1->read_thread(((processing_thread_args_wrap *)_object)->request);
	}

	void taostore_oram::writeback_thread_wrap(void *_object)
	{
		return ((taostore_oram *)_object)->write_back();
	}

	void taostore_oram::access(block_id bid, leaf_id lif, std::uint8_t *data_in, std::uint8_t *data_out, leaf_id next_lif)
	{
		request_t _req = {data_in, lif, next_lif, data_out, bid, false, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

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

		return;
	}

	void taostore_oram::access_r(block_id bid, leaf_id lif, std::uint8_t *data_out)
	{
		request_t _req = {nullptr, lif, 0, data_out, bid, false, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};
		struct processing_thread_args_wrap obj_wrap = {this, _req};

		int err = threadpool_add(thpool, access_read_thread_wrap, (void *)&obj_wrap, 0);
		assert(err == 0);

		pthread_mutex_lock(&_req.cond_mutex);
		while (!_req.res_ready)
		{
			pthread_cond_wait(&_req.serializer_res_ready, &_req.cond_mutex);
		}
		pthread_mutex_unlock(&_req.cond_mutex);

		return;
	}
	void taostore_oram::access_w(block_id bid, leaf_id lif, std::uint8_t *data_in, leaf_id next_lif)
	{
		request_t _req = {data_in, lif, next_lif, nullptr, bid, false, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};

		struct processing_thread_args_wrap obj_wrap = {this, _req};

		int err = threadpool_add(thpool, access_write_thread_wrap, (void *)&obj_wrap, 0);
		assert(err == 0);

		//wait on the conditional var
		pthread_mutex_lock(&_req.cond_mutex);
		while (!_req.res_ready)
		{
			pthread_cond_wait(&_req.serializer_res_ready, &_req.cond_mutex);
		}
		pthread_mutex_unlock(&_req.cond_mutex);

		return;
	}

	void taostore_oram::write(block_id bid, std::uint8_t *data_in, leaf_id next_lif)
	{
		request_t _req = {data_in, 0, next_lif, nullptr, bid, false, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER};
		struct processing_thread_args_wrap obj_wrap = {this, _req};

		int err = threadpool_add(thpool, access_write_thread_wrap, (void *)&obj_wrap, 0);
		assert(err == 0);

		//wait on the conditional var
		pthread_mutex_lock(&_req.cond_mutex);
		while (!_req.res_ready)
		{
			pthread_cond_wait(&_req.serializer_res_ready, &_req.cond_mutex);
		}
		pthread_mutex_unlock(&_req.cond_mutex);

		return;
	}

	//DEGUG
	/*	void taostore_oram::printstash()
	{
		for (unsigned int i = 0; i < S; ++i)
			std::cerr << "stash " << i << "bid: " << (block_id)stash[i].bid << "lid :" << (leaf_id)stash[i].lid << " data: " << (std::uint64_t) * ((std::uint64_t *)stash[i].payload) << std::endl;
	}
	void taostore_oram::printsubtree()
	{
		int i = 0;
		i = printrec(local_subtree.getroot(), L, 0);
		std::cerr << "-------------" << i << "----------------" << std::endl;
	}
	int taostore_oram::printrec(node *t, int l, int l_index)
	{
		int i = 1;
		if (t == nullptr)
			return 0;
		else
		{
			block_t *bl = (block_t *)t->payload;
			// for (unsigned int i = 0; i < Z; ++i)
			// {
			// 	std::cerr << "node l_index:" << l_index << "bid: " << bl->bid << "lid :" << bl->lid << " data: " << (std::uint64_t) * ((std::uint64_t *)bl->payload) << std::endl;
			// 	bl = (block_t *)((std::uint8_t *)bl + block_size);
			// }
			// std::cerr << "mac destro: " << (std::uint64_t) * ((std::uint64_t *)t->adata.right_mac) << "mac sinistro: " << (std::uint64_t) * ((std::uint64_t *)t->adata.left_mac) << std::endl;
			i += printrec(t->child_l, l - 1, get_left(l_index));
			i += printrec(t->child_r, l - 1, get_right(l_index));
			return i;
		}
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
			wc_AesGcmDecrypt(crypt_handle,
							 (std::uint8_t *)payload,
							 tree[l_index].payload,
							 Z * block_size,
							 iv,
							 OBL_AESGCM_IV_SIZE,
							 mac,
							 OBL_AESGCM_MAC_SIZE,
							 (std::uint8_t *)&adata,
							 sizeof(auth_data_t));
			bl = payload;
			for (unsigned int j = 0; j < Z; ++j)
			{
				std::cerr << "l_index:" << l_index << "bid: " << bl->bid << "lid :" << bl->lid << " data: " << (std::uint64_t) * ((std::uint64_t *)bl->payload) << "mac: " << (std::uint64_t) * ((std::uint64_t *)mac) << "mac sinistro: " << (std::uint64_t) * ((std::uint64_t *)adata.left_mac) << "mac destro: " << (std::uint64_t) * ((std::uint64_t *)adata.right_mac) << std::endl;
				bl = ((block_t *)((std::uint8_t *)bl + block_size));
			}
		}
	}

	void taostore_oram::printpath(leaf_id path)
	{
		std::uint64_t l_index = 0;
		node *reference_node = local_subtree.getroot();
		block_t *bl;
		for (int i = 0; i <= L; i++)
		{
			bl = (block_t *)reference_node->payload;
			for (unsigned int i = 0; i < Z; ++i)
			{
				std::cerr << "node l_index:" << l_index << "bid: " << bl->bid << "lid :" << bl->lid << " data: " << (std::uint64_t) * ((std::uint64_t *)bl->payload) << std::endl;
				bl = (block_t *)((std::uint8_t *)bl + block_size);
			}

			reference_node = (path >> i) & 1 ? reference_node->child_r : reference_node->child_l;
			l_index = (l_index << 1) + 1 + ((path >> i) & 1);
		}
	}
	*/

} // namespace obl
