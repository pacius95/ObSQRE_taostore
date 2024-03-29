// #include "obl/utils.h"
// #include "obl/primitives.h"
// #include "obl/taostore_path.h"

// #include "obl/oassert.h"

// #define DUMMY -1
// #define BOTTOM -2
// #define QUEUE_SIZE 256

// namespace obl
// {

//     taostore_path::taostore_path(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int A, unsigned int T_NUM) : taostore_oram(N, B, Z, S, T_NUM)
//     {
//         this->A = A;
//         std::atomic_init(&eviction_counter, (std::uint64_t)1);
//     }

//     std::uint64_t taostore_path::eviction(leaf_id path)
//     {
//         std::int64_t l_index = 0;
//         block_t *bl, *bl_ev;
//         int i = 0;

//         std::vector<node *> fetched_path;

//         node *reference_node;
//         node *old_ref_node;
//         old_ref_node = local_subtree.getroot();
//         reference_node = local_subtree.getroot();

//         multiset_lock(path);

//         download_path(path, fetched_path);
//         for (i = 0; i <= L && reference_node != nullptr; ++i)
//         {
//             reference_node->lock();
//             old_ref_node = reference_node;

//             reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
//             l_index = (l_index << 1) + 1 + ((path >> i) & 1);
//         }

//         while (i <= L)
//         {
//             (l_index & 1) ? old_ref_node->child_l = fetched_path[i] : old_ref_node->child_r = fetched_path[i];
//             reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
//             reference_node->parent = old_ref_node;
//             local_subtree.newnode();

//             reference_node->lock();
//             old_ref_node = reference_node;

//             l_index = (l_index << 1) + 1 + ((path >> i) & 1);
//             ++i;
//         }

//         node *leaf_pointer = old_ref_node;
//         node *iterator;
//         reference_node = leaf_pointer->parent;
//         leaf_pointer->unlock();

//         for (int i = L - 1; i >= 0; i--) // for every bucket in the fetched path, from leaf to root
//         {
//             bl_ev = (block_t *)reference_node->payload;
//             for (unsigned int z1 = 0; z1 < Z; z1++) // for every block in the source bucket
//             {
//                 std::int64_t maxd = get_max_depth(bl_ev->lid, path, L);
//                 iterator = leaf_pointer;
//                 for (int j = L; j > i; j--) // for every bucket from leaf to the one right under [i]
//                 {
//                     bool can_reside = maxd >= j;
//                     bl = (block_t *)iterator->payload;
//                     for (unsigned int z2 = 0; z2 < Z; z2++) // for every block in the target bucket
//                     {
//                         bool free_slot = bl->bid == DUMMY;
//                         swap(can_reside & free_slot, (std::uint8_t *)bl, (std::uint8_t *)bl_ev, block_size);
//                         can_reside &= !free_slot;

//                         bl = (block_t *)((std::uint8_t *)bl + block_size);
//                     }
//                     iterator = iterator->parent;
//                 }
//                 bl_ev = (block_t *)((std::uint8_t *)bl_ev + block_size);
//             }
//             reference_node->unlock();
//             reference_node = reference_node->parent;
//         }

//         reference_node = local_subtree.getroot();

//         for (unsigned int i = 0; i < SS; ++i)
//             pthread_mutex_lock(&stash_locks[i]);

//         for (int i = 0; i <= L; ++i)
//         {
//             reference_node->lock();
//             reference_node = (path >> i) & 1 ? reference_node->child_r : reference_node->child_l;
//         }
//         for (unsigned int i = 0; i < SS - 1; ++i)
//         {
//             for (unsigned int j = 0; j < ss; ++j)
//             {
//                 unsigned int k = i * ss + j;

//                 std::int64_t maxd = get_max_depth(stash[k].lid, path, L);
//                 iterator = leaf_pointer;
//                 for (int h = L; h >= 0; h--) // for every bucket in the path
//                 {
//                     bool can_reside = maxd >= h;
//                     bl = (block_t *)iterator->payload;

//                     for (unsigned int z = 0; z < Z; z++) // for every block in a bucket
//                     {
//                         bool free_slot = bl->bid == DUMMY;
//                         swap(can_reside & free_slot, (std::uint8_t *)&stash[k], (std::uint8_t *)bl, block_size);
//                         can_reside &= !free_slot;
//                         bl = (block_t *)((std::uint8_t *)bl + block_size);
//                     }
//                     iterator = iterator->parent;
//                 }
//             }
//             pthread_mutex_unlock(&stash_locks[i]);
//         }

//         for (unsigned int i = 0; i < S % ss; ++i)
//         {
//             unsigned int k = (SS - 1) * ss + i;

//             std::int64_t maxd = get_max_depth(stash[k].lid, path, L);
//             iterator = leaf_pointer;
//             for (int j = L; j >= 0; j--) // for every bucket in the path (in reverse order)
//             {
//                 bool can_reside = maxd >= j;
//                 bl = (block_t *)iterator->payload;

//                 for (unsigned int z = 0; z < Z; z++) // for every block in a bucket
//                 {
//                     bool free_slot = bl->bid == DUMMY;
//                     swap(can_reside & free_slot, (std::uint8_t *)&stash[k], (std::uint8_t *)bl, block_size);
//                     can_reside &= !free_slot;
//                     bl = (block_t *)((std::uint8_t *)bl + block_size);
//                 }
//                 iterator = iterator->parent;
//             }
//         }
//         pthread_mutex_unlock(&stash_locks[SS - 1]);
//         reference_node = local_subtree.getroot();
//         for (int i = 0; i <= L; ++i)
//         {
//             reference_node->unlock();
//             reference_node = (path >> i) & 1 ? reference_node->child_r : reference_node->child_l;
//         }
//         multiset_unlock(path);

//         fetched_path.clear();
//         local_subtree.insert_write_queue(path);
//         return access_counter++;
//     }

//     void taostore_path::download_path(leaf_id path, std::vector<node *> &fetched_path)
//     {
//         // always start from root
//         std::int64_t l_index = 0;
//         obl_aes_gcm_128bit_tag_t reference_mac;
//         auth_data_t *adata;
//         bool valid = false;
//         int i = 0;
//         block_t *bl;

//         node *reference_node = local_subtree.getroot();
//         node *old_ref_node = local_subtree.getroot();

//         fetched_path.reserve(L + 1);

//         for (i = 0; i <= L && reference_node != nullptr; ++i)
//         {
//             fetched_path.emplace_back(nullptr);

//             old_ref_node = reference_node;
//             reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;
//             l_index = (l_index << 1) + 1 + ((path >> i) & 1);
//         }
//         if (i <= L)
//         {
//             valid = (l_index & 1) ? old_ref_node->adata.valid_l : old_ref_node->adata.valid_r;
//             if (valid)
//             {
//                 std::uint8_t *src = tree[l_index].mac;
//                 std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
//             }
//         }
//         while (i <= L && valid)
//         {
//             fetched_path.emplace_back(new node(block_size * Z));

//             adata = &fetched_path[i]->adata;
//             std::int64_t leftch = get_left(l_index);
//             std::int64_t rightch = get_right(l_index);

//             // this data will be authenticated data in the GCM mode
//             // dump from encrypted bucket header
//             adata->valid_l = tree[l_index].reach_l;
//             adata->valid_r = tree[l_index].reach_r;

//             // dump left and right child mac if valid, otherwise pad with 0s
//             if (adata->valid_l)
//                 std::memcpy(fetched_path[i]->adata.left_mac, tree[leftch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

//             if (adata->valid_r)
//                 std::memcpy(fetched_path[i]->adata.right_mac, tree[rightch].mac, sizeof(obl_aes_gcm_128bit_tag_t));

//             // if they are not valid, authentication data for the corresponding mac would be 0x00..0
//             // however this was already covered by the memset before the loop

//             // decrypt using the IV
//             wc_AesGcmDecrypt(crypt_handle,
//                              fetched_path[i]->payload,
//                              tree[l_index].payload,
//                              Z * block_size,
//                              tree[l_index].iv,
//                              OBL_AESGCM_IV_SIZE,
//                              reference_mac,
//                              OBL_AESGCM_MAC_SIZE,
//                              (std::uint8_t *)adata,
//                              sizeof(auth_data_t));

//             // MAC mismatch is a critical error
//             //assert(dec != AES_GCM_AUTH_E);
//             // assert(dec == 0);

//             /*
// 				NB: this doesn't need to be oblivious since an attacker might always see
// 				the sequences of accesses to the buckets and understand whether or not a
// 				bucket has already been accessed
// 				NB 2: fetch this from data which was dumped and authenticated, and taken
// 				from PROTECTED MEMORY. This should avoid some kind of attacks
// 			*/
//             // evaluate the next encrypted bucket index in the binary heap
//             l_index = (l_index << 1) + 1 + ((path >> i) & 1);
//             valid = (l_index & 1) ? adata->valid_l : adata->valid_r;
//             if (valid)
//             {
//                 std::uint8_t *src = ((path >> i) & 1) ? adata->right_mac : adata->left_mac;
//                 std::memcpy(reference_mac, src, sizeof(obl_aes_gcm_128bit_tag_t));
//             }
//             ++i;
//         }

//         // fill the other buckets with "empty" blocks
//         while (i <= L)
//         {
//             fetched_path.push_back(new node(block_size * Z));
//             bl = (block_t *)fetched_path[i]->payload;
//             for (unsigned int j = 0; j < Z; ++j)
//             {
//                 bl->bid = DUMMY;
//                 bl = (block_t *)((std::uint8_t *)bl + block_size);
//             }
//             ++i;
//         }
//     }

//     void taostore_path::access_thread(request_t &_req)
//     {
//         std::uint8_t _fetched[block_size];
//         block_t *fetched = (block_t *)_fetched;

//         bool already_evicted = false;
//         std::uint64_t access_counter_1;
//         std::uint64_t access_counter_2 = 1;

//         access_counter_1 = fetch_path(_fetched, _req.bid, _req.lif);

//         fetched->bid = _req.bid;
//         fetched->lid = _req.next_lif;
//         std::memcpy(_req.data_out, fetched->payload, B);
//         if (_req.data_in != nullptr)
//             std::memcpy(fetched->payload, _req.data_in, B);
//         pthread_mutex_lock(&_req.cond_mutex);
//         _req.res_ready = true;

//         pthread_mutex_lock(&stash_locks[0]);
//         pthread_cond_signal(&_req.serializer_res_ready);
//         pthread_mutex_unlock(&_req.cond_mutex);

//         for (unsigned int i = 0; i < SS - 1; ++i)
//         {
//             for (unsigned int j = 0; j < ss; ++j)
//             {
//                 block_id sbid = stash[i * ss + j].bid;
//                 swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[i * ss + j], block_size);
//                 already_evicted = already_evicted | (sbid == DUMMY);
//             }
//             pthread_mutex_lock(&stash_locks[i + 1]);
//             pthread_mutex_unlock(&stash_locks[i]);
//         }
//         for (unsigned int i = 0; i < S % ss; ++i)
//         {
//             block_id sbid = stash[(SS - 1) * ss + i].bid;
//             swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[(SS - 1) * ss + i], block_size);
//             already_evicted = already_evicted | (sbid == DUMMY);
//         }
//         pthread_mutex_unlock(&stash_locks[SS - 1]);
//         assert(already_evicted);

//         std::uint32_t evict = evict_path++;

//         if (evict % A == 0)
//         {
//             access_counter_2 = eviction(evict / A);
//         }

//         if (access_counter_1 % K == 0 || access_counter_2 == 0)
//             write_back();
//     }

//     std::uint64_t taostore_path::fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id path)
//     {
//         // always start from root
//         std::int64_t l_index = 0;
//         int i = 0;
//         block_t *bl;
//         block_t *fetched = (block_t *)_fetched;
//         fetched->bid = DUMMY;
//         fetched->lid = DUMMY;

//         std::vector<node *> fetched_path;

//         //fetch_path della circuit.
//         node *reference_node;
//         node *old_ref_node;
//         old_ref_node = local_subtree.getroot();
//         reference_node = local_subtree.getroot();

//         multiset_lock(path);

//         download_path(path, fetched_path);
//         pthread_mutex_lock(&stash_locks[0]);
//         for (unsigned int i = 0; i < SS - 1; ++i)
//         {
//             for (unsigned int j = 0; j < ss; ++j)
//             {
//                 block_id sbid = stash[i * ss + j].bid;
//                 swap(bid == sbid, _fetched, (std::uint8_t *)&stash[i * ss + j], block_size);
//             }
//             pthread_mutex_lock(&stash_locks[i + 1]);
//             pthread_mutex_unlock(&stash_locks[i]);
//         }
//         for (unsigned int i = 0; i < S % ss; ++i)
//         {
//             block_id sbid = stash[(SS - 1) * ss + i].bid;
//             swap(bid == sbid, _fetched, (std::uint8_t *)&stash[(SS - 1) * ss + i], block_size);
//         }
//         for (i = 0; i <= L && reference_node != nullptr; ++i)
//         {
//             reference_node->lock();
//             if (i != 0)
//                 old_ref_node->unlock();
//             else
//                 pthread_mutex_unlock(&stash_locks[SS - 1]);

//             bl = (block_t *)reference_node->payload;
//             for (unsigned int j = 0; j < Z; ++j)
//             {
//                 swap(bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
//                 bl = ((block_t *)((std::uint8_t *)bl + block_size));
//             }
//             old_ref_node = reference_node;

//             reference_node = (path >> i) & 1 ? old_ref_node->child_r : old_ref_node->child_l;

//             l_index = (l_index << 1) + 1 + ((path >> i) & 1);
//         }

//         while (i <= L)
//         {
//             (l_index & 1) ? old_ref_node->child_l = fetched_path[i] : old_ref_node->child_r = fetched_path[i];
//             reference_node = (l_index & 1) ? old_ref_node->child_l : old_ref_node->child_r;
//             reference_node->parent = old_ref_node;
//             local_subtree.newnode();

//             reference_node->lock();
//             old_ref_node->unlock();

//             bl = (block_t *)reference_node->payload;
//             for (unsigned int j = 0; j < Z; ++j)
//             {
//                 swap(bl->bid == bid, _fetched, (std::uint8_t *)bl, block_size);
//                 bl = ((block_t *)((std::uint8_t *)bl + block_size));
//             }
//             old_ref_node = reference_node;

//             l_index = (l_index << 1) + 1 + ((path >> i) & 1);
//             ++i;
//         }

//         old_ref_node->unlock();
//         multiset_unlock(path);
//         fetched_path.clear();

//         local_subtree.insert_write_queue(path);
//         return access_counter++;
//     }

//     void taostore_path::write_thread(request_t &_req)
//     {
//         std::uint8_t _fetched[block_size];
//         block_t *fetched = (block_t *)_fetched;

//         std::uint64_t access_counter = 1;
//         bool already_evicted = false;

//         fetched->bid = _req.bid;
//         fetched->lid = _req.next_lif;
//         std::memcpy(fetched->payload, _req.data_in, B);
//         pthread_mutex_lock(&_req.cond_mutex);
//         _req.res_ready = true;

//         pthread_mutex_lock(&stash_locks[0]);
//         pthread_cond_signal(&_req.serializer_res_ready);
//         pthread_mutex_unlock(&_req.cond_mutex);
//         for (unsigned int i = 0; i < SS - 1; ++i)
//         {
//             for (unsigned int j = 0; j < ss; ++j)
//             {
//                 block_id sbid = stash[i * ss + j].bid;
//                 swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[i * ss + j], block_size);
//                 already_evicted = already_evicted | (sbid == DUMMY);
//             }
//             pthread_mutex_lock(&stash_locks[i + 1]);
//             pthread_mutex_unlock(&stash_locks[i]);
//         }
//         for (unsigned int i = 0; i < S % ss; ++i)
//         {
//             block_id sbid = stash[(SS - 1) * ss + i].bid;
//             swap(!already_evicted & (sbid == DUMMY), _fetched, (std::uint8_t *)&stash[(SS - 1) * ss + i], block_size);
//             already_evicted = already_evicted | (sbid == DUMMY);
//         }
//         pthread_mutex_unlock(&stash_locks[SS - 1]);

//         assert(already_evicted);

//         std::uint32_t evict = evict_path++;

//         if (evict % A == 0)
//         {
//             access_counter = eviction(evict / A);
//         }
//         if (access_counter % K == 0)
//             write_back();
//     }
//     void taostore_path::write_back()
//     {
//         std::unordered_map<std::int64_t, node *> nodes_level_i[L + 1];
//         std::int64_t l_index;
//         bool flag;
//         obl_aes_gcm_128bit_iv_t iv;
//         obl_aes_gcm_128bit_tag_t mac;
//         node *reference_node;
//         node *parent;
//         leaf_id *_paths = new leaf_id[K];
//         int tmp = K;

//         assert(local_subtree.get_nodes_count() * (sizeof(node) + bucket_size) < 2 << 25);
//         nodes_level_i[L].reserve(K);

//         local_subtree.get_pop_queue(K, _paths);

//         local_subtree.update_valid(_paths, K, tree, nodes_level_i[L]);
//         for (int i = L; i > 0; --i)
//         {
//             tmp = tmp / 2;
//             nodes_level_i[i - 1].reserve(tmp);
//             for (auto &itx : nodes_level_i[i])
//             {
//                 flag = false;
//                 l_index = itx.first;
//                 reference_node = itx.second;
//                 parent = reference_node->parent;

//                 if (reference_node->trylock() == 0)
//                 {
//                     // generate a new random IV
//                     gen_rand(iv, OBL_AESGCM_IV_SIZE);

//                     // save encrypted payload
//                     wc_AesGcmEncrypt(crypt_handle,
//                                      tree[l_index].payload,
//                                      reference_node->payload,
//                                      Z * block_size,
//                                      iv,
//                                      OBL_AESGCM_IV_SIZE,
//                                      mac,
//                                      OBL_AESGCM_MAC_SIZE,
//                                      (std::uint8_t *)&reference_node->adata,
//                                      sizeof(auth_data_t));

//                     // save "mac" + iv + reachability flags
//                     std::memcpy(tree[l_index].mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
//                     std::memcpy(tree[l_index].iv, iv, sizeof(obl_aes_gcm_128bit_iv_t));

//                     // update the mac for the parent for the evaluation of its mac
//                     std::uint8_t *target_mac = (l_index & 1) ? parent->adata.left_mac : parent->adata.right_mac;
//                     std::memcpy(target_mac, mac, sizeof(obl_aes_gcm_128bit_tag_t));
//                     if (parent->trylock() == 0)
//                     {
//                         pthread_mutex_lock(&multi_set_lock);
//                         if (reference_node->child_r == nullptr && reference_node->child_l == nullptr &&
//                             path_req_multi_set.find(l_index) == path_req_multi_set.end())
//                         {
//                             if (l_index & 1)
//                                 parent->child_l = nullptr;
//                             else
//                                 parent->child_r = nullptr;
//                             reference_node->wb_unlock();
//                             flag = true;
//                         }
//                         pthread_mutex_unlock(&multi_set_lock);
//                         parent->unlock();
//                     }
//                     reference_node->unlock();
//                 }
//                 if (flag)
//                 {
//                     if (parent->wb_trylock() == 0)
//                         nodes_level_i[i - 1][get_parent(l_index)] = parent;
//                     delete reference_node;
//                     local_subtree.removenode();
//                 }
//                 else
//                     reference_node->wb_unlock();
//             }
//             nodes_level_i[i].clear();
//         }
//         delete[] _paths;
//     } // namespace obl

// } // namespace obl