#ifndef TAOSTORE_PATH_ORAM_H
#define TAOSTORE_PATH_ORAM_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"
#include "obl/taostore_pos_map.h"
#include "obl/threadpool.h"

#include <wolfcrypt/aes.h>

#ifdef SGX_ENCLAVE_ENABLED
#include "obl/sgx_host_allocator.hpp"
#endif

namespace obl
{

	struct processing_thread_args;

	class taostore_path_oram : public taostore_oram
	{
	private:
		// private methods

		void access_thread(request_t &_req);

		void download_path(leaf_id path, std::vector<node *> &fetched_path);
		std::uint64_t fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake);
		std::uint64_t eviction(leaf_id path);
		void write_back(std::uint32_t c);

	public:
		taostore_path_oram(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int A, unsigned int T_NUM);

		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class taostore_path_factory : public oram_factory
	{
	private:
		unsigned int Z, S, A, T_NUM;

	public:
		taostore_path_factory(unsigned int Z, unsigned int S, unsigned A, unsigned T_NUM)
		{
			this->Z = Z;
			this->S = S;
			this->A = A;
			this->T_NUM = T_NUM;
		}
		tree_oram *spawn_oram(std::size_t N, std::size_t B)
		{
			// since path oram has the largest stash size, improve it
			unsigned int real_S = N < S ? N : S;
			return new taostore_path_oram(N, B, Z, real_S, A, T_NUM);
		}
		bool is_taostore() { return true; }
	};
} // namespace obl

#endif // TAOSTORE_PATH_ORAM_H
