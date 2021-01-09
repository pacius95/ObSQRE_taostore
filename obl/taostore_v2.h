#ifndef TAOSTORE_ORAM_V2_H
#define TAOSTORE_ORAM_V2_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"

namespace obl
{
	class taostore_oram_v2 : public taostore_oram
	{
	private:
		void access_thread(request_t &_req);

		void download_path(leaf_id path, std::vector<node *> &fetched_path);
		std::uint64_t fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake);
		std::uint64_t eviction(leaf_id path);
		void write_back(std::uint32_t c);

	public:
		taostore_oram_v2(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : taostore_oram(N, B, Z, S, T_NUM){};
		// only write block into the stash and perfom evictions
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class taostore_factory_v2 : public oram_factory	{
	private:
		unsigned int Z, S, T_NUM;
	public:
		taostore_factory_v2(unsigned int Z, unsigned int S, unsigned int T_NUM)	{
			this->Z = Z;
			this->S = S;
			this->T_NUM = T_NUM;
		}
		tree_oram* spawn_oram(std::size_t N, std::size_t B)	{
			return new taostore_oram_v2(N, B, Z, S, T_NUM);
		}
		bool is_taostore() {return true;}
	};
} // namespace obl

#endif // TAOSTORE_ORAM_V2_H
