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

		void download_path(leaf_id path, std::vector<node *> fetched_path);
		void fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake);
		void eviction(leaf_id path);

	public:
		taostore_oram_v2(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : taostore_oram(N, B, Z, S, T_NUM){};

		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);

		// only write block into the stash and perfom evictions
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class taostore_factory_v2 : public taostore_factory
	{
	private:
		unsigned int Z, S;

	public:
		taostore_factory_v2(unsigned int Z, unsigned int S)
		{
			this->Z = Z;
			this->S = S;
		}
		taostore_oram *spawn_oram(std::size_t N, std::size_t B, std::size_t T_NUM)
		{
			return new taostore_oram_v2(N, B, Z, S, T_NUM);
		}
	};
} // namespace obl

#endif // TAOSTORE_ORAM_V2_H
