#ifndef TAOSTORE_CIRCUIT_1_PARALLEL_H
#define TAOSTORE_CIRCUIT_1_PARALLEL_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore_p.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"
#include "obl/taostore_pos_map.h"
#include "obl/threadpool.h"

namespace obl
{

	class taostore_circuit_1_parallel : public taostore_oram_parallel
	{
	private:
		void access_thread(request_t &_req);

		std::uint64_t fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake);
		std::uint64_t eviction(leaf_id path);
		void write_back(std::uint32_t c);

	public:
		taostore_circuit_1_parallel(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : taostore_oram_parallel(N, B, Z, S, T_NUM){};

		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class taostore_circuit_1_parallel_factory : public oram_factory	{
	private:
		unsigned int Z, S, T_NUM;
	public:
		taostore_circuit_1_parallel_factory(unsigned int Z, unsigned int S, unsigned int T_NUM)	{
			this->Z = Z;
			this->S = S;
			this->T_NUM = T_NUM;
		}

		tree_oram *spawn_oram(std::size_t N, std::size_t B)
		{
			return new taostore_circuit_1_parallel(N, B, Z, S, T_NUM);
		}
		bool is_taostore(){ return true; }
	};
} // namespace obl

#endif // TAOSTORE_CIRCUIT_1_PARALLEL_H
