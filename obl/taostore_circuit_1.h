#ifndef taostore_circuit_1_H
#define taostore_circuit_1_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"
#include "obl/taostore_pos_map.h"
#include "obl/threadpool.h"

namespace obl
{

	class taostore_circuit_1 : public taostore_oram
	{
	private:
		void access_thread(request_t &_req);
		void write_thread(request_t &_req);
		
        std::uint64_t fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id path);
		std::uint64_t eviction(leaf_id path);
		void write_back();

	public:
		taostore_circuit_1(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : taostore_oram(N, B, Z, S, T_NUM){};
	};

	class taostore_circuit_1_factory : public oram_factory	{
	private:
		unsigned int Z, S, T_NUM;
	public:
		taostore_circuit_1_factory(unsigned int Z, unsigned int S, unsigned int T_NUM)	{
			this->Z = Z;
			this->S = S;
			this->T_NUM = T_NUM;
		}

		tree_oram *spawn_oram(std::size_t N, std::size_t B)
		{
			return new taostore_circuit_1(N, B, Z, S, T_NUM);
		}
		bool is_taostore(){ return true; }
	};
} // namespace obl

#endif // TAOSTORE_CIRCUIT_1_H
