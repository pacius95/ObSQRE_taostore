#ifndef TAOSTORE_CIRCUIT_2_H
#define TAOSTORE_CIRCUIT_2_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"

namespace obl
{

	class taostore_circuit_2 : public taostore_oram
	{
	private:
		~taostore_circuit_2();
		void access_thread(request_t &_req);
		void write_thread(request_t &_req);
		void read_thread(request_t &_req);
		
		void download_path(leaf_id path, std::vector<std::shared_ptr<node>> &fetched_path);
		std::uint64_t fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id path);
		std::uint64_t eviction(leaf_id path);
		void write_back();

	public:
		taostore_circuit_2(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : taostore_oram(N, B, Z, S, T_NUM){};
		// only write block into the stash and perfom evictions
	};

	class taostore_circuit_2_factory : public oram_factory	{
	private:
		unsigned int Z, S, T_NUM;
	public:
		taostore_circuit_2_factory(unsigned int Z, unsigned int S, unsigned int T_NUM)	{
			this->Z = Z;
			this->S = S;
			this->T_NUM = T_NUM;
		}
		tree_oram* spawn_oram(std::size_t N, std::size_t B)	{
			return new taostore_circuit_2(N, B, Z, S, T_NUM);
		}
		bool is_taostore() {return false;}
	};
} // namespace obl

#endif // TAOSTORE_CIRCUIT_2_H
