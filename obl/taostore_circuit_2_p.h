#ifndef TAOSTORE_CIRCUIT_2_PARALLEL_H
#define TAOSTORE_CIRCUIT_2_PARALLEL_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore_p.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"

namespace obl
{
	class taostore_circuit_2_parallel : public taostore_oram_parallel
	{
	private:
	
		~taostore_circuit_2_parallel();
		void access_thread(request_p_t &_req);
		void synch_subtree(leaf_id path, std::vector<node*> &fetched_path);
		void download_path(leaf_id path, std::vector<node*> &fetched_path);
		std::uint64_t fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake);
		std::uint64_t eviction(leaf_id path);
		void write_back();

	public:
		taostore_circuit_2_parallel(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : taostore_oram_parallel(N, B, Z, S, T_NUM){};
		// only write block into the stash and perfom evictions
		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class taostore_circuit_2_parallel_factory : public oram_factory	{
	private:
		unsigned int Z, S, T_NUM;
	public:
		taostore_circuit_2_parallel_factory(unsigned int Z, unsigned int S, unsigned int T_NUM)	{
			if (T_NUM > S)
				this->S = T_NUM;
			else
				this->S = S;
			this->Z = Z;
			this->T_NUM = T_NUM;
		}
		tree_oram* spawn_oram(std::size_t N, std::size_t B)	{
			return new taostore_circuit_2_parallel(N, B, Z, S, T_NUM);
		}
		bool is_taostore() {return true;}
	};
} // namespace obl

#endif // TAOSTORE_CIRCUIT_2_PARALLEL_H
