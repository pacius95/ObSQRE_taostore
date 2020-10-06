#ifndef OBL_REC_POSITION_MAP_H
#define OBL_REC_POSITION_MAP_H

#include "obl/oram.h"
#include "obl/rec.h"
#include "obl/circuit_fake.h"
#include <pthread.h>
//#include <sgx_spinlock.h>

#include <cstddef>

namespace obl
{

	class taostore_position_map
	{
	private:
		std::size_t N;
		std::size_t C;

		int rmap_levs;
		int rmap_csize;

		// for all intermediate levels of the recursive position map
		int rmap_bits;
		// for the very last level
		int rmap_opt;

		circuit_fake **rmap;
		pthread_mutex_t *rmap_locks;

		leaf_id *pos_map;

		leaf_id scan_map(leaf_id *map, int idx, leaf_id replacement, bool to_init, bool fake);

	public:
		taostore_position_map(std::size_t N, std::size_t B, unsigned int csize, circuit_fake_factory *allocator);
		~taostore_position_map();

		leaf_id access(block_id bid, bool fake, leaf_id *_ev_leef);
	};

} // namespace obl

#endif // OBL_REC_POSITION_MAP_H
