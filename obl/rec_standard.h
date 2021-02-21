#ifndef OBL_REC_STD_H
#define OBL_REC_STD_H

#include "obl/oram.h"
#include "obl/taostore.h"
#include "obl/rec.h"

#include <cstddef>

namespace obl
{

	class recursive_oram_standard : public recursive_oram
	{
	protected:
		std::size_t N;
		std::size_t C;

		int rmap_levs;
		int rmap_csize;

		// for all intermediate levels of the recursive position map
		int rmap_bits;
		// for the very last level
		int rmap_opt;

		tree_oram **rmap;
		tree_oram *oram;
		pthread_mutex_t* rmap_locks;

		leaf_id *pos_map;

		leaf_id scan_map(leaf_id *map, int idx, leaf_id replacement, bool to_init);

	public:
		recursive_oram_standard() {};
		recursive_oram_standard(std::size_t N, std::size_t B, unsigned int csize, oram_factory *allocator);
		~recursive_oram_standard();

		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);
	};

} // namespace obl

#endif // OBL_REC_STD_H
