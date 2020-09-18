#ifndef OBL_REC_TAOSTORE_H
#define OBL_REC_TAOSTORE_H

#include "obl/oram.h"
#include "obl/taoram.h"
#include "obl/taostore_pos_map.h"
#include "obl/rec.h"
#include "obl/rec.h"

#include <cstddef>

namespace obl
{

	class recursive_taoram : public recursive_oram
	{
	private:
		taostore_position_map * rec_pos_map;
		taostore_oram * toram;

	public:
		recursive_taoram(std::size_t N, std::size_t B, unsigned int csize, oram_factory *allocator);
		~recursive_taoram();

		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);
	};

} // namespace obl

#endif // OBL_REC_TAOSTORE_H
