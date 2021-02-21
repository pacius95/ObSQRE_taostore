#ifndef OBL_REC_TAOSTORE_H
#define OBL_REC_TAOSTORE_H

#include "obl/oram.h"
#include "obl/taostore_p.h"
#include "obl/rec.h"

#include <cstddef>

namespace obl
{

	class recursive_parallel : public recursive_oram
	{
	private:
		std::size_t N;
		taostore_oram_parallel * toram;

	public:
		recursive_parallel(std::size_t N, std::size_t B, oram_factory *allocator);
		~recursive_parallel();

		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);
	};

} // namespace obl

#endif // OBL_REC_TAOSTORE_H
