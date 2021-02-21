#include "obl/rec_parallel.h"
#include "obl/rec.h"
#include "obl/primitives.h"

#define DUMMY_LEAF -1

namespace obl
{

	constexpr leaf_id sign_bit = (1ULL << (sizeof(leaf_id) * 8 - 1)) - 1;

	// this is to avoid generating randomly a -1!
	inline leaf_id leaf_abs(leaf_id x)
	{
		return x & sign_bit;
	}

	recursive_parallel::recursive_parallel(std::size_t N, std::size_t B, oram_factory *allocator)
	{
		this->N = N;
		toram = (taostore_oram_parallel *)allocator->spawn_oram(this->N, B);
	}

	recursive_parallel::~recursive_parallel()
	{
		delete toram;
	}

	void recursive_parallel::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		toram->access(bid, data_in, data_out);
	}
} // namespace obl