#include "obl/rec_taostore.h"
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

	recursive_taoram::recursive_taoram(std::size_t N, std::size_t B, unsigned int csize, taostore_factory *allocator)
	{
		this->N = N;
		toram = (taostore_oram *)allocator->spawn_oram(this->N, B);
	}

	recursive_taoram::~recursive_taoram()
	{
		delete toram;
	}

	void recursive_taoram::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		toram->access(bid, data_in, data_out);
	}
} // namespace obl