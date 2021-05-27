#include "obl/shadow_mose.h"
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

	shadow_mose::shadow_mose(std::size_t N, std::size_t B, unsigned int c_size, shadow_mose_factory *allocator)
	{
		this->N = N;
		shadow = (mose *)allocator->spawn_oram(this->N, B);
		shadow->set_position_map(c_size);
	}

	shadow_mose::~shadow_mose()
	{
		delete shadow;
	}

	void shadow_mose::access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out)
	{
		shadow->access(bid, data_in, data_out);
	}
} // namespace obl