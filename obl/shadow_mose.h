#ifndef OBL_SHADOW_MOSE_H
#define OBL_SHADOW_MOSE_H

#include "obl/oram.h"
#include "obl/taostore_p.h"
#include "obl/rec.h"
#include "obl/mose.h"

#include <cstddef>

namespace obl
{

	class shadow_mose : public recursive_oram
	{
	private:
		std::size_t N;
		mose * shadow;

	public:
		shadow_mose(std::size_t N, std::size_t B,unsigned int c_size, shadow_mose_factory *allocator);
		~shadow_mose();

		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);
	};

} // namespace obl

#endif // OBL_SHADOW_MOSE_H
