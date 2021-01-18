#ifndef OBL_REC_H
#define OBL_REC_H

#include "obl/oram.h"

#include <cstddef>

namespace obl
{

	class recursive_oram
	{
	public:
		virtual ~recursive_oram() { };

		virtual void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out) = 0;
	};

} // namespace obl

#endif // OBL_REC_H
