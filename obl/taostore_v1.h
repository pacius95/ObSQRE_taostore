#ifndef TAOSTORE_ORAM_V1_H
#define TAOSTORE_ORAM_V1_H

#include "obl/types.h"
#include "obl/oram.h"
#include "obl/taostore.h"
#include "obl/taostore_types.hpp"
#include "obl/flexible_array.hpp"
#include "obl/taostore_pos_map.h"
#include "obl/taostore_subtree.hpp"
#include "obl/threadpool.h"

namespace obl
{

	class taostore_oram_v1 : public taostore_oram
	{
	private:

		void access_thread(request_t &_req);

		// static void eviction_thread_wrap(void *object);
		// void eviction_thread(void *_request);

		void read_path(request_t &req, std::uint8_t *_fetched);
		void fetch_path(std::uint8_t *_fetched, block_id bid, leaf_id new_lid, leaf_id path, bool fake);
		void answer_request(request_t &req, std::uint8_t *fetched);
		void eviction(leaf_id path);

	public:
		taostore_oram_v1(std::size_t N, std::size_t B, unsigned int Z, unsigned int S, unsigned int T_NUM) : taostore_oram(N, B, Z, S, T_NUM){};
		~taostore_oram_v1();

		void access(block_id bid, std::uint8_t *data_in, std::uint8_t *data_out);

		void write(block_id bid, std::uint8_t *data_in, leaf_id next_lif);
	};

	class taostore_factory_v1 : public taostore_factory
	{
	private:
		unsigned int Z, S;

	public:
		taostore_factory_v1(unsigned int Z, unsigned int S)
		{
			this->Z = Z;
			this->S = S;
		}
		taostore_oram *spawn_oram(std::size_t N, std::size_t B, std::size_t T_NUM)
		{
			return new taostore_oram_v1(N, B, Z, S, 4);
		}
	};
} // namespace obl

#endif // TAOSTORE_ORAM_H
