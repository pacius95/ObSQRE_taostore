#ifndef TAOSTORE_TYPES_H
#define TAOSTORE_TYPES_H

#include "obl/oram.h"
#include "obl/types.h"

#include <pthread.h>
#include <cstdint>

namespace obl
{

	struct taostore_block_t
	{
		block_id bid;
		leaf_id lid;
		std::uint8_t payload[];
	};

	struct taostore_bucket_t
	{
		obl_aes_gcm_128bit_iv_t iv;
		bool reach_l, reach_r;
		obl_aes_gcm_128bit_tag_t mac __attribute__((aligned(8)));
		// since payload is going to be a multiple of 16 bytes, the struct will be memory aligned!
		std::uint8_t payload[];
	};

	struct taostore_request_t
	{
		std::uint8_t *data_in;
		block_id bid;
		bool fake;
		bool handled;
		std::uint8_t *data_out;
		bool res_ready;
		bool data_ready;
		pthread_t *thread_id;
		pthread_mutex_t *cond_mutex;
		pthread_cond_t *serializer_res_ready;
	};

	typedef taostore_block_t block_t;
	typedef taostore_bucket_t bucket_t;
	typedef taostore_request_t request_t;
} // namespace obl

#endif //TAOSTORE_TYPES_H