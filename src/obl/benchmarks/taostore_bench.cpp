#include <iostream>
#include <chrono>
#include <vector>
#include <cstdint>
#include <cassert>
#include <iomanip>

#include "obl/taostore.h"
#include "obl/taostore_path.h"
#include "obl/taostore_v2.h"
#include "obl/taostore_v1.h"
#include "obl/circuit.h"
#include "obl/path.h"

#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"

#define C 5
#define S 8
#define Z 3

using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

const int pow_lower = 14;
const int pow_upper = 27;
const int bench_size = 1 << 16;

struct buffer
{
	std::uint8_t _buffer[8];
	bool operator==(const buffer &rhs) const
	{
		return !memcmp(_buffer, rhs._buffer, sizeof(_buffer));
	}
};
struct work_args
{
	obl::taostore_oram *rram;
	std::vector<buffer> *_mirror_data;
};

void *work(void *T)
{
	work_args args = *(work_args *)T;
	buffer value_out;
	std::size_t N = args.rram->get_N();
	unsigned int rnd_bid;

	for (int j = 0; j < bench_size / 8; j++)
	{
		obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
		rnd_bid = (rnd_bid >> 1) % N;
		args.rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
		assert(value_out == (*args._mirror_data)[rnd_bid]);
	}
	return nullptr;
};

int main()
{
	int RUN;
	tt start, end;
	nano duration;
	unsigned int rnd_bid;
	std::vector<buffer> mirror_data;
	std::vector<obl::leaf_id> position_map;
	buffer value, value_out;
	mirror_data.reserve(1 << pow_upper);
	position_map.reserve(1 << pow_upper);
	std::cout << std::setprecision(4);

	std::cout << "benchmarc block size:" << sizeof(buffer) << " bench size: " << bench_size << std::endl;
	for (int p = pow_lower; p < pow_upper; p = p + 2)
	{
		std::size_t N = 1 << p;

		// std::cout << "start recursive:" << N << std::endl;
		// obl::coram_factory of(3, 8);
		// obl::recursive_oram *rram_rec = new obl::recursive_oram(N, sizeof(buffer), 5, &of);

		// for (unsigned int i = 0; i < N; i++)
		// {
		// 	obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
		// 	rram_rec->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

		// 	mirror_data[i] = value;
		// }

		// start = hres::now();
		// for (int j = 0; j < bench_size; j++)
		// {
		// 	obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
		// 	rnd_bid = (rnd_bid >> 1) % N;

		// 	rram_rec->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
		// 	assert(value_out == mirror_data[rnd_bid]);
		// }
		// end = hres::now();
		// duration = end - start;
		// std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
		// delete rram_rec;

		std::cout << "start circuit:" << N << std::endl;

		obl::circuit_oram *circ = new obl::circuit_oram(N, sizeof(buffer), 3, 8);

		for (unsigned int i = 0; i < N; i++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));
			obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

			circ->write(i, (std::uint8_t *)&value, next_leef);
			mirror_data[i] = value;
			position_map[i] = next_leef;
		}

		start = hres::now();
		for (int j = 0; j < bench_size; j++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));
			obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
			rnd_bid = (rnd_bid >> 1) % N;
			circ->access(rnd_bid, position_map[rnd_bid], nullptr, (std::uint8_t *)&value_out, next_leef);
			position_map[rnd_bid] = next_leef;

			assert(value_out == mirror_data[rnd_bid]);
		}
		end = hres::now();
		duration = end - start;
		std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
		delete circ;

		std::cout << "start path 4_3:" << N << std::endl;

		obl::path_oram *path4_3 = new obl::path_oram(N, sizeof(buffer), 4, 32, 3);

		for (unsigned int i = 0; i < N; i++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));
			obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

			path4_3->write(i, (std::uint8_t *)&value, next_leef);
			mirror_data[i] = value;
			position_map[i] = next_leef;
		}

		start = hres::now();
		for (int j = 0; j < bench_size; j++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));
			obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
			rnd_bid = (rnd_bid >> 1) % N;
			path4_3->access(rnd_bid, position_map[rnd_bid], nullptr, (std::uint8_t *)&value_out, next_leef);
			position_map[rnd_bid] = next_leef;

			assert(value_out == mirror_data[rnd_bid]);
		}
		end = hres::now();
		duration = end - start;
		std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
		delete path4_3;

		std::cout << "start path 8_8:" << N << std::endl;

		obl::path_oram *path8_8 = new obl::path_oram(N, sizeof(buffer), 8, 41, 8);

		for (unsigned int i = 0; i < N; i++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));
			obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

			path8_8->write(i, (std::uint8_t *)&value, next_leef);
			mirror_data[i] = value;
			position_map[i] = next_leef;
		}

		start = hres::now();
		for (int j = 0; j < bench_size; j++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));
			obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
			rnd_bid = (rnd_bid >> 1) % N;
			path8_8->access(rnd_bid, position_map[rnd_bid], nullptr, (std::uint8_t *)&value_out, next_leef);
			position_map[rnd_bid] = next_leef;

			assert(value_out == mirror_data[rnd_bid]);
		}
		end = hres::now();
		duration = end - start;
		std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
		delete path8_8;

		for (int T_NUM = 1; T_NUM < 4; T_NUM++)
		{
			pthread_t workers[16];

			std::cout << "start v1 serial with N:" << N << " T_NUM:" << T_NUM << std::endl;
			obl::taostore_oram_v1 *rram_v1 = new obl::taostore_oram_v1(N, sizeof(buffer), Z, S, T_NUM);
			for (unsigned int i = 0; i < N; i++)
			{
				obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
				rram_v1->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

				mirror_data[i] = value;
			}

			start = hres::now();
			for (int j = 0; j < bench_size; j++)
			{
				obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
				rnd_bid = (rnd_bid >> 1) % N;

				rram_v1->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
				assert(value_out == mirror_data[rnd_bid]);
			}
			end = hres::now();
			duration = end - start;
			std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
			delete rram_v1;

			std::cout << "start v2 serial with N:" << N << " T_NUM:" << T_NUM << std::endl;
			obl::taostore_oram_v2 *rram_v2 = new obl::taostore_oram_v2(N, sizeof(buffer), Z, S, T_NUM);

			for (unsigned int i = 0; i < N; i++)
			{
				obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
				rram_v2->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

				mirror_data[i] = value;
			}

			start = hres::now();
			for (int j = 0; j < bench_size; j++)
			{
				obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
				rnd_bid = (rnd_bid >> 1) % N;

				rram_v2->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
				assert(value_out == mirror_data[rnd_bid]);
			}
			end = hres::now();
			duration = end - start;
			std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
			delete rram_v2;

			std::cout << "start path4_3 serial with N:" << N << " T_NUM:" << T_NUM << std::endl;
			
			obl::taostore_path_oram *rram_4_3 = new obl::taostore_path_oram(N, sizeof(buffer), 4, 32, 3, T_NUM);

			for (unsigned int i = 0; i < N; i++)
			{
				obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
				rram_4_3->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

				mirror_data[i] = value;
			}

			start = hres::now();
			for (int j = 0; j < bench_size; j++)
			{
				obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
				rnd_bid = (rnd_bid >> 1) % N;

				rram_4_3->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
				assert(value_out == mirror_data[rnd_bid]);
			}
			end = hres::now();
			duration = end - start;
			std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
			delete rram_4_3;

			std::cout << "start path8_8 serial with N:" << N << " T_NUM:" << T_NUM << std::endl;
			obl::taostore_path_oram *rram_8_8 = new obl::taostore_path_oram(N, sizeof(buffer), 8, 41, 8, T_NUM);

			for (unsigned int i = 0; i < N; i++)
			{
				obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
				rram_8_8->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

				mirror_data[i] = value;
			}

			start = hres::now();
			for (int j = 0; j < bench_size; j++)
			{
				obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
				rnd_bid = (rnd_bid >> 1) % N;

				rram_8_8->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
				assert(value_out == mirror_data[rnd_bid]);
			}
			end = hres::now();
			duration = end - start;
			std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
			delete rram_8_8;

			RUN = 8;
			std::cout << "start v1 parallel with N:" << N << " T_NUM:" << T_NUM << " RUN: " << RUN << std::endl;

			obl::taostore_oram_v1 *rram3_v1 = new obl::taostore_oram_v1(N, sizeof(buffer), Z, S, T_NUM);
			for (unsigned int i = 0; i < N; i++)
			{
				obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
				rram3_v1->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

				mirror_data[i] = value;
			}
			work_args args3_v1[RUN];
			start = hres::now();
			for (int i = 0; i < RUN; i++)
			{
				args3_v1[i] = {rram3_v1, &mirror_data};
				pthread_create(&workers[i], nullptr, work, (void *)&args3_v1[i]);
			}

			for (int i = 0; i < RUN; i++)
			{
				pthread_join(workers[i], nullptr);
			}
			end = hres::now();
			duration = end - start;
			std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
			delete rram3_v1;

			RUN = 8;
			std::cout << "start v2 parallel with N:" << N << " T_NUM:" << T_NUM << " RUN: " << RUN << std::endl;

			obl::taostore_oram_v2 *rram3_v2 = new obl::taostore_oram_v2(N, sizeof(buffer), Z, S, T_NUM);
			for (unsigned int i = 0; i < N; i++)
			{
				obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
				rram3_v2->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

				mirror_data[i] = value;
			}
			work_args args3_v2[RUN];
			start = hres::now();
			for (int i = 0; i < RUN; i++)
			{
				args3_v2[i] = {rram3_v2, &mirror_data};
				pthread_create(&workers[i], nullptr, work, (void *)&args3_v2[i]);
			}

			for (int i = 0; i < RUN; i++)
			{
				pthread_join(workers[i], nullptr);
			}
			end = hres::now();
			duration = end - start;
			std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
			delete rram3_v2;


			RUN = 8;
			std::cout << "start path_4_3 parallel with N:" << N << " T_NUM:" << T_NUM << " RUN: " << RUN << std::endl;

			obl::taostore_path_oram *rram3_4_3 = new obl::taostore_path_oram(N, sizeof(buffer), 4, 32, 3, T_NUM);
			for (unsigned int i = 0; i < N; i++)
			{
				obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
				rram3_4_3->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

				mirror_data[i] = value;
			}
			work_args args3_path[RUN];
			start = hres::now();
			for (int i = 0; i < RUN; i++)
			{
				args3_path[i] = {rram3_4_3, &mirror_data};
				pthread_create(&workers[i], nullptr, work, (void *)&args3_path[i]);
			}

			for (int i = 0; i < RUN; i++)
			{
				pthread_join(workers[i], nullptr);
			}
			end = hres::now();
			duration = end - start;
			std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
			delete rram3_4_3;

			RUN = 8;
			std::cout << "start path_8_8 parallel with N:" << N << " T_NUM:" << T_NUM << " RUN: " << RUN << std::endl;

			obl::taostore_path_oram *rram3_8_8 = new obl::taostore_path_oram(N, sizeof(buffer), 8, 41, 8, T_NUM);
			for (unsigned int i = 0; i < N; i++)
			{
				obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
				rram3_8_8->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

				mirror_data[i] = value;
			}
			work_args args3_path_8[RUN];
			start = hres::now();
			for (int i = 0; i < RUN; i++)
			{
				args3_path_8[i] = {rram3_8_8, &mirror_data};
				pthread_create(&workers[i], nullptr, work, (void *)&args3_path_8[i]);
			}

			for (int i = 0; i < RUN; i++)
			{
				pthread_join(workers[i], nullptr);
			}
			end = hres::now();
			duration = end - start;
			std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
			delete rram3_8_8;
		}
	}
	return 0;
};