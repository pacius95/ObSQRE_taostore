#include <iostream>
#include <chrono>
#include <vector>
#include <cstdint>
#include <cassert>
#include <iomanip>

#include "obl/taostore.h"
#include "obl/circuit.h"

#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"

#define C 5
#define S 8*(1 + T_NUM/8)
#define Z 3

using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

const int pow_lower = 14;
const int pow_upper = 20;
const int bench_size = 1 << 15;

struct buffer
{
	std::uint8_t _buffer[8];
	bool operator==(const buffer &rhs) const
	{
		return !memcmp(_buffer, rhs._buffer, sizeof(_buffer));
	}
};

;
struct work_args
{
	obl::taostore_oram *rram;
	std::vector<uint64_t> *_mirror_data;
};

void *work(void *T)
{
	work_args args = *(work_args *)T;
	uint64_t value_out;
	std::size_t N = args.rram->get_N();
	unsigned int rnd_bid;
 
	for (int j = 0; j < bench_size; j++)
	{
		obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
		rnd_bid = (rnd_bid >> 1) % N;
		args.rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
		assert( value_out == (*args._mirror_data)[rnd_bid] );
	}
	return nullptr;
};

int main()
{
	int RUN;
	tt start, end;
	nano duration;
	unsigned int rnd_bid;
	std::vector<std::uint64_t> mirror_data;
	std::uint64_t value, value_out;
	mirror_data.reserve(1 << pow_upper);
	std::cout << std::setprecision(4);

	for (int p = pow_lower; p < pow_upper; p++)
	{
		for (int T_NUM = 1; T_NUM < 10; T_NUM++)
		{
			std::size_t N = 1 << p;
			pthread_t workers[16];

			{
				obl::taostore_oram rram(N, sizeof(std::uint64_t), Z, S, T_NUM);
				N = rram.get_N();

				for (unsigned int i = 0; i < N; i++)
				{
					obl::gen_rand((std::uint8_t *)&value, sizeof(std::uint64_t));
					rram.access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

					mirror_data[i] = value;
				}

				std::cout << "start serial with N:" << N << " T_NUM:" << T_NUM << std::endl;

				start = hres::now();
				for (int j = 0; j < bench_size; j++)
				{
					obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
					rnd_bid = (rnd_bid >> 1) % N;

					rram.access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
					assert(value_out == mirror_data[rnd_bid]);
				}
				end = hres::now();
				duration = end - start;
				std::cout << "tempo: " << duration.count()/1000000000.0 << "s" <<std::endl;
			}

/*			{
				RUN = 4;
				std::cout << "start parallel with N:" << N << " T_NUM:" << T_NUM << " RUN: " << RUN << std::endl;

				obl::taostore_oram rram1(N, sizeof(uint64_t), Z, S, T_NUM);
				N = rram1.get_N();
				for (unsigned int i = 0; i < N; i++)
				{
					obl::gen_rand((std::uint8_t *)&value, sizeof(uint64_t));
					rram1.access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

					mirror_data[i] = value;
				}
				work_args args[RUN];
				start = hres::now();
				for (int i = 0; i < RUN; i++)
				{
					args[i] = {&rram1, &mirror_data};
					pthread_create(&workers[i], nullptr, work, (void *)&args[i]);
				}

				for (int i = 0; i < RUN; i++)
				{
					pthread_join(workers[i], nullptr);
				}
				end = hres::now();
				duration = end - start;
				std::cout << "tempo: " << duration.count() << '\n';
			}

			{
				obl::taostore_oram rram2(N, sizeof(uint64_t), Z, S, T_NUM);
				RUN = 8;
				std::cout << "start parallel with N:" << N << " T_NUM:" << T_NUM << " RUN: " << RUN << std::endl;
				N = rram2.get_N();
				for (unsigned int i = 0; i < N; i++)
				{
					obl::gen_rand((std::uint8_t *)&value, sizeof(uint64_t));
					rram2.access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

					mirror_data[i] = value;
				}

				work_args args2[RUN];
				start = hres::now();
				for (int i = 0; i < RUN; i++)
				{
					args2[i] = {&rram2, &mirror_data};
					pthread_create(&workers[i], nullptr, work, (void *)&args2[i]);
				}

				for (int i = 0; i < RUN; i++)
				{
					pthread_join(workers[i], nullptr);
				}
				end = hres::now();
				duration = end - start;
				std::cout << "tempo: " << duration.count() << '\n';
			}
*/
		
			{
				RUN = 16;
				std::cout << "start parallel with N:" << N << " T_NUM:" << T_NUM << " RUN: " << RUN << std::endl;

				obl::taostore_oram rram3(N, sizeof(uint64_t), Z, S, T_NUM);
				N = rram3.get_N();
				for (unsigned int i = 0; i < N; i++)
				{
					obl::gen_rand((std::uint8_t *)&value, sizeof(uint64_t));
					rram3.access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

					mirror_data[i] = value;
				}
				work_args args3[RUN];
				start = hres::now();
				for (int i = 0; i < RUN; i++)
				{
					args3[i] = {&rram3, &mirror_data};
					pthread_create(&workers[i], nullptr, work, (void *)&args3[i]);
				}

				for (int i = 0; i < RUN; i++)
				{
					pthread_join(workers[i], nullptr);
				}
				end = hres::now();
				duration = end - start;
				std::cout << "tempo: " << duration.count()/1000000000.0 << "s" <<std::endl;
			}
		}
	}

	return 0;
};