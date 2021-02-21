#include "obl/mose.h"
#include "obl/primitives.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <chrono>
#include <ctime>

#define P 17
#define N (1 << P)
#define bench_size (1 << 18)
#define T_NUM 32

using hres = std::chrono::high_resolution_clock;
using _nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, _nano>;

#define S 8
#define Z 3

using namespace std;
struct buffer
{
	std::uint8_t _buffer[24000];
	bool operator==(const buffer &rhs) const
	{
		return !memcmp(_buffer, rhs._buffer, sizeof(_buffer));
	}
};
int main()
{
	vector<obl::leaf_id> position_map;
	vector<buffer> mirror_data;

	obl::mose *rram;
	buffer value, value_out;
	position_map.reserve(N);
	mirror_data.reserve(N);
	tt start, end;
	_nano duration;
	uint32_t rnd_bid;
	for (unsigned int k = 17; k < T_NUM; k++)
	{
		rram = new obl::mose(N, sizeof(buffer), Z, S, k);

		for (unsigned int i = 0; i < N; i++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));
			obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

			rram->write(i, (std::uint8_t *)&value, next_leef);
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
			rram->access(rnd_bid, position_map[rnd_bid], nullptr, (std::uint8_t *)&value_out, next_leef);
			position_map[rnd_bid] = next_leef;

			assert(value_out == mirror_data[rnd_bid]);
		}
		end = hres::now();
		duration = end - start;
		std::cout << "mose" << "," << N << "," << sizeof(buffer) << "," << k << "," << bench_size << "," << duration.count() << std::endl;
		delete rram;
	}
return 0;
}
