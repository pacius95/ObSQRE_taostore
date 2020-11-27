#include "obl/taostore.h"
#include "obl/taostore_v1.h"
#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"
#include "obl/circuit.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <ctime>

#define P 18
#define N (1 << P)
#define bench_size (1 << 15)
#define RUN 2

#define S 8
#define Z 3

using namespace std;

struct buffer
{
	std::uint8_t _buffer[8];
	bool operator==(const buffer &rhs) const
	{
		return !memcmp(_buffer, rhs._buffer, sizeof(_buffer));
	}
};

int main()
{
	vector<buffer> mirror_data;

	obl::taostore_oram_v1 rram(N, sizeof(buffer), Z, S, 3);

	uint32_t rnd_bid;
	buffer value, value_out;
	std::clock_t start;
	double duration;

	mirror_data.reserve(N);

	for (unsigned int i = 0; i < N; i++)
	{
		obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

		rram.access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);
		mirror_data[i] = value;
	}

	cerr << "finished init" << endl;
	/* Your algorithm here */

	for (int i = 0; i < RUN; i++)
	{
		start = std::clock();
		for (int j = 0; j < bench_size; j++)
		{
			obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
			rnd_bid = (rnd_bid >> 1) % N;
			rram.access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
			assert(value_out == mirror_data[rnd_bid]);
		}
		cerr << "Run " << i << " finished" << endl;
		duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
		std::cerr << "printf: " << duration << '\n';
	}
	return 0;
}