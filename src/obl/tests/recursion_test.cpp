#include "obl/circuit.h"
#include "obl/path.h"
#include "obl/rec_taostore.h"
#include "obl/taostore_v1.h"
#include "obl/rec.h"
#include "obl/primitives.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <ctime>
#include <chrono>

#define P 22
#define N (1 << P)
#define bench_size (1 << 17)
#define RUN 4

using hres = std::chrono::high_resolution_clock;
using _nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, _nano>;

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

	buffer value, value_out;
	tt start, end;
	_nano duration;
	uint32_t rnd_bid;

	obl::taostore_factory_v1 of(3, 8, 4);

	obl::recursive_oram* rram;
	rram = new obl::recursive_taoram(N, sizeof(buffer), 5, &of);

	mirror_data.reserve(N);

	for (unsigned int i = 0; i < N; i++)
	{
		obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

		rram->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);
		mirror_data[i] = value;
	}

	cerr << "finished init" << endl;
	for (int i = 0; i < RUN; i++)
	{
		start = hres::now();
		for (int j = 0; j < bench_size; j++)
		{
			obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
			rnd_bid = (rnd_bid >> 1) % N;
			rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
			assert(value_out == mirror_data[rnd_bid]);
		}

		cerr << "Run " << i << " finished" << endl;
		end = hres::now();
		duration = end - start;
		std::cout << "printf: " << duration.count() / 1000000000.0 << "s" << std::endl;
	}

	return 0;
}
