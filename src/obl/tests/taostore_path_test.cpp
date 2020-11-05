#include "obl/taostore_path.h"
#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"
#include "obl/circuit.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <ctime>

#define P 15
#define N (1 << P)
#define RUN 1

#define S 32
#define Z 4
#define A 3

using namespace std;

struct buffer
{
	std::uint8_t _buffer[1000];
	bool operator==(const buffer &rhs) const
	{
		return !memcmp(_buffer, rhs._buffer, sizeof(_buffer));
	}
};

int main()
{
	vector<buffer> mirror_data;

	obl::taostore_path_oram rram(N, sizeof(buffer), Z, S, A, 4);
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
		for (int j = 0; j < N; j++)
		{
			rram.access(j, nullptr, (std::uint8_t *)&value_out);
		}
		cerr << "Run " << i << " finished" << endl;
		duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
		std::cerr << "printf: " << duration << '\n';
	}
	return 0;
}