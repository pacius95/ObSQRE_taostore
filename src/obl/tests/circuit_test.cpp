#include "obl/circuit.h"
#include "obl/primitives.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <ctime>

#define P 18
#define N (1 << P)
#define RUN 1

#define S 8
#define Z 3

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
	vector<obl::leaf_id> position_map;
	vector<buffer> mirror_data;

	obl::circuit_oram rram(N, sizeof(buffer), Z, S);
	buffer value, value_out;
	position_map.reserve(N);
	mirror_data.reserve(N);
	std::clock_t start;
	double duration;

	for (unsigned int i = 0; i < N; i++)
	{
		obl::leaf_id next_leef;
		obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));

		obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

		rram.write(i, (std::uint8_t *)&value, next_leef);
		mirror_data[i] = value;
		position_map[i] = next_leef;
	}

	cerr << "finished init" << endl;

	for (int i = 0; i < RUN; i++)
	{
		start = std::clock();
		for (int j = 0; j < N; j++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));

			rram.access(j, position_map[j], nullptr, (std::uint8_t *)&value_out, next_leef);
			position_map[j] = next_leef;

			assert(value_out == mirror_data[j]);
		}
		cerr << "Run " << i << " finished" << endl;
		duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
		std::cerr << "printf: " << duration << '\n';
	}

	return 0;
}
