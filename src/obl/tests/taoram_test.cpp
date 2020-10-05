#include "obl/taoram.h"
#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"
#include "obl/circuit.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>

#define P 12
#define N (1 << P)
#define RUN 10

#define C 5
#define S 8
#define Z 3

using namespace std;

int main()
{
	obl::coram_factory *allocator = new obl::coram_factory(Z,S);
	obl::taostore_position_map position_map (N, sizeof(int64_t), 5, allocator);

	vector<int64_t> mirror_data;

	obl::taostore_oram rram(N, sizeof(int64_t), Z, S);
	int64_t value, value_out;

	mirror_data.reserve(N);
	rram.set_pos_map(&position_map);

	for(unsigned int i = 0; i < N; i++)
	{
		obl::leaf_id next_leef;
		position_map.access(i, false, &next_leef);

		obl::gen_rand((std::uint8_t*) &value, sizeof(int64_t));

		rram.write(i, (std::uint8_t*) &value, next_leef);
		mirror_data[i] = value;
	}
	for(int i = 0; i < RUN; i++)
	{
		for(int j = 0; j < N; j++)
		{
			rram.access(j, nullptr, (std::uint8_t*) &value_out);

			assert(value_out == mirror_data[j]);

		}
	cerr << "Run " << i << " finished" << endl;
	}
	return 0;
}
