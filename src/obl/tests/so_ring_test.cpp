#include "obl/so_ring.h"
#include "obl/primitives.h"

#include <iostream>
#include <cassert>
#include <cstdint>
#include <vector>

#define P 0
#define N (1 << P)
#define RUN 10

#define Z 4
#define A 3
#define S 6
#define STASH 32

using namespace std;

int main()
{
	vector<obl::leaf_id> position_map;
	vector<int64_t> mirror_data;

	obl::so_ring_oram rram(N, sizeof(int64_t), Z, S, A, STASH);
	int64_t value, value_out;

	position_map.reserve(N);
	mirror_data.reserve(N);

	for(unsigned int i = 0; i < N; i++)
	{
		obl::leaf_id next_leef;
		obl::gen_rand((std::uint8_t*) &next_leef, sizeof(obl::leaf_id));

		obl::gen_rand((std::uint8_t*) &value, sizeof(int64_t));

		rram.write(i, (std::uint8_t*) &value, next_leef);
		mirror_data[i] = value;
		position_map[i] = next_leef;
	}

	cerr << "finished init" << endl;

	for(int i = 0; i < RUN; i++)
		for(int j = 0; j < N; j++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t*) &next_leef, sizeof(obl::leaf_id));
			std::int64_t value_upd = mirror_data[j] + 1;

			//rram.access(j, position_map[j], (std::uint8_t*) &value_upd, (std::uint8_t*) &value_out, next_leef);
			rram.access_r(j, position_map[j], (std::uint8_t*) &value_out);
			rram.access_w(j, position_map[j], (std::uint8_t*) &value_upd, next_leef);
			assert(value_out == mirror_data[j]);
			
			++mirror_data[j];
			position_map[j] = next_leef;
		}

	return 0;
}
