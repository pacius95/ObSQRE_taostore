#include "obl/ring.h"
#include "obl/circuit.h"
#include "obl/path.h"
#include "obl/rec.h"
#include "obl/primitives.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <ctime>

#define P 15
#define N (1 << P)
#define RUN 4

using namespace std;
struct buffer {
	std::uint8_t buffer[8];
};
int main()
{
	vector<buffer> mirror_data;

	buffer value, value_out;
	std::clock_t start;
	double duration;

	//obl::path_factory of(4, 48);
	obl::coram_factory of(3, 8);
	obl::recursive_oram rram(N, sizeof(buffer), 5, &of);

	mirror_data.reserve(N);

	for (unsigned int i = 0; i < N; i++)
	{
		obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

		rram.access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);
		mirror_data[i] = value;
	}

	cerr << "finished init" << endl;
	for (int i = 0; i < RUN; i++)
	{
		start = std::clock();
		for (int j = 0; j < N; j++)
		{
			rram.access(j, nullptr, (std::uint8_t *)&value_out);

//			assert(value_out == mirror_data[j]);
		}

		cerr << "Run " << i << " finished" << endl;
		duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
		std::cout << "printf: " << duration << '\n';
	}

	return 0;
}
