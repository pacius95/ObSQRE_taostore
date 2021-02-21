#include "obl/circuit.h"
#include "obl/taostore_circuit_1.h"
#include "obl/taostore_circuit_2.h"
#include "obl/taostore_circuit_1_p.h"
#include "obl/taostore_circuit_2_p.h"
#include "obl/taostore_factory.hpp"
#include "obl/path.h"
#include "obl/rec.h"
#include "obl/rec_standard.h"
#include "obl/rec_parallel.h"
#include "obl/primitives.h"
#include "obl/mose.h"

#include <stdio.h>
#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <ctime>
#include <chrono>

#define P 20
#define N (1 << P)
#define bench_size (1 << 18)
#define RUN 8

using hres = std::chrono::high_resolution_clock;
using _nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, _nano>;

using namespace std;
struct buffer
{
	std::uint8_t _buffer[4000];

	bool operator==(const buffer &rhs) const
	{
		return !memcmp(_buffer, rhs._buffer, sizeof(_buffer));
	}
};
struct work_args
{
	obl::recursive_oram *rram;
	std::vector<buffer> *_mirror_data;
	unsigned int run;
	unsigned int i;
};

void *work_write(void *T)
{
	work_args args = *(work_args *)T;
	buffer value, value_out;
	int i = args.i;
	int run = args.run;

	for (int j = i; j < N; j += run)
	{
		obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

		args.rram->access(j, (std::uint8_t *)&value, (std::uint8_t *)&value_out);
		(*args._mirror_data)[j] = value;
	}
	return nullptr;
}
void *work(void *T)
{
	work_args args = *(work_args *)T;
	buffer value_out;
	int run = args.run;
	unsigned int rnd_bid;

	for (int j = 0; j < bench_size / run; j++)
	{
		obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
		rnd_bid = (rnd_bid >> 1) % N;
		args.rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
		assert(value_out == (*args._mirror_data)[rnd_bid]);
	}
	return nullptr;
}

void *parallel_test(std::string oname, unsigned int T_NUM, obl::recursive_oram *rram)
{

	vector<buffer> mirror_data;
	tt start, end;
	_nano duration;
	mirror_data.reserve(N);

	work_args args[RUN];
	pthread_t workers[RUN];
	unsigned int T = T_NUM;
	if (T_NUM >= RUN)
		T_NUM = RUN;

	for (unsigned int i = 0; i < T_NUM; i++)
	{
		args[i] = {rram, &mirror_data, T_NUM, i};
		pthread_create(&workers[i], nullptr, work_write, (void *)&args[i]);
	}

	for (unsigned int i = 0; i < T_NUM; i++)
		pthread_join(workers[i], nullptr);

	start = hres::now();
	for (unsigned int i = 0; i < T_NUM; i++)
	{
		args[i] = {rram, &mirror_data, T_NUM, i};
		pthread_create(&workers[i], nullptr, work, (void *)&args[i]);
	}

	for (unsigned int i = 0; i < T_NUM; i++)
		pthread_join(workers[i], nullptr);

	end = hres::now();
	duration = end - start;
	std::cout << oname << "," << N << "," << sizeof(buffer) << "," << T << "," << bench_size << "," << duration.count() << std::endl;
	return 0;
}

int main()
{
	//PARALLEL TEST
	obl::recursive_oram_standard *rram;
	obl::recursive_parallel *pram;
	for (unsigned int T_NUM = 9; T_NUM <= 8; T_NUM++)
	{
		obl::coram_factory of(3, 8);
		rram = new obl::recursive_oram_standard(N, sizeof(buffer), 6, &of);
		parallel_test("rec_circuit", T_NUM, rram);

		delete rram;
	}
	for (unsigned int T_NUM = 9; T_NUM <= 8; T_NUM++)
	{
		obl::path_factory of(4, 32, 3);
		rram = new obl::recursive_oram_standard(N, sizeof(buffer), 6, &of);
		parallel_test("path_4_3", T_NUM, rram);
		delete rram;
	}
	for (unsigned int T_NUM = 34; T_NUM <= 30; T_NUM++)
	{
		obl::taostore_circuit_factory of(3, 8, T_NUM - 3);
		rram = new obl::recursive_oram_standard(N, sizeof(buffer), 6, &of);
		parallel_test("rec_taostore_asynch", T_NUM, rram);
		delete rram;
	}
	 for (unsigned int T_NUM = 9; T_NUM <= 8; T_NUM++)
	 {
	 	obl::taostore_circuit_1_parallel_factory of(3, 8, T_NUM);
	 	pram = new obl::recursive_parallel(N, sizeof(buffer), &of);
	 	parallel_test("rec_taostore_circuit_1_parallel", T_NUM, pram);
	 	delete pram;
	 }
	 for (unsigned int T_NUM = 18; T_NUM <= 16; T_NUM++)
	 {
	 	obl::taostore_circuit_1_parallel_factory of(3, T_NUM, T_NUM);
	 	pram = new obl::recursive_parallel(N, sizeof(buffer), &of);
	 	parallel_test("rec_taostore_circuit_1_parallel", T_NUM, pram);
		delete pram;
	 }
	 for (unsigned int T_NUM = 9; T_NUM <= 8; T_NUM++)
	 {
	 	obl::taostore_circuit_2_parallel_factory of(3, 8, T_NUM);
	 	pram = new obl::recursive_parallel(N, sizeof(buffer), &of);
	 	parallel_test("rec_taostore_circuit_2_parallel", T_NUM, pram);
	 	delete pram;
	 }
	 for (unsigned int T_NUM = 18; T_NUM <= 16; T_NUM++)
	 {
	 	obl::taostore_circuit_2_parallel_factory of(3, T_NUM, T_NUM);
	 	pram = new obl::recursive_parallel(N, sizeof(buffer), &of);
	 	parallel_test("rec_taostore_circuit_2_parallel", T_NUM, pram);
	 	delete pram;
	 }
	 for (unsigned int T_NUM = 13; T_NUM <= 32; T_NUM++)
	 {
	 	obl::mose_factory of(3, 8, T_NUM);
	 	rram = new obl::recursive_oram_standard(N, sizeof(buffer), 5, &of);
	 	parallel_test("rec_mose", T_NUM, rram);
	 	delete rram;
	 }
}

// {
// 	vector<buffer> mirror_data;

// 	buffer value, value_out;
// 	tt start, end;
// 	_nano duration;
// 	uint32_t rnd_bid;
// 	mirror_data.reserve(N);

// 	for (unsigned int i = 0; i < N; i++)
// 	{
// 		obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

// 		rram.access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);
// 		mirror_data[i] = value;
// 	}
// 	cerr << "finished init" << endl;
// 	for (int i = 0; i < RUN; i++)
// 	{
// 		start = hres::now();
// 		for (int j = 0; j < bench_size; j++)
// 		{
// 			obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
// 			rnd_bid = (rnd_bid >> 1) % N;
// 			rram.access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
// 			assert(value_out == mirror_data[rnd_bid]);
// 		}

// 		cerr << "Run " << i << " finished" << endl;
// 		end = hres::now();
// 		duration = end - start;
// 		std::cout << "printf: " << duration.count() / 1000000000.0 << "s" << std::endl;
// 	}
// }
