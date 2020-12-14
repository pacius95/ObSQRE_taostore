#include <iostream>
#include <chrono>
#include <vector>
#include <cstdint>
#include <cassert>
#include <iomanip>

#include "obl/taostore.h"
#include "obl/taostore_path.h"
#include "obl/taostore_v2.h"
#include "obl/taostore_v1.h"
#include "obl/circuit.h"
#include "obl/path.h"

#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"

#define C 5
#define S 8
#define Z 3

using hres = std::chrono::high_resolution_clock;
using nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, nano>;

const int pow_lower = 18;
const int pow_upper = 28;
const int bench_size = 1 << 18;
const int RUN = 8;
struct buffer
{
	std::uint8_t _buffer[8];
	bool operator==(const buffer &rhs) const
	{
		return !memcmp(_buffer, rhs._buffer, sizeof(_buffer));
	}
};
struct work_args
{
	obl::taostore_oram *rram;
	std::vector<buffer> *_mirror_data;
};

void *work(void *T)
{
	work_args args = *(work_args *)T;
	buffer value_out;
	std::size_t N = args.rram->get_N();
	unsigned int rnd_bid;

	for (int j = 0; j < bench_size / RUN; j++)
	{
		obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
		rnd_bid = (rnd_bid >> 1) % N;
		args.rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
		assert(value_out == (*args._mirror_data)[rnd_bid]);
	}
	return nullptr;
}

void oram_test(std::string oname, obl::tree_oram *oram)
{	tt start, end;
	nano duration;
	unsigned int rnd_bid;
	std::vector<buffer> mirror_data;
	std::vector<obl::leaf_id> position_map;
	buffer value, value_out;

	std::size_t N = oram->get_N();
	mirror_data.reserve(N);
	position_map.reserve(N);

		std::cout << "start " << oname <<": " << N << std::endl;
		for (unsigned int i = 0; i < N; i++)
		{
			obl::leaf_id next_leef;
			obl::gen_rand((std::uint8_t *)&next_leef, sizeof(obl::leaf_id));
			obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

			oram->write(i, (std::uint8_t *)&value, next_leef);
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
			oram->access(rnd_bid, position_map[rnd_bid], nullptr, (std::uint8_t *)&value_out, next_leef);
			position_map[rnd_bid] = next_leef;

			assert(value_out == mirror_data[rnd_bid]);
		}
		end = hres::now();
		duration = end - start;
		std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
}

void serial_test(std::string oname, int T_NUM, obl::taostore_oram *rram)
{
	tt start, end;
	nano duration;
	unsigned int rnd_bid;
	std::vector<buffer> mirror_data;
	buffer value, value_out;

	std::size_t N = rram->get_N();
	mirror_data.reserve(N);

	std::cout << "start " << oname << " serial with N:" << N << " T_NUM:" << T_NUM << std::endl;

	for (unsigned int i = 0; i < N; i++)
	{
		obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
		rram->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

		mirror_data[i] = value;
	}

	start = hres::now();
	for (int j = 0; j < bench_size; j++)
	{
		obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
		rnd_bid = (rnd_bid >> 1) % N;

		rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
		assert(value_out == mirror_data[rnd_bid]);
	}
	end = hres::now();
	duration = end - start;
	std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
}

void parallel_test(std::string oname, int T_NUM, int RUN, obl::taostore_oram *rram)
{
	tt start, end;
	nano duration;
	unsigned int rnd_bid;
	std::vector<buffer> mirror_data;
	buffer value, value_out;
	pthread_t workers[RUN];
	work_args args[RUN];

	std::size_t N = rram->get_N();
	mirror_data.reserve(N);

	std::cout << "start " << oname << " parallel with N:" << N << " T_NUM:" << T_NUM << " RUN: " << RUN << std::endl;

	for (unsigned int i = 0; i < N; i++)
	{
		obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));
		rram->access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);

		mirror_data[i] = value;
	}

	start = hres::now();
	for (int i = 0; i < RUN; i++)
	{
		args[i] = {rram, &mirror_data};
		pthread_create(&workers[i], nullptr, work, (void *)&args[i]);
	}

	for (int i = 0; i < RUN; i++)
		pthread_join(workers[i], nullptr);

	end = hres::now();
	duration = end - start;
	std::cout << "tempo: " << duration.count() / 1000000000.0 << "s" << std::endl;
}

int main()
{
	std::cout << std::setprecision(4);
	obl::taostore_oram *rram;
	obl::tree_oram *oram;

	std::cout << "benchmarc block size:" << sizeof(buffer) << " bench size: " << bench_size << std::endl;
	for (int p = pow_lower; p < pow_upper; p++)
	{
		std::size_t N = 1 << p;

		oram = new obl::circuit_oram(N, sizeof(buffer), 3, 8);
		oram_test("circuit", oram);
		delete oram;

		oram = new obl::path_oram(N, sizeof(buffer), 4, 32, 3);
		oram_test("path_4_3", oram);
		delete oram;
		
		// oram = new obl::path_oram(N, sizeof(buffer), 8, 41, 8);
		// oram_test("path_8_8", oram);
		// delete oram;

		for (int T_NUM = 1; T_NUM < 9; T_NUM++)
		{
			rram = new obl::taostore_oram_v1(N, sizeof(buffer), Z, S, T_NUM);
			serial_test("taostore_v1", T_NUM, rram);
			rram->wait_end();
			delete rram;

			rram = new obl::taostore_oram_v2(N, sizeof(buffer), Z, S, T_NUM);
			serial_test("taostore_v2", T_NUM, rram);
			rram->wait_end();
			delete rram;

			// rram = new obl::taostore_path_oram(N, sizeof(buffer), 4, 32, 3, T_NUM);
			// serial_test("taostore_path_4_3", T_NUM, rram);
			// delete rram;

			// rram = new obl::taostore_path_oram(N, sizeof(buffer), 8, 41, 8, T_NUM);
			// serial_test("taostore_path_8_8", T_NUM, rram);
			// delete rram;

			rram = new obl::taostore_oram_v1(N, sizeof(buffer), Z, S, T_NUM);
			parallel_test("taostore_v1", T_NUM, RUN, rram);
			rram->wait_end();
			delete rram;
			rram = new obl::taostore_oram_v2(N, sizeof(buffer), Z, S, T_NUM);
			parallel_test("taostore_v2", T_NUM, RUN, rram);
			rram->wait_end();
			delete rram;

			// rram = new obl::taostore_path_oram(N, sizeof(buffer), 4, 32, 3, T_NUM);
			// parallel_test("taostore_path_4_3", T_NUM, RUN, rram);
			// delete rram;

			// rram = new obl::taostore_path_oram(N, sizeof(buffer), 8, 41, 8, T_NUM);
			// parallel_test("taostore_path_8_8", T_NUM, RUN, rram);
			// delete rram;
		}
	}
}