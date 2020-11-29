#include "obl/taostore_path.h"
#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"
#include "obl/circuit.h"

#include <chrono>
#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <iomanip>

#define P 20
#define N (1 << P)
#define bench_size (1 << 15)
#define RUN 4

using hres = std::chrono::high_resolution_clock;
using _nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, _nano>;

#define A 3
#define S 32
#define Z 4

using namespace std;

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
    obl::taostore_path_oram *rram;
    vector<buffer> *_mirror_data;
    int i;
};

void *work(void *T)
{
    tt start, end;
    _nano duration;
    work_args args = *(work_args *)T;
    buffer value_out;
    unsigned int rnd_bid;

    start = hres::now();
    for (int j = 0; j < bench_size; j++)
    {
        obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
        rnd_bid = (rnd_bid >> 1) % N;

        args.rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
        assert(value_out == (*args._mirror_data)[rnd_bid]);
    }
    end = hres::now();
    duration = end - start;
    cerr << "Run " << args.i << " finished" << endl;
    std::cout << "printf: " << duration.count() / 1000000000.0 << "s" << std::endl;
    return nullptr;
};

int main()
{

    vector<buffer> mirror_data;

    obl::taostore_path_oram rram(N, sizeof(buffer), Z, S, A, 4);
    buffer value, value_out;

    mirror_data.reserve(N);

    pthread_t workers[RUN];

    for (unsigned int i = 0; i < N; i++)
    {
        obl::gen_rand((std::uint8_t *)&value, sizeof(buffer));

        rram.access(i, (std::uint8_t *)&value, (std::uint8_t *)&value_out);
        mirror_data[i] = value;
    }

    cerr << "finished init" << endl;

    work_args args[RUN];

    for (int i = 0; i < RUN; i++)
    {
        args[i] = {&rram, &mirror_data, i};
        pthread_create(&workers[i], nullptr, work, (void *)&args[i]);
    }

    for (int i = 0; i < RUN; i++)
    {
        pthread_join(workers[i], nullptr);
    }
    return 0;
};
