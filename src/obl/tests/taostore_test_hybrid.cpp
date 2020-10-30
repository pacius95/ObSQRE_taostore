#include "obl/taostore.h"
#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"
#include "obl/circuit.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>

#define P 15
#define N (1 << P)

#define C 5
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

struct work_args
{
    obl::taostore_oram *rram;
    vector<buffer> *_mirror_data;
    int i;
};

void *work(void *T)
{
    std::clock_t start;
    double duration;
    start = std::clock();
    work_args args = *(work_args *)T;
    buffer value_out;
    for (int j = 0; j < N; j++)
    {
        args.rram->access(j % N, nullptr, (std::uint8_t *)&value_out);
        assert(value_out == (*args._mirror_data)[j % N]);
    }
    cerr << "Run " << args.i << " finished" << endl;
    duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
    std::cout << "printf: " << duration << '\n';
    return nullptr;
};

int main(int argc, char *argv[])
{
    int T_NUM = atoi(argv[1]);
    int RUN = atoi(argv[2]);
    vector<buffer> mirror_data;

    obl::taostore_oram rram(N, sizeof(buffer), Z, S, T_NUM);
    buffer value, value_out;
    std::clock_t start;
    double duration;
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

    start = std::clock();
    for (int j = 0; j < N; j++)
    {
        rram.access(j, nullptr, (std::uint8_t *)&value_out);
    }
    cerr << "Run serial finished" << endl;
    duration = (std::clock() - start) / (double)CLOCKS_PER_SEC;
    std::cout << "printf: " << duration << '\n';

    return 0;
};
