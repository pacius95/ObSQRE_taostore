#include "obl/circuit.h"
#include "obl/taostore_circuit_1.h"
#include "obl/taostore_circuit_2.h"
#include "obl/taostore_circuit_1_p.h"
#include "obl/taostore_circuit_2_p.h"
#include "obl/shadow_mose.h"
#include "obl/taostore_factory.hpp"
#include "obl/path.h"
#include "obl/rec.h"
#include "obl/rec_standard.h"
#include "obl/rec_parallel.h"
#include "obl/primitives.h"
#include "obl/mose.h"
#include "unistd.h"
#include <math.h>

#include <stdio.h>
#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>
#include <ctime>
#include <chrono>

#define P 17
#define N (1 << P)
#define bench_size (1 << 18)
#define RUN 16

using hres = std::chrono::high_resolution_clock;
using _nano = std::chrono::nanoseconds;
using tt = std::chrono::time_point<hres, _nano>;

using namespace std;
struct buffer
{
    std::uint8_t _buffer[24000];

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
    int64_t *res_time;
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
    int64_t *res = ((work_args *)T)->res_time;
    buffer value_out;
    tt start, end;
    _nano duration;
    int run = args.run;
    unsigned int rnd_bid;

    for (int j = 0; j < bench_size / run; j++)
    {
        obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
        rnd_bid = (rnd_bid >> 1) % N;

        start = hres::now();
        args.rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
        end = hres::now();
        duration = end - start;
        // assert(value_out == (*args._mirror_data)[rnd_bid]);
        (args.res_time)[j] = duration.count();
    }
    return nullptr;
}

void *parallel_test(std::string oname, obl::recursive_oram *rram)
{

    vector<buffer> mirror_data;
    tt start, end;
    _nano duration;
    int64_t res_time = 0;
    buffer value, value_out;
    unsigned int rnd_bid;
    mirror_data.reserve(N);

    work_args args[RUN];
    pthread_t workers[RUN];
    int64_t *response_times[RUN];
    int64_t avg_res_times[RUN];

    int64_t tmp;
    int64_t temp;
    int64_t _25th;
    int64_t _75th;
    float mean;
    float var;
    float dev;
    for (unsigned int i = 0; i < RUN; i++)
    {
        args[i] = {rram, &mirror_data, RUN, i, response_times[i]};
        pthread_create(&workers[i], nullptr, work_write, (void *)&args[i]);
    }

    for (unsigned int i = 0; i < RUN; i++)
        pthread_join(workers[i], nullptr);


    for (unsigned int i = 0; i < RUN; i++)
    {
        response_times[i] = new int64_t[bench_size / RUN];
        args[i] = {rram, &mirror_data, RUN, i, response_times[i]};
        pthread_create(&workers[i], nullptr, work, (void *)&args[i]);
    }

    for (unsigned int i = 0; i < RUN; i++)
        pthread_join(workers[i], nullptr);

    for (unsigned int T = 1; T <= RUN; T *= 2)
    {
        res_time = 0;
        for (unsigned int i = 0; i < 2000; i++)
        {
            obl::gen_rand((std::uint8_t *)&rnd_bid, sizeof(obl::block_id));
            rnd_bid = (rnd_bid >> 1) % N;
            rram->access(rnd_bid, nullptr, (std::uint8_t *)&value_out);
        }

    usleep(1000000);

    start = hres::now();
    for (unsigned int i = 0; i < T; i++)
    {
        response_times[i] = new int64_t[bench_size / T];
        args[i] = {rram, &mirror_data, T, i, response_times[i]};
        pthread_create(&workers[i], nullptr, work, (void *)&args[i]);
    }

    for (unsigned int i = 0; i < T; i++)
        pthread_join(workers[i], nullptr);

        end = hres::now();
        duration = end - start;

        for (unsigned int i = 0; i < T; i++)
        {
            for (int b = 0; b < bench_size / T; b++)
            {
                for (int j = b + 1; j < bench_size / T; j++)
                {
                    if (response_times[i][b] > response_times[i][j])
                    {
                        temp = response_times[i][b];
                        response_times[i][b] = response_times[i][j];
                        response_times[i][j] = temp;
                    }
                }
            }
        }

        mean = 0;
        for (unsigned int i = 0; i < T; i++)
        {
            for (unsigned int j = 0; j < bench_size / T; j++)
                mean += response_times[i][j];
        }
        mean = mean / bench_size;

        var = 0;
        for (unsigned int i = 0; i < T; i++)
        {
            for (unsigned int j = 0; j < bench_size / T; j++)
                var += (response_times[i][j] - mean) * (response_times[i][j] - mean);
        }
        var = var / bench_size;
        dev = sqrt(var);
        _25th = 0;
        _75th = 0;
        for (unsigned int i = 0; i < T; i++)
        {
            _25th += response_times[i][(bench_size / T) / 4];
            _75th += response_times[i][3 * (bench_size / T) / 4];
        }
        _25th = _25th / T;
        _75th = _75th / T;
        for (unsigned int i = 0; i < T; i++)
        {
            delete response_times[i];
        }
        std::cout << oname << "," << N << "," << sizeof(buffer) << "," << T << "," << bench_size << "," << duration.count() << "," << (int64_t)mean << "," << (int64_t)var << "," << (int64_t)dev << "," << _25th << "," << _75th << std::endl;
    }
    return 0;
}

int main()
{

    obl::recursive_oram_standard *rram;
    obl::recursive_parallel *pram;
    obl::shadow_mose *sram;
    // {
    // 	obl::coram_factory of(3, 8);
    // 	rram = new obl::recursive_oram_standard(N, sizeof(buffer), 6, &of);
    // 	parallel_test("rec_circuit", rram);

    // 	delete rram;
    // }

    // {
    // 	obl::path_factory of(4, 32, 3);
    // 	rram = new obl::recursive_oram_standard(N, sizeof(buffer), 5, &of);
    // 	parallel_test("path_4_3", rram);
    // 	delete rram;
    // }

    // {
    //     obl::taostore_circuit_factory of(3, 8, 28);
    //     rram = new obl::recursive_oram_standard(N, sizeof(buffer), 6, &of);
    //     parallel_test("rec_taostore_asynch", rram);
    //     delete rram;
    // }
    // {
    //     obl::taostore_circuit_1_parallel_factory of(3, 8, 5);
    //     pram = new obl::recursive_parallel(N, sizeof(buffer), 6, &of);
    //     parallel_test("rec_taostore_circuit_1_parallel", pram);
    //     delete pram;
    // }
    // {
    //     obl::taostore_circuit_2_parallel_factory of(3, 8, 16);
    //     pram = new obl::recursive_parallel(N, sizeof(buffer), 6, &of);
    //     parallel_test("rec_taostore_circuit_2_parallel", pram);
    //     delete pram;
    // }
    // {
    //     obl::mose_factory of(3, 8, 5);
    //     rram = new obl::recursive_oram_standard(N, sizeof(buffer), 5, &of);
    //     parallel_test("rec_mose", rram);
    //     delete rram;
    // }
    // {
    //     obl::shadow_mose_factory of(3, 8, 12, 2);
    //     sram = new obl::shadow_mose(N, sizeof(buffer), 6, &of);
    //     parallel_test("shadow_mose", sram);
    //     delete sram;
    // }
    {
        obl::asynch_mose_factory of (3, 8, 32);
        rram = new obl::recursive_oram_standard(N, sizeof(buffer), 6, &of);
        parallel_test("AsynchMOSE", rram);
        delete rram;
    }
}
