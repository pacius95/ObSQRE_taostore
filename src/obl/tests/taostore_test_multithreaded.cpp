#include "obl/taostore.h"
#include "obl/primitives.h"
#include "obl/taostore_pos_map.h"
#include "obl/circuit.h"

#include <iostream>
#include <cstdint>
#include <vector>
#include <cassert>

#define P 16
#define N (1 << P)
#define RUN 4

#define C 5
#define S 8
#define Z 3

using namespace std;

struct work_args {
    obl::taostore_oram *rram;
    vector<int64_t>* _mirror_data;
    int i;
};

void *work(void* T)
{
    work_args args = *(work_args*) T;
    for (int j = 0; j < N; j++)
    {    
        int64_t value_out;
        args.rram->access(j, nullptr, (std::uint8_t *)&value_out);

        assert(value_out == (*args._mirror_data)[j]);
    }
    cerr << "Run " << args.i << " finished" << endl;
    return nullptr;
};

int main()
{

    vector<int64_t> mirror_data;

    obl::taostore_oram rram(N, sizeof(int64_t), Z, S);
    int64_t value, value_out;
    std::clock_t start;
    double duration;
    mirror_data.reserve(N);

    pthread_t workers[RUN];

    for (unsigned int i = 0; i < N; i++)
    {
		obl::gen_rand((std::uint8_t*) &value, sizeof(int64_t));

		rram.access(i, (std::uint8_t*) &value, (std::uint8_t*) &value_out);
		mirror_data[i] = value;
    }

	cerr << "finished init" << endl;

    work_args args[RUN];

	start = std::clock();
    for (int i = 0; i < RUN; i++)
    {
        args[i] = {&rram, &mirror_data,i};
        pthread_create(&workers[i], nullptr, work, (void*)&args[i]);
    }

    for (int i = 0; i < RUN; i++)
    {
        pthread_join(workers[i], nullptr);
    }
    duration = ( std::clock() - start ) / (double) CLOCKS_PER_SEC;
    std::cout<<"printf: "<< duration <<'\n';
    return 0;
};



