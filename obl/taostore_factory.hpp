#ifndef TAOSTORE_FACTORY
#define TAOSTORE_FACTORY

#include "obl/oram.h"
#include "obl/taostore_circuit_1.h"
#include "obl/taostore_circuit_2.h"
#include "obl/circuit.h"
#include <iostream>

namespace obl
{
    class taostore_circuit_factory : public oram_factory
    {
    private:
        unsigned int Z, S, T_NUM;

    public:
        taostore_circuit_factory(unsigned int Z, unsigned int S, unsigned int T_NUM)
        {
            this->Z = Z;
            this->S = S;
            this->T_NUM = T_NUM;
        }

        tree_oram *spawn_oram(std::size_t N, std::size_t B)
        {
            if (N < (1 << 10))
            {
                return new taostore_circuit_1(N, B, Z, S, 1);
            }
            else
            {
                if (B <= (1 << 5))
                {
                    if (T_NUM >= 2)
                    {
                        T_NUM = T_NUM - 2;
                        return new taostore_circuit_1(N, B, Z, S, 3);
                    }
                    else
                    {
                        int tmp = T_NUM;
                        T_NUM = 0;
                        return new taostore_circuit_1(N, B, Z, S, tmp + 1);
                    }
                }
                if (B > (1 << 5) && B < (1 << 10))
                {
                    if (N < (1 << 20)) //e maggiore di 1<<10
                    {
                        if (T_NUM >= 2)
                        {
                            T_NUM = T_NUM - 2;
                            return new taostore_circuit_1(N, B, Z, S, 3);
                        }
                        else
                        {
                            int tmp = T_NUM;
                            T_NUM = 0;
                            return new taostore_circuit_1(N, B, Z, S, tmp + 1);
                        }
                    }
                    else
                    {
                        if (T_NUM >= 3)
                        {
                            T_NUM = T_NUM - 3;
                            return new taostore_circuit_1(N, B, Z, S, 4);
                        }
                        else
                        {
                            int tmp = T_NUM;
                            T_NUM = 0;
                            return new taostore_circuit_1(N, B, Z, S, tmp + 1);
                        }
                    }
                }
                if (B >= (1 << 10) && B < (1 << 11))
                {
                    if (N < (1 << 15)) // e maggiore di 10
                    {
                        if (T_NUM >= 2)
                        {
                            T_NUM = T_NUM - 2;
                            return new taostore_circuit_1(N, B, Z, S, 3);
                        }
                        else
                        {
                            int tmp = T_NUM;
                            T_NUM = 0;
                            return new taostore_circuit_1(N, B, Z, S, tmp + 1);
                        }
                    }
                    else
                    {
                        if (T_NUM >= 5)
                        {
                            T_NUM = T_NUM - 5;
                            return new taostore_circuit_2(N, B, Z, S, 6);
                        }
                        else
                        {
                            int tmp = T_NUM;
                            T_NUM = 0;
                            return new taostore_circuit_2(N, B, Z, S, tmp + 1);
                        }
                    }
                }
                if (B >= (1 << 11))
                {
                    if (T_NUM >= 5)
                    {
                        T_NUM = T_NUM - 5;
                        return new taostore_circuit_2(N, B, Z, S, 6);
                    }
                    else
                    {
                        int tmp = T_NUM;
                        T_NUM = 0;
                        return new taostore_circuit_2(N, B, Z, S, tmp + 1);
                    }
                }
            }
        }

        bool is_taostore() { return true; }
    };
} // namespace obl

#endif