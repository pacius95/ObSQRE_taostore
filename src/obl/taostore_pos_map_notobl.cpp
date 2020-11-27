#include "obl/taostore_pos_map_notobl.h"
#include "obl/primitives.h"

#define DUMMY_LEAF -1

namespace obl
{
    constexpr leaf_id sign_bit = (1ULL << (sizeof(leaf_id) * 8 - 1)) - 1;

    // this is to avoid generating randomly a -1!
    inline leaf_id leaf_abs(leaf_id x)
    {
        return x & sign_bit;
    }

    taostore_position_map_notobl::taostore_position_map_notobl(std::size_t N)
    {
        this->N = N;
        position_map.reserve(N);
        for (unsigned int i = 0; i < N; i++)
            position_map[i] = DUMMY_LEAF;
    }
    taostore_position_map_notobl::~taostore_position_map_notobl() {
        pthread_mutex_destroy(&map_mutex);
        position_map.clear();
    }

    leaf_id taostore_position_map_notobl::access(block_id bid, bool fake, leaf_id *_ev_leef)
    {
        leaf_id leef;
        leaf_id d_leef;

        gen_rand((std::uint8_t *)_ev_leef, sizeof(leaf_id));
        gen_rand((std::uint8_t *)&d_leef, sizeof(leaf_id));
        *_ev_leef = leaf_abs(*_ev_leef);
        d_leef = leaf_abs(d_leef);
        pthread_mutex_lock(&map_mutex);
        leef = position_map[bid];

        leef = ternary_op(leef == DUMMY_LEAF, d_leef, leef);
        *_ev_leef = ternary_op(fake, leef, *_ev_leef);

        position_map[bid] = *_ev_leef;
        pthread_mutex_unlock(&map_mutex);

        return leef;
    }
} // namespace obl
