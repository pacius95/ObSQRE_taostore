#ifndef OBL_REC_POSITION_MAP_NOTOBL_H
#define OBL_REC_POSITION_MAP_NOTOBL_H

#include "obl/oram.h"
#include <pthread.h>
#include <vector>

namespace obl
{

    class taostore_position_map_notobl
    {
    private:
        std::size_t N;
        pthread_mutex_t map_mutex = PTHREAD_MUTEX_INITIALIZER;
        std::vector<leaf_id> position_map;

    public:
        taostore_position_map_notobl(std::size_t N);
        ~taostore_position_map_notobl();

        leaf_id access(block_id bid, bool fake, leaf_id *_ev_leef);
    };

} // namespace obl

#endif // OBL_REC_POSITION_MAP_NOToBL_H
