
#include <gigamonkey/schema/random.hpp>
#include <sv/random.h>

namespace Gigamonkey {
    
    void bitcoind_random::get(byte* x, size_t size) {
        static bool initialized = false;
        if (!initialized) {
            void RandomInit();
            initialized = true;
        }
        
        bsv::GetStrongRandBytes(x, size);
    } 

}
        
