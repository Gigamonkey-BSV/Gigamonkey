
#include <sv/random.h>
#include <gigamonkey/schema/random.hpp>

namespace Gigamonkey {
    
    void bitcoind_random::get(byte* x, size_t size) {
        static bool initialized = false;
        if (!initialized) {
            void RandomInit();
            initialized = true;
        }
        
        GetStrongRandBytes(x, size);
    } 

}
        
