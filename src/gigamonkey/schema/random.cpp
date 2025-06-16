
#include <sv/random.h>
#include <gigamonkey/schema/random.hpp>

namespace Gigamonkey {
    
    void bitcoind_entropy::read (byte* x, size_t size) {
        static bool initialized = false;
        if (!initialized) {
            void RandomInit ();
            initialized = true;
        }
        
        Satoshi::GetStrongRandBytes (x, size);
    } 

}
        
