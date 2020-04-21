
#include <random.h>
#include <gigamonkey/schema/random.hpp>

namespace Gigamonkey::Bitcoin {
    
    secret random_keysource::get() {
        static bool initialized = false;
        if (!initialized) {
            void RandomInit();
            initialized = true;
        }
        secret x;
        do {
            GetStrongRandBytes(x.Secret.Value.data(), 32);
        } while (!x.valid());
        return x;
    } 

}
        
