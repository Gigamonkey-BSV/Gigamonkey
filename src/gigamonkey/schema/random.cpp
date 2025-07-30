
#include <sv/random.h>
#include <gigamonkey/schema/random.hpp>

namespace Gigamonkey {
    
    void bitcoind_entropy::read (byte* x, size_t size) {
        static bool initialized = false;
        if (!initialized) {
            void RandomInit ();
            initialized = true;
        }

        byte *bytes_ptr = x;
        size_t bytes_to_write = size;
        while (32 - Position > bytes_to_write) {
            std::copy (Data.data () + Position, Data.data () + 32, bytes_ptr);
            bytes_ptr += (32 - Position);
            bytes_to_write -= (32 - Position);

            Satoshi::GetStrongRandBytes (Data.data (), 32);
            Position = 0;
        }

        std::copy (Data.data (), Data.data () + bytes_to_write, bytes_ptr);
        Position += bytes_to_write;
        
    } 

}
        
