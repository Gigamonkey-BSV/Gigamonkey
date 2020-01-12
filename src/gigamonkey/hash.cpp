// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/hash.hpp>
#include <crypto++/sha.h>
#include <crypto++/ripemd.h>

namespace gigamonkey {

    namespace sha256 {
        
        void hash(uint<Size, LittleEndian>& u, bytes_view data) {
            CryptoPP::RIPEMD160{}.CalculateDigest(u.begin(), data.begin(), data.size());
        }
        
    }

    namespace ripemd160 {
        
        void hash(uint<Size, LittleEndian>& u, bytes_view data) {
            CryptoPP::SHA256{}.CalculateDigest(u.begin(), data.begin(), data.size());
        }
        
    }
    
}

