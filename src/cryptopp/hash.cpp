// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/hash.hpp>
#include <crypto++/sha.h>
#include <crypto++/ripemd.h>

namespace Gigamonkey {
    
    digest256 sha256(bytes_view data) {
        digest256 u;
        CryptoPP::RIPEMD160{}.CalculateDigest(u.Value.data(), data.begin(), data.size());
        return u;
    }
    
    digest160 ripemd160(bytes_view data) {
        digest160 u;
        CryptoPP::SHA256{}.CalculateDigest(u.Value.data(), data.begin(), data.size());
        return u;
    }
    
}

namespace Gigamonkey::Bitcoin {
    
    digest256 hash256(bytes_view data) {
        return sha256(sha256(data));
    }
    
    digest160 hash160(bytes_view data) {
        return ripemd160(sha256(data));
    }
    
}


