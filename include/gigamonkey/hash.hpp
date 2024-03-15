// Copyright (c) 2019-2023 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"
#include <data/crypto/hash/hash.hpp>

namespace Gigamonkey {

    template<size_t size>
    using digest = crypto::hash::digest<size>;

    // because of a bug in bitcoind long ago, many bitcoin
    // applications expect hashes to be provided backwards.
    template<size_t size>
    string inline write_backwards_hex (const digest<size> &x) {
        return drop (encoding::hexidecimal::write (x), 2);
    }

    template <size_t size>
    writer &operator << (writer &w, const digest<size> &s);

    template <size_t size>
    reader &operator >> (reader &r, digest<size> &s);

    using digest128 = digest<16>;
    using digest160 = digest<20>;
    using digest224 = digest<28>;
    using digest256 = digest<32>;
    using digest320 = digest<40>;
    using digest384 = digest<48>;
    using digest448 = digest<56>;
    using digest512 = digest<64>;

    // supported hash functions.
    digest160 SHA1 (bytes_view);
    digest160 SHA1 (string_view);

    digest256 SHA2_256 (bytes_view);
    digest256 SHA2_256 (string_view);

    digest160 RIPEMD_160 (bytes_view);
    digest160 RIPEMD_160 (string_view);

    digest256 double_SHA2_256 (bytes_view b);
}
    
namespace Gigamonkey::Bitcoin {
    
    // bitcoin hash functions.
    digest160 inline Hash160 (bytes_view b) {
        return RIPEMD_160 (SHA2_256 (b));
    }

    digest256 inline Hash256 (bytes_view b) {
        return double_SHA2_256 (b);
    }

    digest160 Hash160 (string_view b);
    digest256 Hash256 (string_view b);
        
    digest160 inline address_hash (bytes_view b) {
        return Hash160 (b);
    }
        
    digest256 inline signature_hash (bytes_view b) {
        return Hash256 (b);
    }

    digest160 inline Hash160 (string_view b) {
        return Hash160 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }

    digest256 inline Hash256 (string_view b) {
        return Hash256 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }

}

namespace Gigamonkey {

    digest256 inline double_SHA2_256 (bytes_view b) {
        return SHA2_256 (SHA2_256 (b));
    }

    template <size_t size>
    writer inline &operator << (writer &w, const digest<size> &s) {
        return w << bytes_view (s);
    }

    template <size_t size>
    reader inline &operator >> (reader &r, digest<size> &s) {
        r.read (s.data (), size);
        return r;
    }

    digest160 inline SHA1 (string_view b) {
        return SHA1 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }

    digest256 inline SHA2_256 (string_view b) {
        return SHA2_256 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }

    digest160 inline RIPEMD_160 (string_view b) {
        return RIPEMD_160 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }

    digest160 inline RIPEMD_160 (bytes_view b) {
        return crypto::RIPEMD_160 (b);
    }

    digest256 inline SHA2_256 (bytes_view b) {
        return crypto::SHA2_256 (b);
    }

    digest160 inline SHA1 (bytes_view b) {
        return crypto::SHA1 (b);
    }
    
}

#endif
