// Copyright (c) 2019-2023 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"
#include <data/crypto/hash/hash.hpp>

namespace Gigamonkey {
    namespace crypto = data::crypto;

    template <size_t size>
    using digest = crypto::digest<size>;

    // because of a bug in bitcoind long ago, many bitcoin
    // applications expect hashes to be provided backwards.
    template <size_t size>
    string inline write_reverse_hex (const digest<size> &x) {
        return data::drop (encoding::hexidecimal::write (x), 2);
    }

    template <size_t size>
    digest<size> inline read_reverse_hex (const std::string &x) {
        return digest<size> {std::string {"0x"} + x};
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
    digest160 SHA1 (slice<const byte>);
    digest160 SHA1 (string_view);

    digest256 SHA2_256 (slice<const byte>);
    digest256 SHA2_256 (string_view);

    digest160 RIPEMD_160 (slice<const byte>);
    digest160 RIPEMD_160 (string_view);

    digest256 double_SHA2_256 (slice<const byte> b);
}
    
namespace Gigamonkey::Bitcoin {
    
    // bitcoin hash functions.
    digest160 inline Hash160 (slice<const byte> b) {
        return crypto::RIPEMD_160 (SHA2_256 (b));
    }

    digest256 inline Hash256 (slice<const byte> b) {
        return double_SHA2_256 (b);
    }

    digest160 Hash160 (string_view b);
    digest256 Hash256 (string_view b);
        
    digest160 inline address_hash (slice<const byte> b) {
        return Hash160 (b);
    }
        
    digest256 inline signature_hash (slice<const byte> b) {
        return Hash256 (b);
    }

    digest160 inline Hash160 (string_view b) {
        return Hash160 (slice<const byte> {(const byte*) (b.data ()), b.size ()});
    }

    digest256 inline Hash256 (string_view b) {
        return Hash256 (slice<const byte> {(const byte*) (b.data ()), b.size ()});
    }

}

// Hash writers for large documents that you don't want to actually
// write out completely before hashing them. You can write the
// document to the hash writer incrementally and the hash will be
// calculated as we go along.
namespace Gigamonkey {
    using SHA_2_256_writer = crypto::hash::SHA2<32>;
    using RIPEMD_160_writer = crypto::hash::RIPEMD<20>;
}

namespace Gigamonkey::Bitcoin {
    using Hash160_writer = crypto::hash::Bitcoin<20>;
    using Hash256_writer = crypto::hash::Bitcoin<32>;
}

namespace Gigamonkey {

    digest256 inline double_SHA2_256 (slice<const byte> b) {
        return crypto::SHA2_256 (SHA2_256 (b));
    }

    template <size_t size>
    writer inline &operator << (writer &w, const digest<size> &s) {
        return w << slice<const byte> (s);
    }

    template <size_t size>
    reader inline &operator >> (reader &r, digest<size> &s) {
        r.read (s.data (), size);
        return r;
    }

    digest160 inline SHA1 (string_view b) {
        return SHA1 (slice<const byte> {(const byte*) (b.data ()), b.size ()});
    }

    digest256 inline SHA2_256 (string_view b) {
        return SHA2_256 (slice<const byte> {(const byte*) (b.data ()), b.size ()});
    }

    digest160 inline RIPEMD_160 (string_view b) {
        return RIPEMD_160 (slice<const byte> {(const byte*) (b.data ()), b.size ()});
    }

    digest160 inline RIPEMD_160 (slice<const byte> b) {
        return crypto::RIPEMD_160 (b);
    }

    digest256 inline SHA2_256 (slice<const byte> b) {
        return crypto::SHA2_256 (b);
    }

    digest160 inline SHA1 (slice<const byte> b) {
        return crypto::SHA1 (b);
    }
    
}

#endif
