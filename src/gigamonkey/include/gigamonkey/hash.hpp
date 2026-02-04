// Copyright (c) 2019-2023 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"
#include <data/crypto/hash.hpp>

namespace Gigamonkey {
    namespace crypto = data::crypto;

    // digests are little endian numbers. That's a Bitcoin thing.
    // Therefore if you write them out as numbers they are byte
    // reversed from how they really are.
    template <size_t s> struct digest : public uint<s> {
        using uint<s>::uint;
        digest (const uint<s> &u) : uint<s> {u} {}
        bool valid () const;
    };

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
    digest160 SHA1 (byte_slice);
    digest160 SHA1 (string_view);

    digest256 SHA2_256 (byte_slice);
    digest256 SHA2_256 (string_view);

    digest160 RIPEMD_160 (byte_slice);
    digest160 RIPEMD_160 (string_view);

    digest256 double_SHA2_256 (byte_slice b);

    // Use this for any other hash function (see data::crypto::hash)
    template <data::hash::Engine e> digest<e::DigestSize> hash (byte_slice b);
    template <data::hash::Engine e> digest<e::DigestSize> hash (string_view b);
}
    
namespace Gigamonkey::Bitcoin {
    
    // bitcoin hash functions.
    digest160 inline Hash160 (byte_slice b) {
        return RIPEMD_160 (SHA2_256 (b));
    }

    digest256 inline Hash256 (byte_slice b) {
        return double_SHA2_256 (b);
    }

    digest160 Hash160 (string_view b);
    digest256 Hash256 (string_view b);
        
    digest160 inline address_hash (byte_slice b) {
        return Hash160 (b);
    }
        
    digest256 inline signature_hash (byte_slice b) {
        return Hash256 (b);
    }

    digest160 inline Hash160 (string_view b) {
        return Hash160 (byte_slice {(const byte*) (b.data ()), b.size ()});
    }

    digest256 inline Hash256 (string_view b) {
        return Hash256 (byte_slice {(const byte*) (b.data ()), b.size ()});
    }

}

// Hash writers for large documents that you don't want to actually
// write out completely before hashing them. You can write the
// document to the hash writer incrementally and the hash will be
// calculated as we go along.
namespace Gigamonkey {

    // given an engine, construct a writer.
    template <data::hash::Engine engine> struct hash_writer : data::writer<byte> {
        using digest = Gigamonkey::digest<engine::DigestSize>;
        hash_writer (digest &d) noexcept: Digest {d}, Hash {} {}

        void write (const byte *b, size_t bytes) noexcept final override {
            Hash.Update (b, bytes);
        }

        ~hash_writer () {
            Hash.Final (Digest.data ());
        }

        // non copyable
        hash_writer (const hash_writer &) = delete;
        hash_writer &operator = (const hash_writer &) = delete;
        hash_writer (hash_writer &&) = delete;
        hash_writer &operator = (hash_writer &&) = delete;

    private:
        digest &Digest;
        engine Hash;
    };

    using SHA1_writer = hash_writer<crypto::hash::SHA1>;
    using SHA2_256_writer = hash_writer<crypto::hash::SHA2<32>>;
    using RIPEMD_160_writer = hash_writer<crypto::hash::RIPEMD<20>>;
}

namespace Gigamonkey::Bitcoin {
    using Hash160_writer = hash_writer<crypto::hash::Bitcoin<20>>;
    using Hash256_writer = hash_writer<crypto::hash::Bitcoin<32>>;
}

namespace Gigamonkey {

    template <data::hash::Engine e> digest<e::DigestSize> inline hash (byte_slice b) {
        digest<e::DigestSize> d;
        hash_writer<e> {d}.write (b.data (), b.size ());
        return d;
    }

    template <data::hash::Engine e> digest<e::DigestSize> inline hash (string_view b) {
        digest<e::DigestSize> d;
        hash_writer<e> {d}.write ((const byte *) b.data (), b.size ());
        return d;
    }

    digest256 inline double_SHA2_256 (byte_slice b) {
        digest256 d;
        Bitcoin::Hash256_writer {d}.write (b.data (), b.size ());
        return d;
    }

    digest160 inline RIPEMD_160 (byte_slice b) {
        digest160 d;
        RIPEMD_160_writer {d}.write (b.data (), b.size ());
        return d;
    }

    digest256 inline SHA2_256 (byte_slice b) {
        digest256 d;
        SHA2_256_writer {d}.write (b.data (), b.size ());
        return d;
    }

    digest160 inline SHA1 (byte_slice b) {
        digest160 d;
        SHA1_writer {d}.write (b.data (), b.size ());
        return d;
    }

    digest160 inline SHA1 (string_view b) {
        digest160 d;
        SHA1_writer {d}.write ((const byte*) (b.data ()), b.size ());
        return d;
    }

    digest256 inline SHA2_256 (string_view b) {
        digest256 d;
        SHA2_256_writer {d}.write ((const byte*) (b.data ()), b.size ());
        return d;
    }

    digest160 inline RIPEMD_160 (string_view b) {
        digest160 d;
        RIPEMD_160_writer {d}.write ((const byte*) (b.data ()), b.size ());
        return d;
    }

    template<size_t s>
    bool inline digest<s>::valid () const {
        return *this != digest {0};
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
    
}

#endif
