// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "number.hpp"

namespace Gigamonkey {

    // a hash digest. 
    template <size_t size> struct digest : nonzero<uint<size>> {
        
        digest () : nonzero<uint<size>> {} {}
        
        explicit digest (const uint<size>& u) : nonzero<uint<size>> {u} {}
        explicit digest (string_view s);
        explicit digest (const slice<size>& x) : digest {uint<size> (x)} {}
        
        operator bytes_view () const;
        
        explicit operator N () const;
        
        byte *begin ();
        byte *end ();
        
        const byte *begin () const;
        const byte *end () const;
        
        bool operator == (const digest& d) const;
        bool operator != (const digest& d) const;
        
        bool operator > (const digest& d) const;
        bool operator < (const digest& d) const;
        bool operator <= (const digest& d) const;
        bool operator >= (const digest& d) const;
    };
    
    using digest128 = digest<16>;
    using digest160 = digest<20>;
    using digest224 = digest<28>;
    using digest256 = digest<32>;
    using digest320 = digest<40>;
    using digest384 = digest<48>;
    using digest448 = digest<56>;
    using digest512 = digest<64>;

    template <size_t size> 
    inline std::ostream& operator << (std::ostream &o, const digest<size> &s) {
        return o << "digest{" << s.Value << "}";
    }

    template <size_t size> 
    inline writer &operator << (writer &w, const digest<size> &s) {
        return w << bytes_view (s.Value);
    }

    template <size_t size> 
    inline reader &operator >> (reader &r, digest<size> &s) {
        r.read(s.Value.data (), size);
        return r;
    }
    
    // supported hash functions.
    digest160 SHA1 (bytes_view);
    digest160 SHA1 (string_view);
    
    digest224 SHA2_224 (bytes_view);
    digest224 SHA2_224 (string_view);
    digest256 SHA2_256 (bytes_view);
    digest256 SHA2_256 (string_view);
    digest384 SHA2_384 (bytes_view);
    digest384 SHA2_384 (string_view);
    digest512 SHA2_512 (bytes_view);
    digest512 SHA2_512 (string_view);
    
    template <size_t size> digest<size> SHA3 (bytes_view);
    template <size_t size> digest<size> SHA3 (string_view);
    
    digest224 SHA3_224 (bytes_view);
    digest224 SHA3_224 (string_view);
    digest256 SHA3_256 (bytes_view);
    digest256 SHA3_256 (string_view);
    digest384 SHA3_384 (bytes_view);
    digest384 SHA3_384 (string_view);
    digest512 SHA3_512 (bytes_view);
    digest512 SHA3_512 (string_view);
    
    digest128 RIPEMD_128 (bytes_view);
    digest128 RIPEMD_128 (string_view);
    digest160 RIPEMD_160 (bytes_view);
    digest160 RIPEMD_160 (string_view);
    digest256 RIPEMD_256 (bytes_view);
    digest256 RIPEMD_256 (string_view);
    digest320 RIPEMD_320 (bytes_view);
    digest320 RIPEMD_320 (string_view);
    
    digest256 inline double_SHA2_256 (bytes_view b) {
        return SHA2_256 (SHA2_256 (b));
    }
    
    namespace Bitcoin {
    
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
    
    }
    
    template <size_t size>
    struct lazy_hash_writer : lazy_bytes_writer {
        digest<size> (*Hash) (bytes_view);
        lazy_hash_writer (digest<size> (*h) (bytes_view)) : Hash {h} {}
        digest<size> finalize () const {
            return Hash (this->operator bytes ());
        } 
    };
    
    digest160 inline SHA1 (string_view b) {
        return SHA1 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest224 inline SHA2_224 (string_view b) {
        return SHA2_224 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest256 inline SHA2_256 (string_view b) {
        return SHA2_256 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest384 inline SHA2_384 (string_view b) {
        return SHA2_384 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest512 inline SHA2_512 (string_view b) {
        return SHA2_512 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest224 inline SHA3_224 (string_view b) {
        return SHA3_224 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest256 inline SHA3_256 (string_view b) {
        return SHA3_256 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest384 inline SHA3_384 (string_view b) {
        return SHA3_384 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest512 inline SHA3_512 (string_view b) {
        return SHA3_512 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest128 inline RIPEMD_128 (string_view b) {
        return RIPEMD_128 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest160 inline RIPEMD_160 (string_view b) {
        return RIPEMD_160 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest256 inline RIPEMD_256 (string_view b) {
        return RIPEMD_256 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    digest320 inline RIPEMD_320 (string_view b) {
        return RIPEMD_320 (bytes_view {(const byte*) (b.data ()), b.size ()});
    }
    
    namespace Bitcoin {
        
        digest160 inline Hash160 (string_view b) {
            return Hash160 (bytes_view {(const byte*) (b.data ()), b.size ()});
        }
        
        digest256 inline Hash256 (string_view b) {
            return Hash256 (bytes_view {(const byte*) (b.data ()), b.size ()});
        }
    
    }
}

#include "cryptopp/cryptlib.h"
#include "cryptopp/iterhash.h"

namespace Gigamonkey {

    namespace bitcoind {
        template <class hash, size_t size = hash::OUTPUT_SIZE> 
        struct hash_writer : writer {
            
            hash Hash;
            
            hash_writer () : Hash {} {}
            
            digest<size> finalize () {
                digest<size> d;
                Hash.Finalize (d.Value.data ());
                Hash.Reset ();
                return d;
            }
            
            digest<size> operator () (bytes_view b) {
                digest<size> d;
                Hash.Write (b.data (), b.size ()).Finalize (d.Value.data ());
                return d;
            }
        
            void write (const byte* b, size_t x) override {
                Hash.Write (b, x);
            }
            
        };
        
    }
    
    namespace CryptoPP {
        using namespace ::CryptoPP;
    
        template <class transform, size_t size> 
        struct hash_writer : writer {
            
            transform Hash;
            
            hash_writer () : Hash {} {}
            
            digest<size> finalize () {
                digest<size> d;
                Hash.Final (d.Value.data ());
                Hash.Restart ();
                return d;
            }
            
            digest<size> operator () (bytes_view b) {
                digest<size> d;
                Hash.CalculateDigest (d.Value.data (), b.data (), b.size ());
                return d;
            }
        
            void write (const byte* b, size_t x) override {
                Hash.Update (b, x);
            }
            
        };
    }
}

#include <sv/crypto/sha1.h>
#include <sv/crypto/ripemd160.h>
#include <sv/crypto/sha256.h>
#include <sv/crypto/sha512.h>
#include "cryptopp/ripemd.h"
#include "cryptopp/sha.h"
#include "cryptopp/sha3.h"

namespace Gigamonkey {
    
    using SHA1_writer = bitcoind::hash_writer<CSHA1>;
    
    using RIPEMD_128_writer = CryptoPP::hash_writer<CryptoPP::RIPEMD128, 16>;
    
    using RIPEMD_160_writer = bitcoind::hash_writer<CRIPEMD160>;
    
    using RIPEMD_256_writer = CryptoPP::hash_writer<CryptoPP::RIPEMD256, 32>;
    
    using RIPEMD_320_writer = CryptoPP::hash_writer<CryptoPP::RIPEMD320, 40>;
    
    using SHA2_224_writer = CryptoPP::hash_writer<CryptoPP::SHA224, 28>;
    
    using SHA2_256_writer = bitcoind::hash_writer<CSHA256>;
    
    using SHA2_384_writer = CryptoPP::hash_writer<CryptoPP::SHA384, 48>;
    
    using SHA2_512_writer = CryptoPP::hash_writer<CryptoPP::SHA512, 64>;
    
    template <size_t size> using SHA3_writer = CryptoPP::hash_writer<CryptoPP::SHA3_Final<size>, size>;
    
    using SHA3_224_writer = SHA3_writer<28>;
    
    using SHA3_256_writer = SHA3_writer<32>;
    
    using SHA3_384_writer = SHA3_writer<48>;
    
    using SHA3_512_writer = SHA3_writer<64>;
    
    digest160 inline SHA1 (bytes_view b) {
        return SHA1_writer {} (b);
    }
    
    digest224 inline SHA2_224 (bytes_view b) {
        return SHA2_224_writer {} (b);
    }
    
    digest256 inline SHA2_256 (bytes_view b) {
        return SHA2_256_writer {} (b);
    }
    
    digest384 inline SHA2_384 (bytes_view b) {
        return SHA2_384_writer {} (b);
    }
    
    digest512 inline SHA2_512 (bytes_view b) {
        return SHA2_512_writer {} (b);
    }
    
    digest224 inline SHA3_224 (bytes_view b) {
        return SHA3_224_writer {} (b);
    }
    
    digest256 inline SHA3_256 (bytes_view b) {
        return SHA3_256_writer {} (b);
    }
    
    digest384 inline SHA3_384 (bytes_view b) {
        return SHA3_384_writer {} (b);
    }
    
    digest512 inline SHA3_512 (bytes_view b) {
        return SHA3_512_writer {} (b);
    }
    
    digest128 inline RIPEMD_128 (bytes_view b) {
        return RIPEMD_128_writer {} (b);
    }
    
    digest160 inline RIPEMD_160 (bytes_view b) {
        return RIPEMD_160_writer {} (b);
    }
    
    digest256 inline RIPEMD_256 (bytes_view b) {
        return RIPEMD_256_writer {} (b);
    }
    
    digest320 inline RIPEMD_320 (bytes_view b) {
        return RIPEMD_320_writer {} (b);
    }
    
    namespace Bitcoin {
        
        struct Hash160_writer : SHA2_256_writer {
            
            digest160 finalize () {
                return RIPEMD_160 (SHA2_256_writer::finalize ());
            }
            
            digest160 operator () (bytes_view b) {
                return RIPEMD_160 (SHA2_256_writer::operator () (b));
            }
            
        };
        
        struct Hash256_writer : SHA2_256_writer {
            
            digest256 finalize () {
                return SHA2_256 (SHA2_256_writer::finalize ());
            }
            
            digest256 operator () (bytes_view b) {
                return SHA2_256 (SHA2_256_writer::operator () (b));
            }
            
        };
    }
    
}

namespace Gigamonkey {
    
    template <size_t size>
    digest<size>::digest (string_view s) {
        maybe<bytes> b = data::encoding::hex::read (s);
        if (bool (b)) std::copy (b->begin (), b->end (), begin ());
        else *this = digest {uint<size> {string (s)}};
    }
    
    template <size_t size>
    inline digest<size>::operator bytes_view () const {
        return bytes_view (nonzero<uint<size>>::Value);
    }
    
    template <size_t size>
    byte inline *digest<size>::begin () {
        return nonzero<uint<size>>::Value.begin ();
    }
    
    template <size_t size>
    byte inline *digest<size>::end () {
        return nonzero<uint<size>>::Value.end ();
    }
    
    template <size_t size>
    const byte inline *digest<size>::begin () const {
        return nonzero<uint<size>>::Value.begin ();
    }
    
    template <size_t size>
    const byte inline *digest<size>::end () const {
        return nonzero<uint<size>>::Value.end ();
    }
    
    template <size_t size>
    bool inline digest<size>::operator == (const digest& d) const {
        return nonzero<uint<size>>::Value == d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator != (const digest& d) const {
        return nonzero<uint<size>>::Value != d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator > (const digest& d) const {
        return nonzero<uint<size>>::Value > d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator < (const digest& d) const {
        return nonzero<uint<size>>::Value < d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator <= (const digest& d) const {
        return nonzero<uint<size>>::Value <= d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator >= (const digest& d) const {
        return nonzero<uint<size>>::Value >= d.Value;
    }

}

#endif
