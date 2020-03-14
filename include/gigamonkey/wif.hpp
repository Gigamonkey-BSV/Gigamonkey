// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WIF
#define GIGAMONKEY_WIF

#include "secp256k1.hpp"
#include "address.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct secret {
        
        enum type : byte {
            main = 0x80, 
            test = 0xef
        };
        
        type Prefix;
        secp256k1::secret Secret;
        bool Compressed;
        
        constexpr static byte CompressedSuffix = 0x01;
        
        size_t size() const {
            return 33 + (Compressed ? 1 : 0); 
        }
        
        bool valid() const {
            return Secret.valid() && (Prefix == main || Prefix == test);
        }
        
        // why is wif compressed bigger than wif uncompressed? 
        // because compressed keys were invented after uncompressed keys. 
        // A compressed wif code is denoted with an extra character to
        // distinguish it from an uncompressed wif code. 
        constexpr static size_t CompressedSize{34};
        constexpr static size_t UncompressedSize{33};
        
    private:
        secret() : Prefix{0}, Secret{}, Compressed{false} {}
        
        static Bitcoin::address::type to_address_type(type t) {
            return t == main ? Bitcoin::address::main : Bitcoin::address::test;
        }
        
    public:
        secret(type p, secp256k1::secret s, bool c = true) : Prefix{p}, Secret{s}, Compressed{c} {}
        
        static secret read(string_view s);
        
        secret(string_view s) : secret{read(s)} {}
        
        static string write(byte, const secp256k1::secret&, bool compressed = true);
        
        string write() const {
            return write(Prefix, Secret, Compressed);
        }
        
        bool operator==(const secret& w) const {
            return Prefix == w.Prefix && Secret == w.Secret && Compressed == w.Compressed;
        }
        
        bool operator!=(const secret& w) const {
            return !operator==(w);
        }
        
        pubkey to_public() const {
            if (Compressed) return Secret.to_public().compress();
            return Secret.to_public().decompress();
        }
        
        Bitcoin::address address() const {
            return {to_address_type(Prefix), to_public()};
        }
        
    };
    
}

#endif

