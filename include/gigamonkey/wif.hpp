// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WIF
#define GIGAMONKEY_WIF

#include "secp256k1.hpp"
#include "address.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct wif {
        byte Prefix;
        secret Secret;
        bool Compressed;
        
        constexpr static byte MainNet = 0x80; 
        
        constexpr static byte TestNet = 0xef;
        
        constexpr static byte CompressedSuffix = 0x01;
        
        size_t size() const {
            return 33 + (Compressed ? 1 : 0); 
        }
        
        bool valid() const {
            return Secret.valid() && (Prefix == MainNet || Prefix == TestNet);
        }
        
        // why is wif compressed bigger than wif uncompressed? 
        // because compressed keys were invented after uncompressed keys. 
        // A compressed wif code is denoted with an extra character to
        // distinguish it from an uncompressed wif code. 
        constexpr static size_t CompressedSize{34};
        constexpr static size_t UncompressedSize{33};
        
    private:
        wif() : Prefix{0}, Secret{}, Compressed{false} {}
        
    public:
        wif(byte p, secret s, bool c = true) : Prefix{p}, Secret{s}, Compressed{c} {}
        
        static wif read(string_view s);
        
        wif(string_view s) : wif{read(s)} {}
        
        static string write(byte, const secret&, bool compressed = true);
        
        string write() const {
            return write(Prefix, Secret, Compressed);
        }
        
        bool operator==(const wif& w) const {
            return Prefix == w.Prefix && Secret == w.Secret && Compressed == w.Compressed;
        }
        
        bool operator!=(const wif& w) const {
            return !operator==(w);
        }
        
        pubkey to_public() const {
            if (Compressed) return Secret.to_public().compress();
            return Secret.to_public().decompress();
        }
        
        Bitcoin::address address() const {
            return {to_public().address(), Prefix};
        }
        
    };
    
}

#endif

