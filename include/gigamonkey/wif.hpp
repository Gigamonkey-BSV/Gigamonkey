// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WIF
#define GIGAMONKEY_WIF

#include "secp256k1.hpp"

namespace gigamonkey::bitcoin {
    
    struct wif {
        char Prefix;
        secret Secret;
        bool Compressed;
        
        constexpr static char MainNet = 0x80; 
        
        constexpr static char TestNet = 0xef;
        
        constexpr static char CompressedSuffix = 0x01;
        
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
        constexpr static size_t CompressedSize{38};
        constexpr static size_t UncompressedSize{37};
        
    private:
        wif() : Prefix{0}, Secret{}, Compressed{false} {}
        
    public:
        wif(char p, secret s, bool c = true) : Prefix{p}, Secret{s}, Compressed{c} {}
        
        static wif read(const string& s);
        
        wif(const string& s) : wif{read(s)} {}
        
        static string write(char, const secret&, bool compressed = true);
        
        string write() const {
            return write(Prefix, Secret, Compressed);
        }
        
    };
    
}

#endif

