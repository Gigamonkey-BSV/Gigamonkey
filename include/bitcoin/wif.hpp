// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_WIF
#define BITCOIN_WIF

#include "keys.hpp"

namespace gigamonkey::bitcoin {
    
    struct wif {
        char Prefix;
        secret Secret;
        bool Compressed;
        
        constexpr static char main_net() {
            static const char MainNet = 0x80;
            return MainNet;
        }
        
        constexpr static char test_net() {
            static const char TestNet = 0xef;
            return TestNet;
        }
        
        constexpr static char compressed_suffix() {
            static const char CompressedSuffix = 0x01;
            return CompressedSuffix;
        }
        
        size_t size() const {
            return 33 + (Compressed ? 1 : 0); 
        }
        
        bool valid() const {
            return Secret.valid() && (Prefix == main_net() || Prefix == test_net());
        }
        
        // why is wif compressed bigger than wif uncompressed? 
        // because compressed keys were invented after uncompressed keys. 
        // A compressed wif code is denoted with an extra character to
        // distinguish it from an uncompressed wif code. 
        const size_t wif_compressed_size{38};
        const size_t wif_uncompressed_size{37};

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

