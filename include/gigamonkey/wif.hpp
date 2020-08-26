// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WIF
#define GIGAMONKEY_WIF

#include "signature.hpp"
#include "address.hpp"
#include <gigamonkey/ecies/electrum.hpp>

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
        
        size_t size() const;
        
        bool valid() const;
        
        // why is wif compressed bigger than wif uncompressed? 
        // because compressed keys were invented after uncompressed keys. 
        // A compressed wif code is denoted with an extra character to
        // distinguish it from an uncompressed wif code. 
        constexpr static size_t CompressedSize{34};
        constexpr static size_t UncompressedSize{33};
        
        secret();
        secret(type p, secp256k1::secret s, bool c = true);
        
        static secret read(string_view s);
        
        secret(string_view s);
        
        static string write(byte, const secp256k1::secret&, bool compressed = true);
        
        string write() const;
        
        bool operator==(const secret& w) const;
        
        bool operator!=(const secret& w) const;
        
        pubkey to_public() const;
        
        Bitcoin::address address() const;
        
        signature sign(const digest256& d) const;
        
        signature sign(const input_index& tx, sighash::directive d) const;
        
        bytes encrypt(const bytes& message) const;
        bytes decrypt(const bytes& message) const;
        
    private:
        static Bitcoin::address::type to_address_type(type t);
    };
        
    inline size_t secret::size() const {
        return 33 + (Compressed ? 1 : 0); 
    }
    
    inline bool secret::valid() const {
        return Secret.valid() && (Prefix == main || Prefix == test);
    }
    
    inline secret::secret() : Prefix{0}, Secret{}, Compressed{false} {}
    
    inline Bitcoin::address::type secret::to_address_type(secret::type t) {
        return t == main ? Bitcoin::address::main : Bitcoin::address::test;
    }
    
    inline secret::secret(type p, secp256k1::secret s, bool c) : Prefix{p}, Secret{s}, Compressed{c} {}
    
    inline secret::secret(string_view s) : secret{read(s)} {}
        
    inline string secret::write() const {
        return write(Prefix, Secret, Compressed);
    }
    
    inline bool secret::operator==(const secret& w) const {
        return Prefix == w.Prefix && Secret == w.Secret && Compressed == w.Compressed;
    }
    
    inline bool secret::operator!=(const secret& w) const {
        return !operator==(w);
    }
    
    inline pubkey secret::to_public() const {
        if (Compressed) return Secret.to_public().compress();
        return Secret.to_public().decompress();
    }
    
    inline Bitcoin::address secret::address() const {
        return {to_address_type(Prefix), to_public()};
    }
    
    inline signature secret::sign(const digest256& d) const {
        return Bitcoin::sign(d, Secret);
    }
    
    inline signature secret::sign(const input_index& tx, sighash::directive d) const {
        return Bitcoin::sign(tx, d, Secret);
    }
        
    inline bytes secret::encrypt(const bytes& message) const {
        return ECIES::electrum::encrypt(message, to_public());
    }
    
    inline bytes secret::decrypt(const bytes& message) const {
        return ECIES::electrum::decrypt(message, Secret);
    }
    
}

#endif

