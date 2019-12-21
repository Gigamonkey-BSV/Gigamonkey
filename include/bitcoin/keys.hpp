// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_KEYS
#define GIGAMONKEY_KEYS

#include "secp256k1.hpp"
#include "signature.hpp"

namespace gigamonkey::bitcoin {
    
    struct secret {
        secp256k1::secret Value;
        
        secret() : Value{} {}
        secret(const secp256k1::secret& v) : Value{v} {}
        explicit secret(const string&);
        
        bool valid() const {
            return secp256k1::valid(Value);
        }
        
        signature sign(bytes_view message) const {
            return bitcoin::sign(Value, signature_hash(message), Value);
        }
        
        secret operator-() const {
            return secp256k1::negate(Value);
        }
        
        secret operator+(const secret& s) const {
            return secp256k1::plus(Value, s.Value);
        }
        
        secret operator*(const secret& s) const {
            return secp256k1::times(Value, s.Value);
        }
    };
    
    struct pubkey {
        secp256k1::pubkey_compressed Value;
        
        pubkey() : Value{} {}
        pubkey(const secp256k1::pubkey_compressed& p) : Value{p} {}
        explicit pubkey(const string&);
        
        bool valid() const {
            return secp256k1::valid(Value);
        }
        
        pubkey operator-() const {
            return secp256k1::negate(Value);
        }
        
        pubkey operator+(const pubkey& p) const {
            return secp256k1::plus(Value, p.Value);
        }
        
        pubkey operator*(const secret& s) const {
            return secp256k1::times(Value, s.Value);
        }
    };
    
    struct pubkey_u {
        secp256k1::pubkey_uncompressed Value;
        
        pubkey_u() : Value{} {}
        pubkey_u(const secp256k1::pubkey_uncompressed& p) : Value{p} {}
        explicit pubkey_u(const string&);
        
        bool valid() const {
            return secp256k1::valid(Value);
        }
        
        pubkey_u operator-() const {
            return secp256k1::negate(Value);
        }
        
        pubkey_u operator+(const pubkey& p) const {
            return secp256k1::plus(Value, p.Value);
        }
        
        pubkey_u operator*(const secret& s) const {
            return secp256k1::times(Value, s.Value);
        }
    };
}

inline std::ostream& operator<<(std::ostream& o, const gigamonkey::bitcoin::secret& s) {
    return o << "secret{" << s.Value << "}";
}

inline std::ostream& operator<<(std::ostream& o, const gigamonkey::bitcoin::pubkey& p) {
    return o << "pubkey{" << p.Value << "}";
}

inline std::ostream& operator<<(std::ostream& o, const gigamonkey::bitcoin::pubkey_u& p) {
    return o << "pubkey{" << p.Value << "}";
}

#endif

