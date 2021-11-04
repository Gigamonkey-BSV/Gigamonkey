// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_KEYSOURCE
#define GIGAMONKEY_SCHEMA_KEYSOURCE

#include <gigamonkey/wif.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct keysource {
        virtual secret first() const = 0;
        virtual ptr<keysource> rest() const = 0;
        virtual ~keysource() {}
    };
    
    // a key source containing a single key. 
    struct single_key final : keysource {
        secret Key;
        
        explicit single_key(const secret& k) : Key{k} {}
        
        secret first() const {
            return Key;
        }
        
        ptr<keysource> rest() const {
            return std::make_shared<single_key>(Key);
        }
    };
    
    // a key source that increments the key. 
    struct increment_key final : keysource {
        secret Key;
        
        explicit increment_key(const secret& k) : Key{k} {}
        
        secret first() const override {
            return Key;
        }
        
        ptr<keysource> rest() const override {
            ptr<increment_key> k = std::make_shared<increment_key>(Key);
            k->Key.Secret = k->Key.Secret + secp256k1::secret{uint256{1}};
            return k;
        }
    };
}

#endif
