// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_KEYSOURCE
#define GIGAMONKEY_SCHEMA_KEYSOURCE

#include <gigamonkey/wif.hpp>

namespace Gigamonkey {
    
    struct key_source {
        virtual Bitcoin::secret next() = 0;
        virtual ~key_source() {}
    };
    
    struct address_source {
        virtual Bitcoin::address next() = 0;
        virtual ~address_source() {}
    };
    
    // a key source containing a single key. 
    struct single_key_source final : key_source {
        Bitcoin::secret Key;
        
        explicit single_key_source(const Bitcoin::secret &k) : Key{k} {}
        
        Bitcoin::secret next() override {
            return Key;
        }
        
        Bitcoin::secret first() const {
            return Key;
        }
        
        single_key_source rest() const {
            return single_key_source{Key};
        }
        
    };
    
    // a key source containing a single key. 
    struct single_address_source final : address_source {
        Bitcoin::address Address;
        
        explicit single_address_source(const Bitcoin::address &addr) : Address{addr} {}    
        
        Bitcoin::address next() override {
            return Address;
        }
        
        Bitcoin::address first() const {
            return Address;
        }
        
        single_address_source rest() const {
            return single_address_source{Address};
        }
        
    };
    
    // a key source that increments the key. 
    struct increment_key_source final : key_source {
        Bitcoin::secret Key;
        
        explicit increment_key_source(const Bitcoin::secret& k) : Key{k} {}
        
        Bitcoin::secret next() override {
            auto k = Key;
            Key.Secret = Key.Secret + secp256k1::secret{uint256{1}};
            return k;
        }
        
        Bitcoin::secret first() const {
            return Key;
        }
        
        increment_key_source rest() const {
            auto g = *this;
            g.next();
            return g;
        }
    };
}

#endif
