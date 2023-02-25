// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_KEYSOURCE
#define GIGAMONKEY_SCHEMA_KEYSOURCE

#include <gigamonkey/wif.hpp>

namespace Gigamonkey {

    // for wallets we need types that provide series of addresses or keys or whatever.
    template <typename X>
    struct source {
        virtual X next () = 0;
        virtual ~source () {}
    };

    using key_source = source<Bitcoin::secret>;
    using address_source = source<Bitcoin::address::decoded>;
    
    // a source containing a single item.
    template <typename X>
    struct single_source final : source<X> {
        X It;
        
        explicit single_source (const X &k) : It {k} {}
        
        X next () override {
            return It;
        }
        
        X first () const {
            return It;
        }
        
        single_source rest () const {
            return single_source {It};
        }
        
    };

    using single_key_source = single_source<Bitcoin::secret>;
    using single_address_source = single_source<Bitcoin::address::decoded>;
    
    // a key source that increments the key. 
    struct increment_key_source final : key_source {
        Bitcoin::secret Key;
        
        explicit increment_key_source (const Bitcoin::secret& k) : Key {k} {}
        
        Bitcoin::secret next () override {
            auto k = Key;
            Key.Secret = Key.Secret + secp256k1::secret {uint256 {1}};
            return k;
        }
        
        Bitcoin::secret first () const {
            return Key;
        }
        
        increment_key_source rest () const {
            auto g = *this;
            g.next ();
            return g;
        }
    };

}

#endif
