// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_KEYSOURCE
#define GIGAMONKEY_SCHEMA_KEYSOURCE

#include <gigamonkey/wif.hpp>

namespace Gigamonkey {
    
    struct key_source {
        virtual Bitcoin::secret next () = 0;
        virtual ~key_source () {}
    };
    
    struct address_source {
        virtual Bitcoin::address next () = 0;
        virtual ~address_source () {}
    };

    struct key_database : key_source {
        virtual Bitcoin::secret operator [] (const Bitcoin::address &);
        virtual ~key_database () {}
    };
    
    // a key source containing a single key. 
    struct single_key_source final : key_source {
        Bitcoin::secret Key;
        
        explicit single_key_source (const Bitcoin::secret &k) : Key {k} {}
        
        Bitcoin::secret next () override {
            return Key;
        }
        
        Bitcoin::secret first () const {
            return Key;
        }
        
        single_key_source rest () const {
            return single_key_source {Key};
        }
        
    };
    
    // a key source containing a single key. 
    struct single_address_source final : address_source {
        Bitcoin::address Address;
        
        explicit single_address_source (const Bitcoin::address &addr) : Address {addr} {}
        
        Bitcoin::address next () override {
            return Address;
        }
        
        Bitcoin::address first () const {
            return Address;
        }
        
        single_address_source rest () const {
            return single_address_source {Address};
        }
        
    };
    
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

    struct map_key_database final : key_database {
        ptr<key_source> Keys;
        uint32 MaxLookAhead;

        map<Bitcoin::address, Bitcoin::secret> Past;
        list<Bitcoin::secret> Next;

        explicit map_key_database (ptr<key_source> keys, uint32 max_look_ahead = 0) :
            Keys {keys}, MaxLookAhead {max_look_ahead}, Past {}, Next {} {}

        Bitcoin::secret next () override {
            if (data::size (Next) != 0) {
                auto n = data::first (Next);
                Next = data::rest (Next);
                return n;
            }

            Bitcoin::secret n = Keys->next ();
            Bitcoin::address a = n.address ();

            if (!Past.contains (a)) Past = Past.insert (a, n);

            return n;
        }

        Bitcoin::secret operator [] (const Bitcoin::address &addr) override {
            auto x = Past.contains (addr);
            if (x) return *x;

            while (data::size (Next) < MaxLookAhead) {

                Bitcoin::secret n = Keys->next ();
                Bitcoin::address a = n.address ();

                Next = Next.append (n);

                if (!Past.contains (a)) {
                    Past = Past.insert (a, n);
                }
            }
        }

    };
}

#endif
