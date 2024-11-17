// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_HD
#define GIGAMONKEY_SCHEMA_HD

#include <gigamonkey/wif.hpp>
#include "keysource.hpp"
#include <ostream>

// HD is a format for infinite sequences of keys that 
// can be derived from a single master. This key format
// will be depricated but needs to be supported for 
// older wallets. 
namespace Gigamonkey::HD {
    
    using chain_code = data::bytes;
    using seed = data::bytes;
    using entropy = data::bytes;
    
    // bip 32 defines the basic format. See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    namespace BIP_32 {

        enum type : byte {
            main = 0x78,
            test = 0x74
        };
        
        constexpr type inline from_wif (Bitcoin::secret::type t) {
            return t == Bitcoin::secret::main ? main : t == Bitcoin::secret::test ? test : type{0};
        }
        
        constexpr Bitcoin::secret::type inline to_wif (type t) {
            return t == main ? Bitcoin::secret::main : t == test ? Bitcoin::secret::test : Bitcoin::secret::type{0};
        }
        
        constexpr type inline from_address (Bitcoin::address::type t) {
            return t == Bitcoin::address::main ? main : t == Bitcoin::address::test ? test : type{0};
        }
        
        constexpr Bitcoin::address::type inline to_address (type t) {
            return t == main ? Bitcoin::address::main : t == test ? Bitcoin::address::test : Bitcoin::address::type{0};
        }
        
        constexpr bool inline hardened (uint32 child) {
            return child >= 0x80000000;
        }
        
        constexpr uint32 inline harden (uint32 child) {
            return child | 0x80000000;
        }
        
        using path = list<uint32>;
        
        path read_path (string_view);
        string write (path);

        struct pubkey {
            
            secp256k1::pubkey Pubkey;
            chain_code ChainCode;
            type Net;
            byte Depth;
            uint32_t Parent;
            uint32_t Sequence;
            
            bool valid () const {
                return Pubkey.valid () && Pubkey.size () == secp256k1::pubkey::CompressedSize && (Net == main || Net == test);
            }
            
            pubkey (const secp256k1::pubkey &p, const chain_code &cc) : Pubkey {p}, ChainCode {cc} {}
            pubkey (string_view s) : pubkey {read (s)} {}
            pubkey () = default;
            
            static pubkey read (string_view);
            static pubkey from_seed (seed entropy, type net);

            string write () const;

            Bitcoin::address::decoded address () const {
                return {to_address (Net), Bitcoin::Hash160 (Pubkey)};
            }

            bool operator == (const pubkey &rhs) const;
            bool operator != (const pubkey &rhs) const;
            
            pubkey derive (path l) const;
            pubkey derive (string_view l) const;

            explicit operator Bitcoin::address::decoded () const {
                return address ();
            }
            
            explicit operator string () const {
                return write ();
            }
        };
        
        struct secret {
            
            secp256k1::secret Secret;
            chain_code ChainCode;
            type Net;
            byte Depth;
            uint32_t Parent;
            uint32_t Sequence;

            secret (const secp256k1::secret &s, const chain_code &cc, type network) : Secret {s}, ChainCode {cc}, Net {network} {}
            secret (string_view s) : secret {read (s)} {}
            secret () = default;

            static secret read (string_view);
            static secret from_seed (seed entropy, type net = main);

            string write () const;
            pubkey to_public () const;
            
            bool valid () const {
                return Secret.valid () && (Net == main || Net == test);
            }

            bool operator == (const secret &rhs) const;
            bool operator != (const secret &rhs) const;
            
            Bitcoin::signature sign (const digest256& d) const;
            
            secret derive (path l) const;
            secret derive (string_view l) const;
            
            explicit operator Bitcoin::secret () const {
                return Bitcoin::secret {to_wif (Net), Secret, true};
            }
            
            explicit operator string () const {
                return write ();
            }
        };

        secret derive (const secret &, uint32);
        pubkey derive (const pubkey &, uint32);
        
        secret inline derive (const secret &s, path l) {
            if (l.empty ()) return s;
            return derive (derive (s, l.first ()), l.rest());
        }
        
        pubkey inline derive (const pubkey &p, path l) {
            if (l.empty ()) return p;
            return derive (derive (p, l.first ()), l.rest ());
        }
        
        pubkey inline pubkey::derive (path l) const {
            return BIP_32::derive (*this, l);
        }
        
        secret inline secret::derive (path l) const {
            return BIP_32::derive (*this, l);
        }
        
        pubkey inline pubkey::derive (string_view l) const {
            return BIP_32::derive (*this, read_path (l));
        }
        
        secret inline secret::derive (string_view l) const {
            return BIP_32::derive (*this, read_path (l));
        }

        secret inline derive (const secret &x, string_view p) {
            return derive (x, read_path (p));
        }
        
        pubkey inline derive (const pubkey &x, string_view p) {
            return derive (x, read_path (p));
        }

        std::ostream inline &operator << (std::ostream &os, const pubkey &pubkey) {
            return os << pubkey.write ();
        }

        std::ostream inline &operator << (std::ostream &os, const secret &secret) {
            return os << secret.write ();
        }
    
    }
    
    struct key_source final : Gigamonkey::key_source {
        uint32 Index;
        BIP_32::secret Key;
        
        key_source (uint32 i, const BIP_32::secret &s) :
            Index {i}, Key {s} {}
        
        key_source (const BIP_32::secret &s) : key_source {1, s} {}
        
        Bitcoin::secret next () override {
            return Bitcoin::secret (Key.derive ({Index++}));
        }
        
        Bitcoin::secret first () const {
            return Bitcoin::secret (Key.derive ({Index}));
        }
        
        key_source rest () const {
            return key_source {Index + 1, Key};
        }
    };
    
    struct address_source final : Gigamonkey::address_source {
        uint32 Index;
        BIP_32::pubkey Key;
        
        address_source (uint32 i, const BIP_32::pubkey &s) :
            Index {i}, Key {s} {}
        
        address_source (const BIP_32::pubkey &s) : address_source {1, s} {}
        
        Bitcoin::address::decoded next () override {
            return Key.derive ({Index++}).address ();
        }
        
        Bitcoin::address::decoded first () const {
            return Key.derive ({Index}).address ();
        }
        
        address_source rest () const {
            return address_source {Index + 1, Key};
        }
    };

}

#endif

