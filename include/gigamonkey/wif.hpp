// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WIF
#define GIGAMONKEY_WIF

#include "signature.hpp"
#include "address.hpp"
#include <gigamonkey/ecies/electrum.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct secret;
        
    bool operator == (const secret &, const secret &);
    bool operator != (const secret &, const secret &);
    
    std::ostream &operator << (std::ostream &, const secret &);

    // WIF stands for Wallet Import Format.
    struct WIF;
    
    // Bitcoin secret keys are more than just secp256k1 private keys. 
    // They also include information on network (main or test) and
    // on whether the corresponding public key is given in compressed 
    // format. This is important because the format of the public key 
    // changes the address. 
    struct secret {
        
        // The serialized form of the key has a different prefix 
        // depending on whether it is for testnet or mainnet. 
        enum type : byte {
            main = 0x80, 
            test = 0xef
        };
        
        type Prefix;
        secp256k1::secret Secret;
        
        // whether the corresponding public key is compressed. 
        bool Compressed;
        
        size_t size () const;
        
        bool valid () const;
        
        secret ();
        secret (type p, secp256k1::secret s, bool c = true);
        
        secret (string_view s);
        
        pubkey to_public () const;
        
        Bitcoin::address::decoded address () const;
        
        secp256k1::signature sign (const digest256& d) const;
        
        signature sign (const sighash::document& document, sighash::directive d = directive (sighash::all)) const;
        
        bytes encrypt (const bytes& message) const;
        bytes decrypt (const bytes& message) const;

        WIF encode () const;

        operator string () const;
        
    private:
        static Bitcoin::address::type to_address_type (type t);
    };

    struct WIF : string {

        // why is wif compressed bigger than wif uncompressed?
        // because compressed keys were invented after uncompressed keys.
        // A compressed wif code is denoted with an extra character to
        // distinguish it from an uncompressed wif code.
        constexpr static size_t CompressedSize {34};
        constexpr static size_t UncompressedSize {33};

        constexpr static byte CompressedSuffix = 0x01;

        static bool valid (string_view);
        static Bitcoin::secret::type prefix (string_view);
        static secp256k1::secret secret (string_view);
        static bool compressed (string_view);

        static WIF encode (byte, const secp256k1::secret&, bool compressed = true);
        static Bitcoin::secret decode (string_view);

        bool valid () const;
        Bitcoin::secret::type prefix () const;
        secp256k1::secret secret () const;
        bool compressed () const;

        Bitcoin::secret decode () const;

        WIF (): string {} {}
    };
    
    bool inline operator == (const secret& a, const secret& b) {
        return a.Prefix == b.Prefix && a.Secret == b.Secret && a.Compressed == b.Compressed;
    }
    
    bool inline operator != (const secret& a, const secret& b) {
        return !(a == b);
    }
    
    std::ostream inline &operator << (std::ostream& o, const secret& s) {
        return o << s.encode ();
    }
        
    size_t inline secret::size () const {
        return 33 + (Compressed ? 1 : 0); 
    }
    
    bool inline secret::valid () const {
        return Secret.valid () && (Prefix == main || Prefix == test);
    }
    
    inline secret::secret () : Prefix {0}, Secret {}, Compressed {false} {}
    
    Bitcoin::address::type inline secret::to_address_type (secret::type t) {
        return t == main ? Bitcoin::address::main : Bitcoin::address::test;
    }
    
    inline secret::secret (type p, secp256k1::secret s, bool c) : Prefix {p}, Secret {s}, Compressed {c} {}
    
    inline secret::secret (string_view s) : secret {WIF::decode (s)} {}
        
    WIF inline secret::encode () const {
        return WIF::encode (Prefix, Secret, Compressed);
    }

    inline secret::operator string () const {
        return static_cast<string> (encode ());
    }
    
    pubkey inline secret::to_public () const {
        return pubkey {Compressed ? Secret.to_public ().compress () : Secret.to_public ().decompress ()};
    }
    
    Bitcoin::address::decoded inline secret::address () const {
        return {to_address_type (Prefix), to_public ().address_hash ()};
    }
    
    secp256k1::signature inline secret::sign (const digest256& d) const {
        return Secret.sign (d);
    }
    
    signature inline secret::sign (const sighash::document& document, sighash::directive d) const {
        return signature::sign (Secret, d, document);
    }
        
    bytes inline secret::encrypt (const bytes& message) const {
        return ECIES::electrum::encrypt (message, to_public ());
    }
    
    bytes inline secret::decrypt (const bytes& message) const {
        return ECIES::electrum::decrypt (message, Secret);
    }

    bool inline WIF::valid (string_view x) {
        return decode (x).valid ();
    }

    secret::type inline WIF::prefix (string_view x) {
        return decode (x).Prefix;
    }

    secp256k1::secret inline WIF::secret (string_view x) {
        return decode (x).Secret;
    }

    bool inline WIF::compressed (string_view x) {
        return decode (x).Compressed;
    }

    bool inline WIF::valid () const {
        return valid (*this);
    }

    secret::type inline WIF::prefix () const {
        return prefix (*this);
    }

    secp256k1::secret inline WIF::secret () const {
        return secret (*this);
    }

    bool inline WIF::compressed () const {
        return compressed (*this);
    }

    secret inline WIF::decode () const {
        return decode (*this);
    }
    
}

#endif

