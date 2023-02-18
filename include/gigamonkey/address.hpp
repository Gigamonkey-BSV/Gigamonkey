// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_ADDRESS
#define GIGAMONKEY_ADDRESS

#include <gigamonkey/p2p/checksum.hpp>
#include <gigamonkey/signature.hpp>
#include <data/encoding/base58.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct pubkey;
    
    // A Bitcoin address is a Hash160 digest of a public key 
    // with a human-readable format designed on it. 
    struct address : string {
        enum type : byte {
            main = 0x00,
            test = 0x6F
        };

        type prefix () const;

        digest160 digest () const;

        address ();
        address (type p, const digest160& d);

        explicit address (string_view s);

        address (type p, const secp256k1::pubkey& pub);

        static string write (char prefix, const digest160& d);

        static bool valid_prefix (type p);

        bool valid () const;

        static bool valid (string_view);

        struct decoded {
            type Prefix;
            digest160 Digest;

            bool valid () const;

            decoded ();
            decoded (type, const digest160 &);

            string write () const;
        };

        static decoded read (string_view);
        decoded read () const;

        address (decoded);
    };

    std::ostream inline &operator << (std::ostream& o, const address& a) {
        return o << std::string(a);
    }
    
    // a Bitcoin pubkey is the same as a secp256k1 pubkey except 
    // that we have a standard human representation, which is
    // a hex string. 
    struct pubkey : secp256k1::pubkey {
        using secp256k1::pubkey::pubkey;
        pubkey (const secp256k1::pubkey &p) : secp256k1::pubkey {p} {}
        
        explicit pubkey (string_view s) : secp256k1::pubkey {} {
            ptr<bytes> hex = encoding::hex::read(s);
            if (hex != nullptr) {
                this->resize (hex->size ());
                std::copy (hex->begin (), hex->end (), this->begin ());
            };
        }
        
        Bitcoin::address address (Bitcoin::address::type t) const {
            return Bitcoin::address {t, address_hash (*this)};
        }
        
        explicit operator string () const;
        
        bool verify (const signature &x, const sighash::document& document) const {
            return signature::verify (x, *this, document);
        }
    };

    inline address::decoded::decoded () : Prefix {}, Digest {} {}
    inline address::decoded::decoded (type p, const digest160& d) : Prefix {p}, Digest {d} {}

    inline address::address () : string {} {}
    inline address::address (type p, const digest160& d) : string {write (p, d)} {}

    inline address::address (type p, const secp256k1::pubkey& pub) : address {p, Hash160 (pub)} {}

    address::type inline address::prefix () const {
        return read ().Prefix;
    }

    digest<20> inline address::digest () const {
        return read ().Digest;
    }

    string inline address::write (char prefix, const digest160& d) {
        return base58::check {byte (prefix), bytes_view {d}}.encode ();
    }

    bool inline address::valid_prefix (type p) {
        return p == main || p == test;
    }

    bool inline address::decoded::valid () const {
        return Digest.valid () && valid_prefix (Prefix);
    }

    bool inline address::valid () const {
        return valid (*this);
    }

    inline address::address (address::decoded d) : string {d.write ()} {}

    string inline address::decoded::write () const {
        return address::write (Prefix, Digest);
    }

    address::decoded inline address::read () const {
        return read (*this);
    }

    bool inline address::valid (string_view x) {
        return read (x).valid ();
    }

    inline address::address (string_view s) : string {s} {}
    
    inline pubkey::operator string () const {
        return encoding::hex::write (*this);
    }

}

#endif
