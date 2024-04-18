// Copyright (c) 2019-2023 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_ADDRESS
#define GIGAMONKEY_ADDRESS

#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct pubkey;
    struct address;

    std::ostream &operator << (std::ostream &o, const address &a);
    std::ostream &operator << (std::ostream &o, const pubkey &a);
    
    // A Bitcoin address is a Hash160 digest of a public key 
    // with a human-readable format in base58 check encoding.
    struct address : string {
        // the decoded form of the address has a prefix that
        // specifies the type of address.
        enum type : byte {
            main = 0x00,
            test = 0x6F
        };

        static bool valid (string_view);
        static type prefix (string_view);
        static digest160 digest (string_view);

        bool valid () const;

        type prefix () const;
        digest160 digest () const;

        address ();
        address (type p, const digest160 &d);

        explicit address (string_view s);

        static address encode (char prefix, const digest160 &d);

        static bool valid_prefix (type p);

        // the decoded form of the address, consisting
        // of a prefix and the Hash160 digest.
        struct decoded {
            type Prefix;
            digest160 Digest;

            bool valid () const;

            decoded ();
            decoded (type, const digest160 &);
            decoded (string_view);

            address encode () const;

            bool operator == (const decoded &d) const {
                return Prefix == d.Prefix && Digest == d.Digest;
            }

            std::strong_ordering operator <=> (const decoded &) const;
            explicit operator string () const;
        };

        static decoded decode (string_view);
        decoded decode () const;

        address (decoded);
    };
    
    // a Bitcoin pubkey is the same as a secp256k1 pubkey except 
    // that we have a standard human representation, which is
    // a hex string. 
    struct pubkey : secp256k1::pubkey {
        using secp256k1::pubkey::pubkey;
        pubkey (const secp256k1::pubkey &p) : secp256k1::pubkey {p} {}
        
        explicit pubkey (string_view s) : secp256k1::pubkey {} {
            maybe<bytes> hex = encoding::hex::read (s);
            if (bool (hex)) {
                this->resize (hex->size ());
                std::copy (hex->begin (), hex->end (), this->begin ());
            };
        }
        
        digest160 address_hash () const;
        
        explicit operator string () const;
        
        bool verify (const signature &x, const sighash::document &document) const {
            return signature::verify (x, *this, document);
        }
    };

    std::ostream inline &operator << (std::ostream &o, const address &a) {
        return o << static_cast<string> (a);
    }

    std::ostream inline &operator << (std::ostream &o, const pubkey &a) {
        return o << string (a);
    }

    bool inline address::valid (string_view x) {
        return decode (x).valid ();
    }

    address::type inline address::prefix (string_view x) {
        return decode (x).Prefix;
    }

    digest160 inline address::digest (string_view x) {
        return decode (x).Digest;
    }

    address::type inline address::prefix () const {
        return prefix (*this);
    }

    digest160 inline address::digest () const {
        return digest (*this);
    }

    bool inline address::valid () const {
        return valid (*this);
    }

    inline address::decoded::decoded () : Prefix {}, Digest {} {}
    inline address::decoded::decoded (type p, const digest160 &d) : Prefix {p}, Digest {d} {}

    inline address::address () : string {} {}
    inline address::address (type p, const digest160& d) : address {encode (p, d)} {}

    bool inline address::valid_prefix (type p) {
        return p == main || p == test;
    }

    bool inline address::decoded::valid () const {
        return Digest.valid () && valid_prefix (Prefix);
    }

    inline address::address (address::decoded d) : address {d.encode ()} {}

    inline address::address (string_view s) : string {s} {}

    address inline address::decoded::encode () const {
        return address::encode (Prefix, Digest);
    }

    address::decoded inline address::decode () const {
        return decode (*this);
    }

    inline address::decoded::decoded (string_view x) : decoded {address::decode (x)} {}

    inline address::decoded::operator string () const {
        return static_cast<string> (encode ());
    }
    
    inline pubkey::operator string () const {
        return encoding::hex::write (*this);
    }

    digest160 inline pubkey::address_hash () const {
        return Bitcoin::address_hash (*this);
    }

}

#endif
