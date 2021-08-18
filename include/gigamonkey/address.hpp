// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_ADDRESS
#define GIGAMONKEY_ADDRESS

#include "signature.hpp"
#include <data/encoding/base58.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct pubkey;
    
    // A Bitcoin address is a hash160 digest of a public key 
    // with a human-readable format designed on it. 
    struct address {
        enum type : byte {
            main = 0x00,
            test = 0x6F
        };

        type Prefix;

        using digest = Gigamonkey::digest<20>;

        digest Digest;

        address();
        address(type p, const address::digest& d);

        explicit address(string_view s);

        address(type p, const secp256k1::pubkey& pub);

        bool operator==(const address& a) const;
        bool operator!=(const address& a) const;

        static string write(char prefix, const digest& d);

        string write() const;

        operator string() const;

        static bool valid_prefix(type p);

        bool valid() const;
    };

    inline address read_address(string_view str) {
        return address{str};
    }

    inline std::ostream& operator<<(std::ostream& o, const address& a) {
        return o << std::string(a);
    }
    
    // a Bitcoin pubkey is the same as a secp256k1 pubkey except 
    // that we have a standard human representation, which is
    // just a hex string. 
    struct pubkey : secp256k1::pubkey {
        using secp256k1::pubkey::pubkey;
        pubkey(const secp256k1::pubkey &p) : secp256k1::pubkey{p} {}
        
        explicit pubkey(string_view s) : secp256k1::pubkey{} {
            ptr<bytes> hex = encoding::hex::read(s);
            if (hex != nullptr) {
                this->resize(hex->size());
                std::copy(hex->begin(), hex->end(), this->begin());
            };
        }
        
        Bitcoin::address address(Bitcoin::address::type t) const {
            return Bitcoin::address{t, hash160(*this)};
        }
        
        explicit operator string() const;
        
        bool verify(const signature &x, const signature::document& document, sighash::directive d) const;
    };

    // A Bitcoin checksum takes the hash256 value of a string
    // and appends the last 4 bytes of the result. 
    Gigamonkey::checksum checksum(bytes_view b);

    inline bytes append_checksum(bytes_view b) {
        bytes checked(b.size() + 4);
        bytes_writer(checked.begin(), checked.end()) << b << checksum(b);
        return checked;
    }

    bytes_view remove_checksum(bytes_view b);

}

namespace Gigamonkey::base58 {

    // A base 58 check encoded string. 
    // The first byte is a version byte. 
    // The rest is the payload. 

    // In base 58 check encoding, each initial
    // zero bytes are written as a '1'. The rest
    // is encoded as a base 58 number. 
    struct check : bytes {

        bool valid() const;

        byte version() const;

        bytes_view payload() const;

        static check decode(string_view);
        std::string encode() const;

        check(byte version, bytes data);
        check(string_view s);
        check(bytes p);
        
        // try all single letter replacements, insertions, and deletions
        // to see if we can find a valid base58 check encoded string. 
        static check recover(const string_view invalid);
    private:
        check();

    };

}

namespace Gigamonkey::Bitcoin {

    inline address::address() : Prefix{}, Digest{} {}
    inline address::address(type p, const digest& d) : Prefix{p}, Digest{d} {}

    inline address::address(type p, const secp256k1::pubkey& pub) : address{p, hash160(pub)} {}

    bool inline address::operator==(const address& a) const {
        return Prefix == a.Prefix && Digest == a.Digest;
    }

    bool inline address::operator!=(const address& a) const {
        return !operator==(a);
    }

    string inline address::write(char prefix, const address::digest& d) {
        return base58::check{byte(prefix), bytes_view{d}}.encode();
    }

    string inline address::write() const {
        return write(Prefix, Digest);
    }

    inline address::operator string() const {
        return write();
    }

    bool inline address::valid_prefix(type p) {
        return p == main || p == test;
    }

    bool inline address::valid() const {
        return Digest.valid() && valid_prefix(Prefix);
    }
    
    inline pubkey::operator string() const {
        return encoding::hex::write(*this);
    }

}

namespace Gigamonkey::base58 {

    inline bool check::valid() const {
        return size() > 0;
    }

    inline byte check::version() const {
        if (!valid()) return 0;
        return operator[](0);
    }

    inline bytes_view check::payload() const {
        if (!valid()) return {};
        return bytes_view(*this).substr(1);
    }

    inline check::check(byte version, bytes data) : bytes{write(data.size() + 1, version, data)} {}
    inline check::check(string_view s) : check{decode(s)} {}

    inline check::check() : bytes{} {};
    inline check::check(bytes p) : bytes{p} {}

}

#endif
