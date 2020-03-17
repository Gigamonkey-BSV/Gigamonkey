// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_ADDRESS
#define GIGAMONKEY_ADDRESS

#include "hash.hpp"
#include "secp256k1.hpp"
#include <data/encoding/base58.hpp>

namespace Gigamonkey::base58 {
    
    // A base 58 check encoded string. 
    // The first byte is a version byte. 
    // The rest is the payload. 
    
    // In base 58 check encoding, each initial
    // zero bytes are written as a '1'. The rest
    // is encoded as a base 58 number. 
    struct check {
        bytes Data;
        
        bool valid() const;
        
        byte version() const;
        
        bytes_view payload() const;
        
        static check decode(string_view);
        std::string encode() const;
        
        check(byte version, bytes data);
        check(string_view s);
        
    private:
        check();
        check(bytes p);
    };
    
}

namespace Gigamonkey::Bitcoin {
    
    Gigamonkey::checksum checksum(bytes_view b);
    
    inline bytes append_checksum(bytes_view b) {
        bytes checked(b.size() + 4);
        bytes_writer(checked.begin(), checked.end()) << b << checksum(b);
        return checked;
    }
    
    bytes_view remove_checksum(bytes_view b);
    
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
        
        address(type p, const pubkey& pub);
        
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
    
}

inline std::ostream& operator<<(std::ostream& o, Gigamonkey::Bitcoin::address& a) {
    return o << std::string(a);
}

namespace Gigamonkey::base58 {
    
    inline bool check::valid() const {
        return Data.size() > 0;
    }
    
    inline byte check::version() const {
        if (!valid()) return 0;
        return Data[0];
    }
    
    inline bytes_view check::payload() const {
        if (!valid()) return {};
        return bytes_view(Data).substr(1);
    }
    
    inline check::check(byte version, bytes data) : Data{write(data.size() + 1, version, data)} {}
    inline check::check(string_view s) : check{decode(s)} {}
    
    inline check::check() : Data{} {};
    inline check::check(bytes p) : Data{p} {}
    
}

namespace Gigamonkey::Bitcoin {
    
    inline address::address() : Prefix{}, Digest{} {}
    inline address::address(type p, const digest& d) : Prefix{p}, Digest{d} {}
    
    inline address::address(type p, const pubkey& pub) : address{p, pub.hash()} {}
    
    inline bool address::operator==(const address& a) const {
        return Prefix == a.Prefix && Digest == a.Digest;
    }
    
    inline bool address::operator!=(const address& a) const {
        return !operator==(a);
    }
    
    inline string address::write(char prefix, const address::digest& d) {
        return base58::check{byte(prefix), bytes_view{d}}.encode();
    }
    
    inline string address::write() const {
        return write(Prefix, Digest);
    }
    
    inline address::operator string() const {
        return write();
    }
    
    inline bool address::valid_prefix(type p) {
        return p == main || p == test;
    }
    
    inline bool address::valid() const {
        return Digest.valid() && valid_prefix(Prefix);
    }
    
}

#endif
