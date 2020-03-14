// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_ADDRESS
#define GIGAMONKEY_ADDRESS

#include "hash.hpp"
#include "secp256k1.hpp"
#include <data/encoding/base58.hpp>

namespace Gigamonkey::base58 {
    
    struct check {
        bytes Data;
        
        bool valid() const {
            return Data.size() > 0;
        }
        
        byte version() const {
            if (!valid()) return 0;
            return Data[0];
        }
        
        bytes_view payload() const {
            if (!valid()) return {};
            return bytes_view(Data).substr(1);
        }
        
        static check decode(string_view);
        std::string encode() const;
        
        check(byte version, bytes data) : Data{write(data.size() + 1, version, data)} {}
        check(string_view s) : check{decode(s)} {}
        
    private:
        check() : Data{} {};
        check(bytes p) : Data{p} {}
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
        
        address() : Prefix{}, Digest{} {}
        address(type p, const digest& d) : Prefix{p}, Digest{d} {}
        
        explicit address(string_view s);
        
        address(type p, const pubkey& pub) : address{p, pub.hash()} {}
        
        bool operator==(const address& a) const {
            return Prefix == a.Prefix && Digest == a.Digest;
        }
        
        bool operator!=(const address& a) const {
            return !operator==(a);
        }
    
        static string write(char prefix, const digest& d) {
            return base58::check{byte(prefix), bytes_view{d}}.encode();
        }
        
        string write() const {
            return write(Prefix, Digest);
        }
        
        operator string() const {
            return write();
        }
        
        static bool valid_prefix(type p) {
            return p == main || p == test;
        }
        
        bool valid() const {
            return Digest.valid() && valid_prefix(Prefix);
        }
    };
    
    inline address read_address(string_view str) {
        return address{str};
    }
    
}

inline std::ostream& operator<<(std::ostream& o, Gigamonkey::Bitcoin::address& a) {
    return o << std::string(a);
}

#endif
