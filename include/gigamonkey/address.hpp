// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_ADDRESS
#define GIGAMONKEY_ADDRESS

#include "hash.hpp"
#include "secp256k1.hpp"
#include <data/encoding/base58.hpp>

namespace gigamonkey::bitcoin {
    
    gigamonkey::checksum checksum(bytes_view);
    
    inline writer write_checksum(writer w, bytes_view b) {
        return w << b << checksum(b);
    }
    
    namespace base58 {
    
        inline string encode(bytes_view b) {
            return data::encoding::base58::write(b);
        }
        
        inline bool decode(bytes&, string_view);
        
        string check_encode(bytes_view);
        
        bool check_decode(bytes&, string_view);
        
    }
    
    inline string write_address(char prefix, bytes_view b) {
        return base58::check_encode(data::stream::write(b.size() + 1, prefix, b));
    }
    
    struct address {
        char Prefix;
        digest<20, LittleEndian> Digest;
        
        address() : Prefix{}, Digest{} {}
        address(char p, digest<20> d) : Digest{d} {}
        
        explicit address(const string s);
        
        explicit address(char, const pubkey&);
        
        explicit address(char, const secret&);
        
        operator string() const {
            return write_address(Prefix, Digest);
        }
        
        static bool valid_prefix(char p);
        
        bool valid() const {
            return Digest.valid() && valid_prefix(Prefix);
        }
    };
    
    address read_address(string);
    
}

inline std::ostream& operator<<(std::ostream& o, gigamonkey::bitcoin::address& a) {
    return o << std::string(a);
}

#endif
