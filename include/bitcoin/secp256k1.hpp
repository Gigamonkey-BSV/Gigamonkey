// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SECP256K1
#define GIGAMONKEY_SECP256K1

#include "types.hpp"
#include "hash.hpp"

namespace gigamonkey::secp256k1 {
    
    const size_t secret_size = 32;
    
    using secret = uint<secret_size, big_endian>;
    
    bool valid(const secret& s);
    
    signature sign(const secret&, const digest<32, big_endian>&);
    
    enum pubkey_type : byte {
        uncompressed = 0x04,
        compressed_positive = 0x03,
        compressed_negative = 0x02
    };
    
    // There are two representations of public
    // keys that are allowed in Bitcoin. 
    // compressed is default. 
    const size_t pubkey_size = 33;
    const size_t uncompressed_pubkey_size = 65;
    
    using pubkey_compressed = uint<pubkey_size, little_endian>;
    using pubkey_uncompressed = uint<pubkey_size, little_endian>;
    
    bool valid(const pubkey_compressed& s);
    bool valid(const pubkey_uncompressed& s);
    
    pubkey_compressed to_pubkey(const secret& s);
    pubkey_uncompressed to_pubkey_uncompressed(const secret& s);
    
    bool verify(const pubkey_compressed&, digest<32, big_endian>&, const signature&);
    bool verify(const pubkey_uncompressed&, digest<32, big_endian>&, const signature&);
    
    secret negate(const secret&);
    pubkey_compressed negate(const pubkey_compressed&);
    pubkey_uncompressed negate(const pubkey_uncompressed&, const pubkey_uncompressed&);
    
    secret plus(const secret&, const secret&);
    pubkey_compressed plus(const pubkey_compressed&, const pubkey_compressed&);
    pubkey_uncompressed plus(const pubkey_uncompressed&, const pubkey_uncompressed&);
    
    pubkey_compressed plus(const pubkey_uncompressed&, const secret&);
    pubkey_uncompressed plus(const pubkey_uncompressed&, const secret&);
    
    secret times(const secret&, const secret&);
    pubkey_uncompressed times(const pubkey_uncompressed&, const secret&);
    pubkey_uncompressed times(const pubkey_uncompressed&, const secret&);
    
}

#endif

