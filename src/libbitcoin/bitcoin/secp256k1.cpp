// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <bitcoin/secp256k1.hpp>
#include <bitcoin/system/math/elliptic_curve.hpp>

namespace gigamonkey::secp256k1 {
    bool valid(const secret& s) {
        return libbitcoin::system::verify(s.Array);
    }
    
    signature sign(const secret& s, bytes_view b) {
        
    }
    
    bool valid(const pubkey& p) {
        return libbitcoin::system::verify(p.Array);
    }
    
    bool valid(const pubkey_uncompressed& s) {
        return libbitcoin::system::verify(p.Array);
    }
    
    pubkey to_pubkey(const secret& s) {
        secp256k1::pubkey x{};
        libbitcoin::system::secret_to_public(x.Array, s.Array);
        return x;
    }
    
    pubkey_uncompressed to_pubkey_uncompressed(const secret& s) {
        secp256k1::pubkey_uncompressed x{};
        libbitcoin::system::secret_to_public(x.Array, s.Array);
        return x;
    }
    
    bool verify(const pubkey& p, digest<32, big_endian>& d, const signature& s) {
        std::array<byte, 64> sig;
        std::copy(s.begin(), s.end(), sig.begin());
        return libbitcoin::system::verify_signature(p.Value, d.Digest.Array, sig);
    }
    
    bool verify(const pubkey_uncompressed& p, digest<32, big_endian>& d, const signature& s) {
        std::array<byte, 64> sig;
        std::copy(s.begin(), s.end(), sig.begin());
        return libbitcoin::system::verify_signature(p.Value, d.Digest.Array, sig);
    }
    
    secret negate(const secret&) {
        
    }
    
    pubkey negate(const pubkey&) {
        
    }
    
    pubkey_uncompressed negate(const pubkey_uncompressed&) {
        
    }
    
    secret plus(const secret& a, const secret& b) {
        secret x = a;
        libbitcoin::system::ec_add(x.Value.Array, b.Value.Array);
        return x;
    }
    
    pubkey plus(const pubkey&, const pubkey&) {
        
    }
    
    pubkey_uncompressed plus(const pubkey_uncompressed&, const pubkey_uncompressed&) {
        
    }
    
    pubkey plus(const pubkey&, const secret&) {
        
    }
    
    pubkey_uncompressed plus(const pubkey_uncompressed&, const secret&) {
        
    }
    
    secret times(const secret&, const secret&) {
        
    }
    
    pubkey times(const pubkey&, const secret&) {
        
    }
    
    pubkey_uncompressed times(const pubkey&, const secret&) {
        
    }
    
}
