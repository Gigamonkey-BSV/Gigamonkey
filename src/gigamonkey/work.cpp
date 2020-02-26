// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work.hpp>
#include <gigamonkey/hash.hpp>

namespace Gigamonkey::work {
    
    // copied from arith_uint256.cpp and therefore probably works. 
    uint256 expand_compact(uint32_little compact) {
        base_uint<256> expanded;
        int nSize = compact >> 24;
        uint32_t nWord = compact & 0x007fffff;
        if (nSize <= 3) {
            nWord >>= 8 * (3 - nSize);
            expanded = nWord;
        } else {
            expanded = nWord;
            expanded <<= 8 * (nSize - 3);
        }
        
        // negative 
        if (nWord != 0 && (compact & 0x00800000) != 0) return 0;
        
        // overflow
        if (nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) ||
                           (nWord > 0xffff && nSize > 32))) return 0;
        
        return digest256(expanded).Value;
    }
    
    uint256 satoshi_uint256_to_uint256(::uint256 x) {
        uint256 y;
        std::copy(x.begin(), x.end(), y.begin());
        return y;
    }
    
    string::string(const CBlockHeader& b) : 
        Version{int32_little{b.nVersion}}, 
        Digest{satoshi_uint256_to_uint256(b.hashPrevBlock)}, 
        MerkleRoot{satoshi_uint256_to_uint256(b.hashMerkleRoot)}, 
        Timestamp{uint32_little{b.nTime}}, 
        Target{uint32_little{b.nBits}}, 
        Nonce{b.nNonce} {};
        
    string::operator CBlockHeader() const {
        CBlockHeader h;
        h.nVersion = Version;
        h.nTime = Timestamp.Value;
        h.nBits = Target;
        h.nNonce = Nonce;
        std::copy(Digest.begin(), Digest.end(), h.hashPrevBlock.begin());
        std::copy(MerkleRoot.begin(), MerkleRoot.end(), h.hashMerkleRoot.begin());
        return h;
    }
        
    bytes string::write() const {
        return Gigamonkey::write(80, Version, Digest, MerkleRoot, Target, Timestamp, Nonce);
    }
    
}

