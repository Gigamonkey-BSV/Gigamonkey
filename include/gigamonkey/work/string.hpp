// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_STRING
#define GIGAMONKEY_WORK_STRING

#include <gigamonkey/timechain.hpp>

namespace Gigamonkey::work {
    
    struct string {
        int32_little Version;
        uint256 Digest;
        uint256 MerkleRoot;
        timestamp Timestamp;
        target Target;
        nonce Nonce;
        
        string(int32_little v, uint256 d, uint256 mp, timestamp ts, target tg, nonce n) : 
            Version{v}, Digest{d}, MerkleRoot{mp}, Timestamp{ts}, Target{tg}, Nonce{n} {}
            
        static string read(const slice<80> x);
        
        explicit string(const slice<80> x);
        
        bytes write() const;
        
        uint256 hash() const {
            return Bitcoin::hash256(write());
        }
        
        static bool valid(const slice<80> x) {
            return Bitcoin::hash256(x).Value < header::target(x).expand();
        }
        
        bool valid() {
            return hash() < Target.expand();
        }
        
        explicit string(const Bitcoin::header&);
        
        work::difficulty difficulty() const {
            return Target.difficulty();
        }
        
        explicit operator CBlockHeader() const;
    };
    
}

#endif


