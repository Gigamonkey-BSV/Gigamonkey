// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_PROOF
#define GIGAMONKEY_WORK_PROOF

#include <gigamonkey/work/string.hpp>

namespace Gigamonkey::work {
    
    struct solution {
        timestamp Timestamp;
        nonce Nonce;
        bytes ExtraNonce;
        
        solution(timestamp t, nonce n, bytes b) : Timestamp{t}, Nonce{n}, ExtraNonce{b} {}
        solution() : Timestamp{}, Nonce{}, ExtraNonce{} {};
        
        bool valid() const {
            return Timestamp.valid();
        }
        
        bool operator==(const solution& s) const {
            return Timestamp == s.Timestamp && 
                Nonce == s.Nonce && 
                ExtraNonce == s.ExtraNonce;
        }
        
        bool operator!=(const solution& s) const {
            return !operator==(s);
        }
    };
    
    struct puzzle {
        int32_little Version;
        uint256 Digest;
        target Target;
        Merkle::path MerklePath;
        bytes Header;
        bytes Body;
        
        puzzle() : Version{}, Digest{}, Target{}, MerklePath{}, Header{}, Body{} {}
        puzzle(int32_little v, uint256 d, target g, Merkle::path mp, bytes h, bytes b) : 
            Version{v}, Digest{d}, Target{g}, MerklePath{mp}, Header{h}, Body{b} {}
        
        bool valid() const {
            return Target.valid();
        }
        
        bytes cover_page(solution x) const {
            return write(Header.size() + x.ExtraNonce.size() + Body.size(), Header, x.ExtraNonce, Body);
        }
            
        work::string string(solution x) const {
            return work::string{
                Version, 
                Digest, 
                MerklePath.derive_root(Bitcoin::hash256(cover_page(x))), 
                x.Timestamp, 
                Target, 
                x.Nonce
            };
        }
        
        bool check(solution x) const {
            return string(x).valid();
        }
        
        bool operator==(const puzzle& p) const {
            return Version == p.Version && 
                Digest == p.Digest && 
                Target == p.Target && 
                MerklePath == p.MerklePath && 
                Header == p.Header && 
                Body == p.Body;
        }
        
        bool operator!=(const puzzle& p) const {
            return !operator==(p);
        }
    };
    
    struct proof {
        puzzle Puzzle;
        solution Solution;
        
        bool valid() const {
            return string().valid();
        }
        
        proof() : Puzzle{}, Solution{} {}
        proof(puzzle p, solution x) : Puzzle{p}, Solution{x} {}
        
        bytes cover_page() const {
            return Puzzle.cover_page(Solution);
        }
        
        work::string string() const {
            return Puzzle.string(Solution);
        }
        
        bool operator==(const proof& p) const {
            return Puzzle == p.Puzzle && Solution == p.Solution;
        }
        
        bool operator!=(const proof& p) const {
            return !operator==(p);
        }
    };
    
    inline proof cpu_solve(puzzle p, solution initial) {
        uint256 target = p.Target.expand();
        if (target == 0) return {};
        // This is for test purposes only. Therefore we do not
        // accept difficulties that are above the ordinary minimum. 
        if (p.Target.difficulty() > difficulty::minimum()) return {}; 
        while(p.string(initial).hash() >= target) initial.Nonce++;
        return proof{p, initial};
    }
    
}

inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::work::solution& p) {
    return o << "solution{Timestamp: " << p.Timestamp << ", Nonce: " << p.Nonce << ", ExtraNonce: " << p.ExtraNonce << "}";
}

inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::work::puzzle& p) {
    return o << "puzzle{Version: " << p.Version << ", Digest: " << p.Digest << ", Target: " << 
        p.Target << ", MerklePath" << p.MerklePath << ", Header: " << p.Header << ", Body: " << p.Body << "}";
}

inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::work::proof& p) {
    return o << "proof{Puzzle: " << p.Puzzle << ", Solution: " << p.Solution << "}";
}

#endif

