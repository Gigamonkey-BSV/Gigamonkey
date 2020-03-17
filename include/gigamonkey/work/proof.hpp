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
        
        solution(timestamp t, nonce n, bytes b);
        solution();
        
        bool valid() const;
        
        bool operator==(const solution& s) const;
        bool operator!=(const solution& s) const;
    };
    
    struct puzzle {
        int32_little Category;
        uint256 Digest;
        target Target;
        Merkle::path MerklePath;
        bytes Header;
        bytes Body;
        
        puzzle();
        puzzle(int32_little v, uint256 d, target g, Merkle::path mp, bytes h, bytes b);
        
        bool valid() const;
        
        bytes meta(solution x) const;
            
        work::string string(solution x) const;
        
        bool check(solution x) const;
        
        bool operator==(const puzzle& p) const;
        bool operator!=(const puzzle& p) const;
    };
    
    struct proof {
        puzzle Puzzle;
        solution Solution;
        
        bool valid() const;
        
        proof();
        proof(puzzle p, solution x);
        
        bytes meta() const;
        
        work::string string() const;
        
        bool operator==(const proof& p) const;
        bool operator!=(const proof& p) const;
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
    return o << "puzzle{Category: " << p.Category << ", Digest: " << p.Digest << ", Target: " << 
        p.Target << ", MerklePath" << p.MerklePath << ", Header: " << p.Header << ", Body: " << p.Body << "}";
}

inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::work::proof& p) {
    return o << "proof{Puzzle: " << p.Puzzle << ", Solution: " << p.Solution << "}";
}

namespace Gigamonkey::work {
    
    inline bool proof::valid() const {
        return string().valid();
    }
        
    inline bytes puzzle::meta(solution x) const {
        return write(Header.size() + x.ExtraNonce.size() + Body.size(), Header, x.ExtraNonce, Body);
    }
    
    inline solution::solution(timestamp t, nonce n, bytes b) : Timestamp{t}, Nonce{n}, ExtraNonce{b} {}
    inline solution::solution() : Timestamp{}, Nonce{}, ExtraNonce{} {};
    
    inline bool solution::valid() const {
        return Timestamp.valid();
    }
    
    inline bool solution::operator==(const solution& s) const {
        return Timestamp == s.Timestamp && 
            Nonce == s.Nonce && 
            ExtraNonce == s.ExtraNonce;
    }
    
    inline bool solution::operator!=(const solution& s) const {
        return !operator==(s);
    }
    
    inline puzzle::puzzle() : Category{}, Digest{}, Target{}, MerklePath{}, Header{}, Body{} {}
    inline puzzle::puzzle(int32_little v, uint256 d, target g, Merkle::path mp, bytes h, bytes b) : 
        Category{v}, Digest{d}, Target{g}, MerklePath{mp}, Header{h}, Body{b} {}
    
    inline bool puzzle::valid() const {
        return Target.valid();
    }
    
    inline string puzzle::string(solution x) const {
        return work::string{
            Category, 
            Digest, 
            MerklePath.derive_root(Bitcoin::hash256(meta(x))), 
            x.Timestamp, 
            Target, 
            x.Nonce
        };
    }
    
    inline bool puzzle::check(solution x) const {
        return string(x).valid();
    }
    
    inline bool puzzle::operator==(const puzzle& p) const {
        return Category == p.Category && 
            Digest == p.Digest && 
            Target == p.Target && 
            MerklePath == p.MerklePath && 
            Header == p.Header && 
            Body == p.Body;
    }
    
    inline bool puzzle::operator!=(const puzzle& p) const {
        return !operator==(p);
    }
    
    inline proof::proof() : Puzzle{}, Solution{} {}
    inline proof::proof(puzzle p, solution x) : Puzzle{p}, Solution{x} {}
    
    inline bytes proof::meta() const {
        return Puzzle.meta(Solution);
    }
    
    inline string proof::string() const {
        return Puzzle.string(Solution);
    }
    
    inline bool proof::operator==(const proof& p) const {
        return Puzzle == p.Puzzle && Solution == p.Solution;
    }
    
    inline bool proof::operator!=(const proof& p) const {
        return !operator==(p);
    }
}

#endif

