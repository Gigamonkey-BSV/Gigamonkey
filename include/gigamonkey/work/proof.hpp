// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_PROOF
#define GIGAMONKEY_WORK_PROOF

#include <gigamonkey/work/string.hpp>

namespace Gigamonkey::work {
    
    struct solution {
        Bitcoin::timestamp Timestamp;
        nonce Nonce;
        uint64_little ExtraNonce;
        
        solution(Bitcoin::timestamp t, nonce n, uint64_little b);
        solution();
        
        bool valid() const;
        
        bool operator==(const solution& s) const;
        bool operator!=(const solution& s) const;
    };
    
    struct puzzle {
        int32_little Category;
        uint256 Digest;
        compact Target;
        Merkle::path Path;
        bytes Header;
        uint32_little ExtraNonce;
        bytes Body;
        
        puzzle();
        puzzle(
            int32_little v, const uint256& d, 
            compact g, Merkle::path mp, const bytes& h, 
            uint32_little extra, const bytes& b);
        
        bool valid() const;
        
        bool operator==(const puzzle& p) const;
        bool operator!=(const puzzle& p) const;
    };
    
    struct proof {
        puzzle Puzzle;
        solution Solution;
        
        bool valid() const;
        
        proof();
        proof(const puzzle& p, const solution& x);
        proof(
            const string& w, 
            Merkle::path mp, 
            const bytes& h, 
            const uint32_little& n1, 
            const uint64_little& n2, 
            const bytes& b);
        
        bytes meta() const;
        
        digest256 merkle_root() const;
        
        work::string string() const;
        
        bool operator==(const proof& p) const;
        bool operator!=(const proof& p) const;
    };
    
    proof cpu_solve(puzzle p, solution initial);
    
    inline std::ostream& operator<<(std::ostream& o, const solution& p) {
        return o << "solution{Timestamp: " << p.Timestamp << ", Nonce: " << p.Nonce << ", ExtraNonce: " << p.ExtraNonce << "}";
    }

    inline std::ostream& operator<<(std::ostream& o, const puzzle& p) {
        return o << "puzzle{Category: " << p.Category << ", Digest: " << p.Digest << ", Target: " << 
            p.Target << ", Path: " << p.Path << ", Header: " << p.Header << ", ExtraNonce: " << p.ExtraNonce << ", Body: " << p.Body << "}";
    }

    inline std::ostream& operator<<(std::ostream& o, const proof& p) {
        return o << "proof{Puzzle: " << p.Puzzle << ", Solution: " << p.Solution << "}";
    }
    
    inline solution::solution(Bitcoin::timestamp t, nonce n, uint64_little b) : Timestamp{t}, Nonce{n}, ExtraNonce{b} {}
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
    
    inline puzzle::puzzle() : Category{}, Digest{}, Target{}, Path{}, Header{}, ExtraNonce{}, Body{} {}
    inline puzzle::puzzle(int32_little v, const uint256& d, compact g, Merkle::path mp, const bytes& h, uint32_little extra, const bytes& b) : 
        Category{v}, Digest{d}, Target{g}, Path{mp}, Header{h}, ExtraNonce{extra}, Body{b} {}
    
    inline bool puzzle::valid() const {
        return Target.valid();
    }
    
    inline bool puzzle::operator==(const puzzle& p) const {
        return Category == p.Category && 
            Digest == p.Digest && 
            Target == p.Target && 
            Path == p.Path && 
            Header == p.Header && 
            ExtraNonce == p.ExtraNonce &&
            Body == p.Body;
    }
    
    inline bool puzzle::operator!=(const puzzle& p) const {
        return !operator==(p);
    }
    
    inline proof::proof() : Puzzle{}, Solution{} {}
    inline proof::proof(const puzzle& p, const solution& x) : Puzzle{p}, Solution{x} {}
    
    inline proof::proof(
        const struct string& w, 
        Merkle::path mp, 
        const bytes& h, 
        const uint32_little& n1, 
        const uint64_little& n2, 
        const bytes& b) : Puzzle{w.Category, w.Digest, w.Target, {}, h, n1, b}, Solution{w.Timestamp, w.Nonce, n2} {
        if (w.MerkleRoot != merkle_root()) *this = {};
    }
    
    inline bytes proof::meta() const {
        return write(Puzzle.Header.size() + 12 + Puzzle.Body.size(), 
            Puzzle.Header, Puzzle.ExtraNonce, Solution.ExtraNonce, Puzzle.Body);
    }
    
    inline digest256 proof::merkle_root() const {
        return Puzzle.Path.derive_root(Bitcoin::hash256(meta()));
    }
    
    inline string proof::string() const {
        return work::string{
            Puzzle.Category, 
            Puzzle.Digest, 
            merkle_root(), 
            Solution.Timestamp, 
            Puzzle.Target, 
            Solution.Nonce
        };
    }
    
    inline bool proof::valid() const {
        return string().valid();
    }
     
    inline bool proof::operator==(const proof& p) const {
        return Puzzle == p.Puzzle && Solution == p.Solution;
    }
    
    inline bool proof::operator!=(const proof& p) const {
        return !operator==(p);
    }
    
    inline proof cpu_solve(puzzle p, solution initial) {
        uint256 target = p.Target.expand();
        if (target == 0) return {};
        // This is for test purposes only. Therefore we do not
        // accept difficulties that are above the ordinary minimum. 
        if (p.Target.difficulty() > difficulty::minimum()) return {}; 
        proof pr{p, initial};
        while(!pr.valid()) pr.Solution.Nonce++;
        return pr;
    }
}

#endif

