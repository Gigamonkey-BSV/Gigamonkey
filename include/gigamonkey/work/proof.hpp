// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_PROOF
#define GIGAMONKEY_WORK_PROOF

#include <gigamonkey/work/string.hpp>
#include <gigamonkey/stratum/session_id.hpp>

namespace Gigamonkey::work {
    
    struct solution;
    struct puzzle;
    struct proof;
    
    proof solve(puzzle p, solution initial);
    
    bool operator==(const solution&, const solution&);
    bool operator!=(const solution&, const solution&);
    
    bool operator==(const puzzle&, const puzzle&);
    bool operator!=(const puzzle&, const puzzle&);
    
    bool operator==(const proof&, const proof&);
    bool operator!=(const proof&, const proof&);
    
    struct solution {
        Bitcoin::timestamp Timestamp;
        nonce Nonce;
        
        // Extra nonce is a part of Stratum but not part of the Bitcoin protocol. That is why we use big-endian. 
        uint64_big ExtraNonce2;
        
        solution(Bitcoin::timestamp t, nonce n, uint64_big b);
        solution();
        
        bool valid() const;
    };
    
    struct puzzle {
        // corresponds to Version in the Bitcoin protocol. 
        int32_little Category;
        uint256 Digest;
        compact Target;
        Merkle::path Path;
        
        // corresponds to the first part of the coinbase tx. 
        bytes Header;
        
        Stratum::session_id ExtraNonce1;
        
        // second part of the coinbase tx. 
        bytes Body;
        
        puzzle();
        puzzle(
            int32_little v, const uint256& d, 
            compact g, Merkle::path mp, const bytes& h, 
            Stratum::session_id extra, const bytes& b);
        
        bool valid() const;
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
            const Stratum::session_id& n1, 
            const uint64_big& n2, 
            const bytes& b);
        
        bytes meta() const;
        
        digest256 merkle_root() const;
        
        work::string string() const;
    };
    
    proof cpu_solve(puzzle p, solution initial);
    
    // right now we only have cpu mining in this lib. 
    inline proof solve(puzzle p, solution initial) {
        return cpu_solve(p, initial);
    }
    
    inline std::ostream& operator<<(std::ostream& o, const solution& p) {
        return o << "solution{Timestamp: " << p.Timestamp << ", Nonce: " << p.Nonce << ", ExtraNonce2: " << p.ExtraNonce2 << "}";
    }

    inline std::ostream& operator<<(std::ostream& o, const puzzle& p) {
        return o << "puzzle{Category: " << p.Category << ", Digest: " << p.Digest << ", Target: " << 
            p.Target << ", Path: " << p.Path << ", Header: " << p.Header << ", ExtraNonce1: " << p.ExtraNonce1 << ", Body: " << p.Body << "}";
    }

    inline std::ostream& operator<<(std::ostream& o, const proof& p) {
        return o << "proof{Puzzle: " << p.Puzzle << ", Solution: " << p.Solution << "}";
    }
    
    inline solution::solution(Bitcoin::timestamp t, nonce n, uint64_big b) : Timestamp{t}, Nonce{n}, ExtraNonce2{b} {}
    inline solution::solution() : Timestamp{}, Nonce{}, ExtraNonce2{} {};
    
    inline bool solution::valid() const {
        return Timestamp.valid();
    }
    
    inline bool operator==(const solution& a, const solution& b) {
        return a.Timestamp == b.Timestamp && 
            a.Nonce == b.Nonce && 
            a.ExtraNonce2 == b.ExtraNonce2;
    }
    
    inline bool operator!=(const solution& a, const solution& b) {
        return !(a == b);
    }
    
    inline puzzle::puzzle() : Category{}, Digest{}, Target{}, Path{}, Header{}, ExtraNonce1{}, Body{} {}
    inline puzzle::puzzle(int32_little v, const uint256& d, compact g, Merkle::path mp, const bytes& h, Stratum::session_id extra, const bytes& b) : 
        Category{v}, Digest{d}, Target{g}, Path{mp}, Header{h}, ExtraNonce1{extra}, Body{b} {}
    
    inline bool puzzle::valid() const {
        return Target.valid();
    }
    
    inline bool operator==(const puzzle& a, const puzzle& b) {
        return a.Category == b.Category && 
            a.Digest == b.Digest && 
            a.Target == b.Target && 
            a.Path == b.Path && 
            a.Header == b.Header && 
            a.ExtraNonce1 == b.ExtraNonce1 &&
            a.Body == b.Body;
    }
    
    inline bool operator!=(const puzzle& a, const puzzle& b) {
        return !(a == b);
    }
    
    inline proof::proof() : Puzzle{}, Solution{} {}
    inline proof::proof(const puzzle& p, const solution& x) : Puzzle{p}, Solution{x} {}
    
    inline proof::proof(
        const struct string& w, 
        Merkle::path mp, 
        const bytes& h, 
        const Stratum::session_id& n1, 
        const uint64_big& n2, 
        const bytes& b) : Puzzle{w.Category, w.Digest, w.Target, {}, h, n1, b}, Solution{w.Timestamp, w.Nonce, n2} {
        if (w.MerkleRoot != merkle_root()) *this = {};
    }
    
    inline bytes proof::meta() const {
        return write(Puzzle.Header.size() + 12 + Puzzle.Body.size(), 
            Puzzle.Header, Puzzle.ExtraNonce1, Solution.ExtraNonce2, Puzzle.Body);
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
     
    inline bool operator==(const proof& a, const proof& b) {
        return a.Puzzle == b.Puzzle && a.Solution == b.Solution;
    }
    
    inline bool operator!=(const proof& a, const proof& b) {
        return !(a == b);
    }
}

#endif

