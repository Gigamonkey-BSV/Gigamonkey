// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_PROOF
#define GIGAMONKEY_WORK_PROOF

#include <gigamonkey/work/string.hpp>
#include <gigamonkey/stratum/session_id.hpp>

namespace Gigamonkey::work {
    
    struct candidate;
    struct puzzle;
    struct job;
    struct share;
    struct solution;
    struct proof;
    
    proof solve (const puzzle& p, const solution& initial);
    
    bool operator == (const share&, const share&);
    bool operator != (const share&, const share&);
    
    bool operator == (const solution&, const solution&);
    bool operator != (const solution&, const solution&);
    
    bool operator == (const job&, const job&);
    bool operator != (const job&, const job&);
    
    bool operator == (const puzzle&, const puzzle&);
    bool operator != (const puzzle&, const puzzle&);
    
    bool operator == (const proof&, const proof&);
    bool operator != (const proof&, const proof&);
    
    bool operator == (const candidate&, const candidate&);
    bool operator != (const candidate&, const candidate&);
    
    // candidate corresponds to a block that has been designed by the node but not completed with a nonce, timestamp, or coinbase. 
    struct candidate {
        // corresponds to Version in the Bitcoin protocol. 
        int32_little Category;
        uint256 Digest;
        compact Target;
        Merkle::path Path;
        
        candidate () : Category {}, Digest {}, Target {}, Path {} {}
        candidate (int32_little v, const uint256& d, compact g, Merkle::path mp) :
            Category {v}, Digest {d}, Target {g}, Path {mp} {}
        
        bool valid () const;
    };
    
    // puzzle corresponds to the point where the coinbase has been constructed, other than the extra nonces.
    struct puzzle final {
        candidate Candidate;
        
        // corresponds to the first part of the coinbase tx. 
        bytes Header;
        
        // second part of the coinbase tx. 
        bytes Body;
        
        // Allows for additional bits to be provided as the solution to the
        // puzzle which alter the category field according to this mask. 
        int32_little Mask;
        
        puzzle ();
        puzzle (
            int32_little v, 
            const uint256& d, 
            compact g, 
            Merkle::path mp, 
            const bytes& h, 
            const bytes& b, 
            int32_little mask = -1) : puzzle {candidate {v, d, g, mp}, h, b, mask} {}
        
        puzzle(const candidate& x, const bytes& h, const bytes& b, int32_little mask = -1) : 
            Candidate {x}, Header {h}, Body {b}, Mask {mask} {}
        
        bool valid () const;
    };
    
    // job corresponds to the point where the mining pool has assigned an extra nonce to a miner
    // and is ready to pass on the job to that miner. 
    struct job {
        puzzle Puzzle;
        
        Stratum::session_id ExtraNonce1;
        
        job ();
        job (const puzzle&, Stratum::session_id extra);
        
        bool valid () const;
    };
    
    struct share final {
        Bitcoin::timestamp Timestamp;
        nonce Nonce;
        
        // Extra nonce is a part of Stratum but not part of the Bitcoin protocol. That is why we use big-endian. 
        bytes ExtraNonce2;
        
        // see BIP 320
        // https://en.bitcoin.it/wiki/BIP_0320
        std::optional<int32_little> Bits;
        
        share (Bitcoin::timestamp t, nonce n, bytes b, int32_little bits);
        share (Bitcoin::timestamp t, nonce n, bytes b);
        share ();
        
        bool valid() const;
        
        int32_little general_purpose_bits (int32_little mask) const {
            return int32_little {bool (Bits) ? ((*Bits) & mask) : 0};
        }
    };
    
    struct solution final {
        share Share;
        
        Stratum::session_id ExtraNonce1;
        
        solution () : Share {}, ExtraNonce1 {} {}
        solution (const share& x, Stratum::session_id n1) : Share {x}, ExtraNonce1 {n1} {}
        solution (Bitcoin::timestamp t, nonce n, bytes_view b, Stratum::session_id n1) : solution {share {t, n, b}, n1} {}
        
        bool valid () const {
            return Share.valid ();
        } 
    };
    
    struct proof {
        puzzle Puzzle;
        solution Solution;
        
        bool valid () const;
        
        proof ();
        proof (const puzzle& p, const solution& x);
        proof (const job& j, const share& x) : proof {j.Puzzle, solution {x, j.ExtraNonce1}} {}
        proof (
            const string& w, 
            Merkle::path mp, 
            const bytes& h, 
            const Stratum::session_id& n1, 
            const bytes& n2, 
            const bytes& b);
        
        bytes meta () const;
        
        digest256 merkle_root () const;
        
        work::string string () const;
        
        work::job job () const {
            return {Puzzle, Solution.ExtraNonce1};
        }
    };
    
    proof cpu_solve (const puzzle& p, const solution& initial);
    
    // right now we only have cpu mining in this lib. 
    proof inline solve (puzzle p, solution initial) {
        return cpu_solve (p, initial);
    }
    
    bool inline operator == (const share& a, const share& b) {
        return a.Timestamp == b.Timestamp && a.Nonce == b.Nonce && 
            a.ExtraNonce2 == b.ExtraNonce2 && a.Bits == b.Bits;
    }
    
    bool inline operator != (const share& a, const share& b) {
        return !(a == b);
    }
    
    bool inline operator == (const solution& a, const solution& b) {
        return a.Share == b.Share && a.ExtraNonce1 == b.ExtraNonce1;
    }
    
    bool inline operator != (const solution& a, const solution& b) {
        return !(a == b);
    }
    
    bool inline operator == (const candidate& a, const candidate& b) {
        return a.Category == b.Category && 
            a.Digest == b.Digest && 
            a.Target == b.Target && 
            a.Path == b.Path;
    }
    
    bool inline operator != (const candidate& a, const candidate& b) {
        return !(a == b);
    }
    
    bool inline operator == (const puzzle& a, const puzzle& b) {
        return a.Candidate == b.Candidate && a.Header == b.Header && 
            a.Body == b.Body && a.Mask == b.Mask;
    }
    
    bool inline operator != (const puzzle& a, const puzzle& b) {
        return !(a == b);
    }
    
    bool inline operator == (const job& a, const job& b) {
        return a.Puzzle == b.Puzzle && a.ExtraNonce1 == b.ExtraNonce1;
    }
    
    bool inline operator != (const job& a, const job& b) {
        return !(a == b);
    }
    
    bool inline operator == (const proof& a, const proof& b) {
        return a.Puzzle == b.Puzzle && a.Solution == b.Solution;
    }
    
    bool inline operator != (const proof& a, const proof& b) {
        return !(a == b);
    }
    
    inline std::ostream& operator << (std::ostream& o, const share& p) {
        o << "share{Timestamp: " << p.Timestamp << ", Nonce: " << p.Nonce << ", ExtraNonce2: " << p.ExtraNonce2;
        if (p.Bits) o << ", Bits: " << *p.Bits; 
        return o << "}";
    }
    
    inline std::ostream& operator << (std::ostream& o, const candidate& p) {
        return o << "candidate{Category: " << p.Category << ", Digest: " << p.Digest << ", Target: " << 
            p.Target << ", Path: " << p.Path << "}";
    }
    
    inline std::ostream& operator << (std::ostream& o, const puzzle& p) {
        return o << "puzzle{" << p.Candidate << ", Header: " << p.Header << ", Body: " << p.Body << ", Mask: " << p.Mask << "}";
    }
    
    inline std::ostream& operator << (std::ostream& o, const job& p) {
        return o << "job{" << p.Puzzle << ", ExtraNonce1: " << p.ExtraNonce1 << "}";
    }
    
    inline std::ostream& operator << (std::ostream& o, const solution& p) {
        return o << "solution{" << p.Share << ", ExtraNonce1: " << p.ExtraNonce1 << "}";
    }
    
    inline std::ostream& operator << (std::ostream& o, const proof& p) {
        return o << "proof{Puzzle: " << p.Puzzle << ", Solution: " << p.Solution << "}";
    }
    
    inline share::share (Bitcoin::timestamp t, nonce n, bytes b)
        : Timestamp {t}, Nonce {n}, ExtraNonce2 {b}, Bits {} {}
    
    inline share::share (Bitcoin::timestamp t, nonce n, bytes b, int32_little bits)
        : Timestamp {t}, Nonce {n}, ExtraNonce2 {b}, Bits {bits} {}
    
    inline share::share () : Timestamp {}, Nonce {}, ExtraNonce2 {} {};
    
    bool inline share::valid () const {
        return Timestamp.valid ();
    }
    
    inline puzzle::puzzle () : Candidate {}, Header {}, Body {}, Mask {-1} {}
    
    inline job::job () : Puzzle {}, ExtraNonce1 {} {}
    inline job::job (const puzzle& p, Stratum::session_id extra) : Puzzle {p}, ExtraNonce1 {extra} {}
    
    bool inline candidate::valid () const {
        return Target.valid () && Path.valid ();
    }
    
    bool inline puzzle::valid () const {
        return Candidate.valid ();
    }
    
    bool inline job::valid () const {
        return Puzzle.valid ();
    }
    
    inline proof::proof () : Puzzle{}, Solution{} {}
    inline proof::proof (const puzzle& p, const solution& x) : Puzzle{p}, Solution{x} {}
    
    inline proof::proof (
        const struct string& w, 
        Merkle::path mp, 
        const bytes& h, 
        const Stratum::session_id& n1, 
        const bytes& n2, 
        const bytes& b) : 
        Puzzle {w.Category, w.Digest, w.Target, {}, h, b},
        Solution {share {w.Timestamp, w.Nonce, n2}, n1} {
        if (w.MerkleRoot != merkle_root ()) *this = {};
    }
    
    bytes inline proof::meta () const {
        return write (Puzzle.Header.size () + 4 + Solution.Share.ExtraNonce2.size () + Puzzle.Body.size (),
            Puzzle.Header, Solution.ExtraNonce1, Solution.Share.ExtraNonce2, Puzzle.Body);
    }
    
    digest256 inline proof::merkle_root () const {
        return Puzzle.Candidate.Path.derive_root (Bitcoin::Hash256 (meta ()));
    }
    
    string inline proof::string () const {
        return work::string {
            (Puzzle.Candidate.Category & Puzzle.Mask) | Solution.Share.general_purpose_bits (~Puzzle.Mask),
            Puzzle.Candidate.Digest, 
            merkle_root (),
            Solution.Share.Timestamp, 
            Puzzle.Candidate.Target, 
            Solution.Share.Nonce
        };
    }
    
    bool inline proof::valid () const {
        return string ().valid ();
    }
}

#endif

