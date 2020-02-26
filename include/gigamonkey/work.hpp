// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK
#define GIGAMONKEY_WORK

#include <gigamonkey/timechain.hpp>
#include <primitives/block.h>

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
        
        explicit string(const CBlockHeader&);
        
        explicit string(const Bitcoin::header&);
        
        work::difficulty difficulty() const {
            return Target.difficulty();
        }
        
        explicit operator CBlockHeader() const;
    };
    
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
        
        static solution cpu_solve(puzzle p, solution initial) {
            uint256 target = p.Target.expand();
            // This is for test purposes only. Therefore we do not
            // accept difficulties that are above the ordinary minimum. 
            if (p.Target.difficulty() > difficulty::minimum()) return {}; 
            while(p.string(initial).hash() > target) initial.Nonce++;
            return initial;
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
    
}

#endif

