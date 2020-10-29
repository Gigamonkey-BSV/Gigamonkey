// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE
#define GIGAMONKEY_MERKLE

#include "hash.hpp"

namespace Gigamonkey::Merkle {
        
    inline digest256 hash_concatinated(const digest256& a, const digest256& b) {
        return Bitcoin::hash256(write(64, a, b));
    }
    
    using leaves = list<digest256>;
    
    digest256 root(list<digest256> l);
    
    struct path {
        uint32 Index;
        list<digest256> Hashes;
        
        path() : Index{0}, Hashes{} {}
        path(uint32 i, list<digest256> p);
        
        digest256 derive_root(digest256 leaf) const;
    
        bool check(digest256 leaf, digest256 root) const;
        
        bool operator==(const path& p) const;
        
        bool operator!=(const path& p) const;
        
    };
    
    struct branch {
        digest256 Leaf;
        path Path;
        digest256 Root;
        
        branch() : Leaf{}, Path{}, Root{} {}
        branch(const digest256& leaf, path p, const digest256& root) : Leaf{leaf}, Path{p}, Root{root} {}
        
        bool valid() const {
            return Leaf.valid() && Path.check(Leaf, Root);
        }
    };
    
    class tree {
        size_t Size;
        cross<digest256> Hashes;
        
    public:
        tree(leaves);
        
        digest256 root() const {
            return Hashes[Hashes.size() - 1];
        }
        
        size_t size() const {
            return Size;
        }
        
        Merkle::branch branch(uint32 index) const;
    };
    
    inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::Merkle::path& p) {
        return o << "path{" << p.Index << ", " << p.Hashes << "}";
    }
    
    inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::Merkle::branch& p) {
        return o << "branch{Leaf: " << p.Leaf << ", Path: " << p.Path << ", Root: " << p.Root << "}";
    }
    
    inline path::path(uint32 i, list<digest256> p) : Index{i}, Hashes{p} {};
    
    inline digest256 path::derive_root(digest256 leaf) const {
        if (Hashes.size() == 0) return leaf; 
        return path{Index >> 1, Hashes.rest()}.derive_root(
            Index & 1 ? hash_concatinated(Hashes.first(), leaf) : hash_concatinated(leaf, Hashes.first()));
    }
    
    inline bool path::check(digest256 leaf, digest256 root) const {
        return root == derive_root(leaf);
    }
    
    inline bool path::operator==(const path& p) const {
        return Hashes == p.Hashes && Index == p.Index;
    }
    
    inline bool path::operator!=(const path& p) const {
        return !operator==(p);
    }
}

#endif
