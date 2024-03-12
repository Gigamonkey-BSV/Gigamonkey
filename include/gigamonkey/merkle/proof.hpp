// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE_PROOF
#define GIGAMONKEY_MERKLE_PROOF

#include <gigamonkey/hash.hpp>

namespace Gigamonkey::Merkle {
    
    using digest = digest256;
    
    // the function that is used to compute successive nodes in the Merkle tree. 
    inline digest hash_concatinated (const digest &a, const digest &b) {
        return Bitcoin::Hash256 (write (64, a, b));
    }
    
    // all hashes for the leaves of a given tree in order starting from zero.
    using leaf_digests = list<digest>;
    
    using digests = stack<digest>;
    
    digest root (leaf_digests l);
    
    // path includes the index but not the leaf or root hash. 
    struct path;
    
    bool operator == (const path &a, const path &b);
    bool operator != (const path &a, const path &b);
    
    std::ostream &operator << (std::ostream &o, const path &p);
    
    // leaf has the index and leaf hash. 
    struct leaf;
    
    digest root (leaf, digests);
    
    bool operator == (const leaf &a, const leaf &b);
    bool operator != (const leaf &a, const leaf &b);
    
    bool operator <= (const leaf &a, const leaf &b);
    bool operator >= (const leaf &a, const leaf &b);
    bool operator < (const leaf &a, const leaf &b);
    bool operator > (const leaf &a, const leaf &b);
    
    std::ostream &operator << (std::ostream &o, const leaf &p);
    
    // branch includes the data of both leaf and path. 
    struct branch;
    
    bool operator == (const branch &a, const branch &b);
    bool operator != (const branch &a, const branch &b);
    
    bool operator <= (const branch &a, const branch &b);
    bool operator >= (const branch &a, const branch &b);
    bool operator < (const branch &a, const branch &b);
    bool operator > (const branch &a, const branch &b);
    
    std::ostream &operator << (std::ostream &o, const branch &b);
    
    // proof has a branch and the root hash. 
    struct proof;
    
    digest root (const proof &p);
    
    bool operator == (const proof &a, const proof &b);
    bool operator != (const proof &a, const proof &b);
    
    bool operator <= (const proof &a, const proof &b);
    bool operator >= (const proof &a, const proof &b);
    bool operator < (const proof &a, const proof &b);
    bool operator > (const proof &a, const proof &b);
    
    std::ostream &operator << (std::ostream &o, const proof &p);
    
    // path is an index and a sequence of hashes not 
    // including the leaf hash or root. 
    struct path final {
        uint64 Index;
        digests Digests;
        
        path ();
        path (uint64 i, const digests p);
        
        bool valid () const;
        
        digest derive_root (const digest &l) const;
    };
    
    struct leaf final {
        digest Digest;
        uint64 Index;
        
        leaf ();
        leaf (digest d, uint64 i);
        explicit leaf (const digest &d) : leaf(d, 0) {}
        
        bool valid () const;
        
        leaf next (const digest &d) const {
            return {Index & 1 ? hash_concatinated (d, Digest) : hash_concatinated (Digest, d), Index >> 1};
        }
    };
    
    inline digest path::derive_root (const digest& l) const {
        return root (leaf {l, Index}, Digests);
    }
    
    using entry = data::entry<digest, path>;
    
    // branch has a leaf and a path but not a root. 
    struct branch final {
        leaf Leaf;
        digests Digests;
        
        branch ();
        branch (leaf);
        branch (leaf, digests);
        branch (const digest &d, path p) : branch {leaf {d, p.Index}, p.Digests} {}
        explicit branch (const entry &e) : Leaf {e.Key, e.Value.Index}, Digests {e.Value.Digests} {}
        
        bool valid () const;
        
        bool empty () const;
        
        leaf first () const;
        
        operator leaf () const;
    
        branch rest () const {
            if (Digests.empty ()) return *this;
            return branch {Leaf.next (Digests.first ()), Digests.rest ()};
        }
        
        digest root () const {
            return Merkle::root (Leaf, Digests);
        }
        
        explicit operator path () const;
        
        explicit operator entry () const;
        
    };
    
    struct proof final {
        
        branch Branch;
        digest Root;
    
        proof ();
        explicit proof (const digest &root);
        proof (branch p, const digest &root);
        
        bool valid () const;
        uint32 index () const {
            return Branch.Leaf.Index;
        }
        
    };
    
    digest inline root (const proof &p) {
        return p.Root;
    }
    
    std::ostream inline &operator << (std::ostream &o, const path &p) {
        return o << "path{" << p.Index << ", " << p.Digests << "}";
    }
    
    std::ostream inline &operator << (std::ostream &o, const leaf &p) {
        return o << "leaf{" << p.Index << ", " << p.Digest << "}";
    }
    
    std::ostream inline &operator << (std::ostream &o, const branch &b) {
        return o << "branch{" << b.Leaf << ", " << b.Digests << "}";
    }
    
    std::ostream inline &operator << (std::ostream &o, const proof &p) {
        return o << "proof{" << p.Branch << ", " << p.Root << "}";
    }
    
    bool inline operator == (const path &a, const path &b) {
        return a.Index == b.Index && a.Digests == b.Digests;
    }
    
    bool inline operator != (const path &a, const path &b) {
        return a.Index != b.Index || a.Digests == b.Digests;
    }
    
    bool inline operator == (const leaf &a, const leaf &b) {
        return a.Digest == b.Digest && a.Index == b.Index;
    }
    
    bool inline operator != (const leaf &a, const leaf &b) {
        return a.Digest != b.Digest || a.Index != b.Index;
    }
    
    bool inline operator <= (const leaf &a, const leaf &b) {
        if (a.Index == b.Index) return a.Digest <= b.Digest;
        return a.Index <= b.Index;
    }
    
    bool inline operator >= (const leaf &a, const leaf &b) {
        if (a.Index == b.Index) return a.Digest >= b.Digest;
        return a.Index >= b.Index;
    }
    
    bool inline operator < (const leaf &a, const leaf &b) {
        if (a.Index == b.Index) return a.Digest < b.Digest;
        return a.Index < b.Index;
    }
    
    bool inline operator > (const leaf &a, const leaf &b) {
        if (a.Index == b.Index) return a.Digest > b.Digest;
        return a.Index > b.Index;
    }
    
    bool inline operator == (const branch &a, const branch &b) {
        return a.Leaf == b.Leaf && a.Digests == b.Digests;
    }
    
    bool inline operator != (const branch &a, const branch &b) {
        return a.Leaf != b.Leaf || a.Digests != b.Digests;
    }
    
    bool inline operator <= (const branch &a, const branch &b) {
        return a.Leaf <= b.Leaf;
    }
    
    bool inline operator >= (const branch &a, const branch &b) {
        return a.Leaf >= b.Leaf;
    }
    
    bool inline operator < (const branch &a, const branch &b) {
        return a.Leaf < b.Leaf;
    }
    
    bool inline operator > (const branch &a, const branch &b) {
        return a.Leaf > b.Leaf;
    }
    
    bool inline operator == (const proof &a, const proof &b) {
        return a.Root == b.Root && a.Branch == b.Branch;
    }
    
    bool inline operator != (const proof &a, const proof &b) {
        return a.Root != b.Root || a.Branch != b.Branch;
    }
    
    bool inline operator <= (const proof &a, const proof &b) {
        if (a.Branch == b.Branch) return a.Root <= b.Root;
        return a.Branch <= b.Branch;
    }
    
    bool inline operator >= (const proof &a, const proof &b) {
        if (a.Branch == b.Branch) return a.Root >= b.Root;
        return a.Branch >= b.Branch;
    }
    
    bool inline operator < (const proof &a, const proof &b) {
        if (a.Branch == b.Branch) return a.Root < b.Root;
        return a.Branch < b.Branch;
    }
    
    bool inline operator > (const proof &a, const proof &b) {
        if (a.Branch == b.Branch) return a.Root > b.Root;
        return a.Branch > b.Branch;
    }
    
    inline path::path () : Index {0}, Digests {} {}
    
    inline path::path (uint64 i, const digests p) : Index {i}, Digests {p} {}
    
    inline bool path::valid () const {
        return Digests.valid ();
    }
    
    inline leaf::leaf () : Digest {}, Index {0} {}
    
    inline leaf::leaf (digest d, uint64 i) : Digest {d}, Index {i} {}
    
    inline bool leaf::valid () const {
        return Digest.valid ();
    }
    
    inline branch::branch (): Leaf {}, Digests {} {}
    
    inline branch::branch (leaf l, digests p) : Leaf {l}, Digests {p} {}
    
    inline branch::branch (leaf l) : Leaf {l}, Digests {} {}
    
    bool inline branch::valid () const {
        return Leaf.valid () && Digests.valid ();
    }
    
    bool inline branch::empty () const {
        return Digests.empty ();
    }
    
    leaf inline branch::first () const {
        return Leaf;
    }
    
    inline branch::operator leaf () const {
        return Leaf;
    }
    
    inline branch::operator path () const {
        return path {Leaf.Index, Digests};
    }
    
    inline branch::operator entry () const {
        return entry {Leaf.Digest, operator path ()};
    }
    
    inline proof::proof () : Branch {}, Root {} {}
    
    inline proof::proof (branch p, const digest &root) : Branch {p}, Root {root} {}
    
    inline proof::proof (const digest &root) : Branch {leaf {root, 0}}, Root {root} {}
    
    bool inline proof::valid () const {
        return Root.valid () && Branch.valid () && Root == Branch.root ();
    }
}

#endif

