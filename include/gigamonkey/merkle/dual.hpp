// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE_DUAL
#define GIGAMONKEY_MERKLE_DUAL

#include <gigamonkey/merkle/proof.hpp>

namespace Gigamonkey::Merkle {
    
    struct dual;
    
    bool operator==(const dual&, const dual&);
    bool operator!=(const dual&, const dual&);
    
    dual operator+(const proof& a, const proof& b);
    
    std::ostream& operator<<(std::ostream& o, const dual& d);
    
    struct tree;
    
    using map = data::map<digest, path>;
    
    // dual to the Merkle tree. Prunable. 
    // would be good in a wallet. 
    struct dual final {
        map Paths;
        digest Root;
        
        dual() : Paths{}, Root{} {}
        dual(map m, digest root) : Paths{m}, Root{root} {}
        explicit dual(digest root) : dual{{}, root} {}
        
        dual(const proof& p) : Paths{entry(p.Branch)}, Root{p.Root} {}
        
        dual(const tree& t);
        
        bool valid() const;
        
        bool contains(const digest&) const;
        
        proof operator[](const digest& b) const {
            auto e = Paths[b];
            if (!e.valid()) return proof{};
            return proof{branch{b, e}, Root};
        }
        
        list<leaf> leaves() const {
            return data::for_each([](const proof& p) -> leaf {
                return p.Branch.Leaf;
            }, proofs());
        }
        
        const ordered_list<proof> proofs() const;
        
        dual operator+(const dual& d) const;
        
        dual& operator=(const dual& d);
        
        json serialize() const;
        static dual deserialize(const json&);
    };
    
    inline bool operator==(const dual& a, const dual& b) {
        return a.Root == b.Root && a.Paths == b.Paths;
    }
    
    inline bool operator!=(const dual& a, const dual& b) {
        return !(a == b);
    }
    
    inline dual operator+(const proof& a, const proof& b) {
        return dual{a} + b;
    }
    
    inline dual& dual::operator=(const dual& d) {
        Paths = d.Paths;
        Root = d.Root;
        return *this;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const dual& d) {
        return o << "dual{" << d.Paths << ", " << d.Root << "}";
    }
    
}

#endif

