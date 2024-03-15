// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MERKLE_SERVER
#define GIGAMONKEY_MERKLE_SERVER

#include <gigamonkey/merkle/proof.hpp>

namespace Gigamonkey::Merkle {
    
    struct tree;
    
    // for serving branches. Would be on a miner's computer. 
    class server final {
        cross<digest> Digests;
        data::map<digest, uint32> Indices;
        
        server () : Digests {}, Indices {}, Width {0}, Height {0} {}
        
    public:
        uint32 Width;
        uint32 Height;
        
        server (leaf_digests);
        server (const tree &);
        
        operator tree () const;
        
        digest root () const;
        
        list<proof> proofs () const;
        
        proof operator [] (const digest &d) const;
        
        bool operator == (const server &s) const;
    };
    
    inline digest server::root () const {
        return Digests[-1];
    }
        
    inline bool server::operator == (const server &s) const {
        return Width == s.Width && Height == s.Height && Digests == s.Digests;
    }
}

#endif

