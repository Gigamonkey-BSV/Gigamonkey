// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPV
#define GIGAMONKEY_SPV

#include <gigamonkey/timechain.hpp>
#include <gigamonkey/merkle/dual.hpp>

namespace Gigamonkey::Bitcoin {
    
    block genesis();
    
    // interface for the headers and merkle paths database. 
    struct headers {
        
        struct header {
            digest256 Hash;
            Bitcoin::header Header;
            N Height;
            work::difficulty Cumulative;
            
            bool operator==(const header& h) const {
                return Header == h.Header;
            }
            
            bool operator!=(const header& h) const {
                return !operator==(h);
            }
            
            bool valid() const {
                return Hash.valid() && Header.valid();
            }
            
            header();
            header(digest256 s, Bitcoin::header h, N n, work::difficulty d) : Hash{s}, Header{h}, Height{n}, Cumulative{d} {}
        };
        
        virtual header latest() const = 0;
        
        virtual header operator[](const N&) const = 0;
        virtual header operator[](const digest256&) const = 0;
        
        virtual Merkle::dual dual_tree(const digest256&) const = 0;
        
        virtual Merkle::proof proof(const txid&) const = 0;
        
        virtual bool insert(const header&) = 0;
        
        virtual bool insert(const Merkle::proof&) = 0;
        
        // an in-memory version of headers.
        class memory;
        
    };
    
    /*class headers::memory final : headers {
        struct entry : header {
            Merkle::map Tree;
            entry(digest256 s, Bitcoin::header h, N n, work::difficulty d) : header{s, h, n, d}, Tree{} {}
        };
        
        struct chain {
            data::stack<ptr<entry>> Chain;
            
            chain() : Chain{} {}
            
            chain(const Bitcoin::header& e) : Chain{} {
                *this = this->insert(e);
            }
            
            chain(const data::stack<ptr<entry>>& x) : Chain{x} {}
            
            bool valid() const {
                return Chain.size() == 0;
            }
            
            work::difficulty difficulty() const {
                if (valid()) return {};
                return Chain.first()->Cumulative;
            }
            
            bool operator<=(const chain& x) const {
                return difficulty() <= x.difficulty();
            }
            
            chain insert(const Bitcoin::header& h) const {
                auto hash_digest = h.hash();
                return chain{Chain.prepend(std::make_shared<entry>(
                    hash_digest, h, Chain.size() + 1, h.Target.difficulty() + difficulty()))};
            }
            
            const entry& first() const {
                return *Chain.first();
            }
            
            entry& first() {
                return *Chain.first();
            }
            
            bool operator==(const chain& x) const {
                return Chain == x.Chain;
            }
            
            bool operator!=(const chain& x) const {
                return Chain != x.Chain;
            }
        };
        
        data::ordered_list<chain> Headers;
        
        data::map<N, chain> ByHeight;
        
        data::map<digest256, chain> ByHash;
        
        data::map<digest256, chain> ByRoot;
        
        data::map<txid, chain> ByTxid;
        
        memory(const Bitcoin::header& h) : 
            Headers{chain{h}}, 
            ByHeight{0, Headers.first()}, 
            ByHash{Headers.first().first().Hash, Headers.first()},
            ByRoot{Headers.first().first().Header.MerkleRoot, Headers.first()}, ByTxid{} {}
        
    public:
        memory() : memory(genesis().Header) {}
        
        header latest() const override {
            return Headers.first().first();
        }
        
        header operator[](const N& n) const override {
            chain headers = ByHeight[n];
            if (!headers.valid()) return {};
            return headers.first();
        }
        
        Merkle::dual dual_tree(const digest256& d) const override {
            chain headers = ByHash[d];
            if (!headers.valid()) return {};
            return Merkle::dual{headers.first().Tree, headers.first().Header.MerkleRoot};
        }
        
        Merkle::proof proof(const txid& t) const override {
            chain headers = ByTxid[t];
            if (!headers.valid()) return {};
            return Merkle::dual{headers.first().Tree, headers.first().Header.MerkleRoot}[t];
        };
        
        bool insert(const Bitcoin::header& h) override {
            data::stack<chain> p{};
            data::ordered_list<chain> x = Headers;
            
            // are we adding to some known chain tip? 
            while(x.size() > 0) {
                if (h.Previous == x.first().first().Hash) {
                    Headers = x.rest() << p << (x.first().insert(h));
                    return true;
                }
                p = p << x.first();
                x = x.rest();
            }
            
            // Do we know about this prev hash at all?
            chain headers = ByHash[h.Previous];
            if (!headers.valid()) return false;
            
            Headers = Headers << headers.insert(h);
            return true;
        }
        
        bool insert(const Merkle::proof& p) override {
            chain headers = ByRoot[p.Root];
            if (!headers.valid()) return false;
            auto d = Merkle::dual{headers.first().Tree, headers.first().Header.MerkleRoot} + p;
            if (!d.valid()) return false;
            headers.first().Tree = d.Paths;
            ByTxid = ByTxid.insert(p.Branch.Leaf.Digest, headers);
            return true;
        }
    };*/
    
}

#endif
