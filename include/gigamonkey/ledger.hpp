// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_LEDGER
#define GIGAMONKEY_LEDGER

#include "spv.hpp"
#include <gigamonkey/script/script.hpp>

namespace Gigamonkey::Bitcoin {
        
    struct prevout : data::entry<Bitcoin::outpoint, Bitcoin::output> {
        using data::entry<Bitcoin::outpoint, Bitcoin::output>::entry;
        
        Bitcoin::outpoint outpoint() const {
            return this->Key;
        }
        
        Bitcoin::satoshi value() const {
            return this->Value.Value;
        }
        
        bytes script() const {
            return this->Value.Script;
        }
    };
}

namespace Gigamonkey {
    
    struct ledger {
        using block_header = Gigamonkey::headers::header;
        
        virtual list<block_header> headers(uint64 since_height) = 0;
        
        struct double_entry : ptr<bytes> {
            Merkle::proof Proof;
            Bitcoin::header Header;
            
            bool valid() const {
                return *this != nullptr;
            }
            
            bool confirmed() const {
                return valid() && Header.valid() && id() == Proof.Branch.Leaf.Digest && Proof.valid() && Proof.Root == Header.MerkleRoot;
            }
            
            double_entry() : ptr<bytes>{nullptr}, Proof{}, Header{} {}
            
            // for a confirmed transaction. 
            double_entry(ptr<bytes> t, Merkle::proof p, const Bitcoin::header& h) : ptr<bytes>{t}, Proof{p}, Header{h} {}
            
            // for an unconfirmed transaction. 
            double_entry(ptr<bytes> t) : ptr<bytes>{t}, Proof{}, Header{} {}
            
            bool operator==(const double_entry &t) const;
            bool operator!=(const double_entry &t) const;
            bool operator<=(const double_entry& t) const;
            bool operator>=(const double_entry& t) const;
            bool operator<(const double_entry& t) const;
            bool operator>(const double_entry& t) const;
            
            Bitcoin::output output(uint32) const;
            Bitcoin::input input(uint32) const;
            
            list<Bitcoin::output> outputs() const {
                return operator Bitcoin::transaction().Outputs;
            }
            
            list<Bitcoin::input> inputs() const {
                return operator Bitcoin::transaction().Inputs;
            }
            
            Bitcoin::txid id() const {
                return Bitcoin::transaction::id(this->operator*());
            }
            
            Bitcoin::satoshi sent() const {
                return Bitcoin::transaction(*this).sent();
            }
            
            Bitcoin::timestamp time() const {
                return Header.Timestamp;
            }
            
            explicit operator Bitcoin::transaction() const {
                return Bitcoin::transaction{this->operator*()};
            }
            
        };
        
        virtual data::entry<Bitcoin::txid, double_entry> transaction(const Bitcoin::txid&) const = 0;
        
        // get header by header hash and merkle root.
        virtual block_header header(const digest256&) const = 0; 
        
        // get block by header hash and merkle root. 
        virtual bytes block(const digest256&) const = 0; 
        
        struct edge {
            Bitcoin::output Output;
            Bitcoin::input Input;
        
            bool valid() const {
                return Output.valid() && Input.valid();
            } 
            
            Bitcoin::satoshi spent() const {
                return Output.Value;
            }
        };
        
        struct vertex : public double_entry {
            data::map<Bitcoin::outpoint, Bitcoin::output> Previous;
            
            Bitcoin::satoshi spent() const {
                return data::fold([](Bitcoin::satoshi x, const edge& p) -> Bitcoin::satoshi {
                    return x + p.spent();
                }, Bitcoin::satoshi{0}, incoming_edges());
            }
            
            Bitcoin::satoshi fee() const {
                return spent() - sent();
            }
            
            double fee_per_bytes() const {
                return double(fee()) / double((*this)->size());
            }
            
            bool valid() const;
            
            list<edge> incoming_edges() const {
                list<edge> p;
                list<Bitcoin::input> inputs = double_entry::inputs();
                for (const Bitcoin::input& in : inputs) p = p << edge{Previous[in.Reference], in};
                return p;
            }
            
            vertex(const double_entry& d, data::map<Bitcoin::outpoint, Bitcoin::output> p) : double_entry{d}, Previous{p} {}
            vertex() : double_entry{}, Previous{} {}
            
            edge operator[](index i) {
                struct Bitcoin::input in = double_entry::input(i);
                
                return {Previous[in.Reference], in};
            }
            
            uint32 sigops() const;
        };
        
        vertex make_vertex(const double_entry& d) {
            list<Bitcoin::input> in = d.inputs();
            data::map<Bitcoin::outpoint, Bitcoin::output> p;
            for (const Bitcoin::input& i : in) p = p.insert(i.Reference, transaction(i.Reference.Digest).Value.output(i.Reference.Index));
            return {d, p};
        }
        
        virtual ~ledger() {}
        
    };
    
    struct timechain : ledger {
        
        virtual bool broadcast(const bytes_view&) = 0;
        virtual ~timechain() {}
    };
    
    bool inline ledger::double_entry::operator==(const double_entry &t) const {
        // if the types are valid then checking this proves that they are equal. 
        return Header == t.Header && Proof.index() == t.Proof.index();
    }
    
    bool inline ledger::double_entry::operator!=(const double_entry &t) const {
        return !(*this == t);
    }
    
    bool inline ledger::double_entry::operator<=(const double_entry& t) const {
        if (Header == t.Header) return Proof.index() <= t.Proof.index();
        return Header <= t.Header;
    }
    
    bool inline ledger::double_entry::operator>=(const double_entry& t) const {
        if (Header == t.Header) return Proof.index() >= t.Proof.index();
        return Header >= t.Header;
    }
    
    bool inline ledger::double_entry::operator<(const double_entry& t) const {
        if (Header == t.Header) return Proof.index() < t.Proof.index();
        return Header < t.Header;
    }
    
    bool inline ledger::double_entry::operator>(const double_entry& t) const {
        if (Header == t.Header) return Proof.index() > t.Proof.index();
        return Header > t.Header;
    }
    
    Bitcoin::output inline ledger::double_entry::output(uint32 i) const {
        auto t = Bitcoin::transaction{ptr<bytes>::operator*()};
        if (!t.valid() || t.Outputs.size() <= i) return {};
        return t.Outputs[i];
    }
    
    Bitcoin::input inline ledger::double_entry::input(uint32 i) const {
        auto t = Bitcoin::transaction{ptr<bytes>::operator*()};
        if (!t.valid() || t.Inputs.size() <= i) return {};
        return t.Inputs[i];
    }
    
}

#endif
