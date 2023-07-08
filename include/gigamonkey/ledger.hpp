// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_LEDGER
#define GIGAMONKEY_LEDGER

#include "spv.hpp"
#include <gigamonkey/script/script.hpp>

namespace Gigamonkey::Bitcoin {
        
    struct prevout : data::entry<Bitcoin::outpoint, Bitcoin::output> {
        using data::entry<Bitcoin::outpoint, Bitcoin::output>::entry;
        
        Bitcoin::outpoint outpoint () const {
            return this->Key;
        }
        
        Bitcoin::satoshi value () const {
            return this->Value.Value;
        }
        
        bytes script () const {
            return this->Value.Script;
        }
    };
}

namespace Gigamonkey {
    
    struct ledger {
        using block_header = Gigamonkey::headers::header;
        
        virtual list<block_header> headers (uint64 since_height) = 0;
        
        struct confirmation {
            Merkle::proof Proof;
            Bitcoin::header Header;
            
            confirmation () : Proof {}, Header {} {}
            
            // for a confirmed transaction. 
            confirmation (Merkle::proof p, const Bitcoin::header &h): Proof {p}, Header {h} {}
            
            bool operator == (const confirmation &t) const;
            bool operator != (const confirmation &t) const;
            bool operator <= (const confirmation& t) const;
            bool operator >= (const confirmation& t) const;
            bool operator < (const confirmation& t) const;
            bool operator > (const confirmation& t) const;
            
            Bitcoin::txid id () const {
                return Proof.Branch.Leaf.Digest;
            }
            
            Bitcoin::timestamp time () const {
                return Header.Timestamp;
            }
            
        };
        
        virtual data::entry<bytes, confirmation> transaction (const Bitcoin::txid &) const = 0;
        
        // get header by header hash and merkle root.
        virtual block_header header (const digest256 &) const = 0;
        
        // get block by header hash and merkle root. 
        virtual bytes block (const digest256 &) const = 0;
        
        struct edge {
            Bitcoin::output Output;
            Bitcoin::input Input;
        
            bool valid () const {
                return Output.valid () && Input.valid ();
            } 
            
            Bitcoin::satoshi spent () const {
                return Output.Value;
            }
        };
        
        struct vertex : public Bitcoin::transaction {
            data::map<Bitcoin::outpoint, Bitcoin::output> Previous;
            
            Bitcoin::satoshi spent () const {
                return data::fold([] (Bitcoin::satoshi x, const edge &p) -> Bitcoin::satoshi {
                    return x + p.spent ();
                }, Bitcoin::satoshi {0}, incoming_edges ());
            }
            
            Bitcoin::satoshi fee () const {
                return spent () - sent ();
            }
            
            double fee_rate () const {
                return double (fee ()) / double (this->serialized_size ());
            }
            
            bool valid () const;
            
            list<edge> incoming_edges () const {
                list<edge> p;
                list<Bitcoin::input> inputs = this->Inputs;
                for (const Bitcoin::input& in : inputs) p = p << edge {Previous[in.Reference], in};
                return p;
            }
            
            vertex (const Bitcoin::transaction &d, data::map<Bitcoin::outpoint, Bitcoin::output> p) :
                Bitcoin::transaction {d}, Previous {p} {}
            vertex () : Bitcoin::transaction {}, Previous {} {}
            
            edge operator [] (index i) {
                struct Bitcoin::input in = this->Inputs [i];
                
                return {Previous[in.Reference], in};
            }
        };
        
        vertex make_vertex (const Bitcoin::transaction& d) {
            list<Bitcoin::input> in = d.Inputs;
            data::map<Bitcoin::outpoint, Bitcoin::output> p;
            for (const Bitcoin::input& i : in) p = 
                p.insert (i.Reference,
                    Bitcoin::output {Bitcoin::transaction::output (transaction (i.Reference.Digest).Key, i.Reference.Index)});
            return {d, p};
        }
        
        virtual ~ledger () {}
        
    };
    
    struct timechain : ledger {
        
        virtual bool broadcast (const bytes_view&) = 0;
        virtual ~timechain () {}
    };
    
    bool inline ledger::confirmation::operator == (const confirmation &t) const {
        // if the types are valid then checking this proves that they are equal. 
        return Header == t.Header && Proof.index () == t.Proof.index ();
    }
    
    bool inline ledger::confirmation::operator != (const confirmation &t) const {
        return !(*this == t);
    }
    
    bool inline ledger::confirmation::operator <= (const confirmation &t) const {
        if (Header == t.Header) return Proof.index () <= t.Proof.index ();
        return Header <= t.Header;
    }
    
    bool inline ledger::confirmation::operator >= (const confirmation &t) const {
        if (Header == t.Header) return Proof.index () >= t.Proof.index ();
        return Header >= t.Header;
    }
    
    bool inline ledger::confirmation::operator < (const confirmation &t) const {
        if (Header == t.Header) return Proof.index () < t.Proof.index ();
        return Header < t.Header;
    }
    
    bool inline ledger::confirmation::operator > (const confirmation &t) const {
        if (Header == t.Header) return Proof.index () > t.Proof.index ();
        return Header > t.Header;
    }
    
}

#endif
