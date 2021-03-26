// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_LEDGER
#define GIGAMONKEY_LEDGER

#include "timechain.hpp"
#include "spv.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct ledger {
        using block_header = Bitcoin::headers::header;
        
        virtual list<block_header> headers(uint64 since_height) const = 0;
        
        struct double_entry : ptr<bytes> {
            Merkle::proof Proof;
            header Header;
            
            bool valid() const {
                return *this != nullptr && Header.valid();
            }
            
            bool confirmed() const {
                return Proof != Merkle::proof{};
            }
            
            double_entry() : ptr<bytes>{nullptr}, Proof{}, Header{} {}
            
            double_entry(ptr<bytes> t, Merkle::proof p, const header& h) : Proof{p}, Header{h} {}
            
            bool operator<=(const double_entry& t) const;
            bool operator>=(const double_entry& t) const;
            bool operator<(const double_entry& t) const;
            bool operator>(const double_entry& t) const;
            
            Bitcoin::output output(index) const;
            Bitcoin::input input(index) const;
        };
        
        virtual data::entry<txid, double_entry> transaction(const digest256&) const = 0;
        
        // get header by header hash and merkle root.
        virtual block_header header(const digest256&) const = 0; 
        
        // get block by header hash and merkle root. 
        virtual bytes block(const digest256&) const = 0; 
    };
    
    struct timechain : ledger {
        
        virtual bool broadcast(const bytes_view&) = 0;
        
    };
    
    struct input_index {
        bytes_view Transaction;
        index Index;
        
        input_index() : Transaction{}, Index{0} {}
        input_index(bytes_view t, index i) : Transaction{t}, Index{i} {}
        
        bytes_view output() const {
            return transaction::output(Transaction, Index);
        }
        
        bool valid() const {
            return Bitcoin::output{output()}.valid();
        }
        
        satoshi value() const {
            return Bitcoin::output{output()}.Value;
        }
    };
    
    struct prevout {
        data::entry<txid, ledger::double_entry> Previous;
        index Index;
        ledger::double_entry Transaction;
        
        bytes_view output() const {
            return operator input_index().output();
        }
        
        Bitcoin::input input() const {
            return Transaction.input(Index);
        }
        
        bool valid() const {
            Bitcoin::input in = input();
            return in.valid() && Previous.Key == in.Outpoint.Reference && Previous.Value.valid();
        }
        
        satoshi value() const {
            return operator input_index().value();
        }
        
        explicit operator input_index() const {
            return valid() ? input_index{bytes_view{Previous.Value->data(), Previous.Value->size()}, input().Outpoint.Index} : input_index{};
        }
    };
    
}

#endif
