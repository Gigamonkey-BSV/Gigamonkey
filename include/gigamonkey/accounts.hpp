// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_ACCOUNTS
#define GIGAMONKEY_ACCOUNTS

#include "ledger.hpp"

namespace Gigamonkey::bookkeeping {
    
    template <typename amount, typename time>
    struct entry {
        amount Value;
        time Time;
        
        bool operator<(const entry &) const;
        bool operator>(const entry &) const;
        bool operator<=(const entry &) const;
        bool operator>=(const entry &) const;
        
    };
    
    template <typename amount, typename time>
    std::ostream inline &operator<<(std::ostream &o, const entry<amount, time> &e) {
        return o << "entry{Time: " << e.Time << ", Value: " << e.Value << "}";
    }
    
    template <typename Amount, typename Time>
    struct account {
        ordered_list<entry<Amount, Time>> Entries;
        
        ordered_list<entry<Amount, Time>> debits() const {
            return data::select(Entries, [](const entry<Amount, Time>& e) -> bool {
                return e.Value > 0;
            });
        }
        
        ordered_list<entry<Amount, Time>> credits() const {
            return data::select(Entries, [](const entry<Amount, Time>& e) -> bool {
                return e.Value < 0;
            });
        }
        
        Amount value() const {
            if (Entries.size() == 0) return 0;
            return Entries.first().value() + account{Entries.rest()}.value();
        }
    };
}
    
namespace Gigamonkey::Bitcoin {
    
    struct account {
        using entry = bookkeeping::entry<satoshi, timestamp>;
        
        // we use a bitcoin output as a credit. 
        static entry credit(const ledger::double_entry& tx, const index i) {
            return entry{-input_index{*tx, i}.value(), tx.Header.Timestamp};
        } 
        
        // we use an input + output as a debit. 
        static entry debit(const prevout &p) {
            return entry{p.value(), p.Transaction.Header.Timestamp};
        } 
        
        // the transactions that are in this account. 
        data::set<txid> Transactions;
        
        // the outputs that belong to me. 
        data::map<outpoint, ledger::double_entry> Mine;
        
        // the outputs belonging to me that have been cancelled. 
        data::map<outpoint, ledger::double_entry> Cancellations;
        
        list<data::entry<outpoint, ledger::double_entry>> Debits;
        list<data::entry<outpoint, ledger::double_entry>> Credits;
        
        struct transaction {
            data::entry<txid, ledger::double_entry> Entry;
            ordered_list<index> Mine;
            
            // the outpoints of the redeeming txs. 
            stack<outpoint> prevouts() const;
            
            // the outpoints of all my outputs. 
            stack<outpoint> outpoints() const;
            
            transaction();
            transaction(data::entry<txid, ledger::double_entry> e, ordered_list<index> m) : Entry{e}, Mine{m} {}
        };
        
        account reduce(const transaction& tx) const;
        
        account reduce(stack<transaction> txs) const {
            if (txs.empty()) return *this;
            return reduce(txs.first()).reduce(txs.rest());
        }
        
        account(stack<transaction> txs) : account{account{}.reduce(txs)} {}
        account() : Mine{}, Debits{}, Credits{} {}
        
        bookkeeping::account<satoshi, timestamp> balance(const ledger& l) const;
        
    };
}

namespace Gigamonkey::bookkeeping {
        
    template <typename amount, typename time>
    bool inline entry<amount, time>::operator<(const entry &e) const {
        return Time < e.Time;
    }
    
    template <typename amount, typename time>
    bool inline entry<amount, time>::operator>(const entry &e) const {
        return Time > e.Time;
    }
    
    template <typename amount, typename time>
    bool inline entry<amount, time>::operator<=(const entry &e) const {
        return Time <= e.Time;
    }
    
    template <typename amount, typename Time>
    bool inline entry<amount, Time>::operator>=(const entry &e) const {
        return Time >= e.Time;
    }
}

#endif
