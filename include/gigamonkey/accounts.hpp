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
    
namespace Gigamonkey {
    
    struct account {
        using entry = bookkeeping::entry<Bitcoin::satoshi, Bitcoin::timestamp>;
        
        struct prevout : ledger::double_entry {
            data::entry<Bitcoin::txid, ledger::double_entry> Previous;
            index InputIndex;
            
            Bitcoin::input input() const {
                return ledger::double_entry::input(InputIndex);
            }
            
            bool valid() const {
                return Previous.Key == input().Reference.Digest;
            }
        };
        
        // we use a bitcoin output as a credit. 
        static entry credit(const ledger::double_entry& tx, const index i) {
            return entry{tx.output(i).Value, tx.Header.Timestamp};
        } 
        
        // we use an input + output as a debit. 
        static entry debit(const prevout &v) {
            return entry{v.Previous.Value.output(v.input().Reference.Index).Value, v.Previous.Value.Header.Timestamp};
        } 
        
        struct event : public ledger::vertex {
            
            // outputs marked as belonging to me. 
            ordered_list<uint32> Mine;
            
            // the outpoints of all my outputs. 
            stack<Bitcoin::outpoint> output_outpoints() const;
            
            event() : ledger::vertex{}, Mine{} {}
            event(const ledger::vertex& p, ordered_list<uint32> m) : ledger::vertex{p}, Mine{m} {}

        };
        
        // the transactions that are in this account. 
        data::set<Bitcoin::txid> Transactions;
        
        // the outputs that belong to me. 
        data::map<Bitcoin::outpoint, event> Mine;
        
        // the outputs belonging to me that have been cancelled. 
        data::map<Bitcoin::outpoint, event> Cancellations;
        
        data::map<ledger::double_entry, ordered_list<index>> Debits;
        data::map<event, ordered_list<index>> Credits;
        
        account(priority_queue<event> txs) : account{account{}.reduce(txs)} {}
        account() : Mine{}, Debits{}, Credits{} {}
        
        bookkeeping::account<Bitcoin::satoshi, Bitcoin::timestamp> balance(const ledger& l) const;
        
    private:
        account reduce(const event& tx) const;
        
        account reduce(priority_queue<event> txs) const {
            if (txs.empty()) return *this;
            return data::fold([](const account& a, const event& e) -> account {
                return a.reduce(e);
            }, account{}, txs);
            return reduce(txs.first()).reduce(txs.rest());
        }
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
