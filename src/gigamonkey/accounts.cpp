#include <gigamonkey/accounts.hpp>
    
namespace Gigamonkey::Bitcoin {
    
    account account::reduce(const event& tx) const {
        txid id{tx.id()};
        
        // do we know about this tx?
        if (Transactions.contains(id)) return *this;
        
        Bitcoin::transaction t{*tx};
        if (!t.valid()) return {};
        
        account Account{*this};
        Account.Transactions = Account.Transactions.insert(id);
        
        list<Bitcoin::input> inputs = t.Inputs;
        
        // attempt to cancel every input against other outputs that are mine. 
        // make a debit for every input that didn't cancel. 
        //
        // this means that events must be given in order. 
        ordered_list<index> debits{};
        
        for (index i = 0; inputs.size() > 0; i++) {
            if (Account.Mine.contains(inputs.first().Outpoint)) 
                Account.Cancellations = Account.Cancellations.insert(inputs.first().Outpoint, tx);
            else debits.insert(i);
            inputs = inputs.rest();
        }
        
        Account.Debits = Account.Debits.insert(tx, debits);
        
        ordered_list<uint32> Mine = tx.Mine;
        
        // make a credit for every output that isn't mine. 
        ordered_list<index> credits{};
        
        for (uint32 i = 0; i < t.Outputs.size(); i++) {
            if (Mine.size() > 0 && Mine.first() == i) {
                Account.Mine = Account.Mine.insert(outpoint{id, i}, tx);
                Mine = Mine.rest();
            } else credits = credits.insert(i);
        }
        
        Account.Credits = Account.Credits.insert(tx, credits);
        
        return Account;
    }
    /*
    bookkeeping::account<satoshi, timestamp> account::balance(const ledger& l) const {
        list<entry> debits = data::for_each([](const outpoint& o) -> entry {
            return debit(o.Value[o.]);
        }, Debits);
        
        list<entry> credits = data::for_each([](const outpoint& o) -> entry {
            return credit(o.Value, o.Key.Index);
        }, Credits);
        
        bookkeeping::account<satoshi, timestamp> x{};
        
        for (const entry& e : debits) x.Entries = x.Entries << e;
        for (const entry& e : credits) x.Entries = x.Entries << e;
        
        return x;
    }*/
}

