#include <gigamonkey/accounts.hpp>
    
namespace Gigamonkey::Bitcoin {
    
    account account::reduce(const transaction& tx) const {
        // do we know about this tx?
        if (Transactions.contains(tx.Entry.Key)) return *this;
        
        Bitcoin::transaction t{*tx.Entry.Value};
        if (!t.valid()) return {};
        
        account Account{*this};
        Account.Transactions = Account.Transactions.insert(tx.Entry.Key);
        
        list<Bitcoin::input> inputs = t.Inputs;
        
        // attempt to cancel every input against other outputs that are mine. 
        // make a debit for every input that didn't cancel. 
        for (index i = 0; inputs.size() > 0; i++) {
            if (Account.Mine.contains(inputs.first().Outpoint)) 
                Account.Cancellations = Account.Cancellations.insert(inputs.first().Outpoint, tx.Entry.Value);
            else Account.Debits = Account.Debits << data::entry{inputs.first().Outpoint, tx.Entry.Value};
            inputs = inputs.rest();
        }
        
        ordered_list<uint32> Mine = tx.Mine;
        
        // make a credit for every output that isn't mine. 
        for (uint32 i = 0; i < t.Outputs.size(); i++) 
            if (Mine.size() > 0 && Mine.first() == i) {
                Account.Mine = Account.Mine.insert(outpoint{tx.Entry.Key, i}, tx.Entry.Value);
                Mine = Mine.rest();
            } else Account.Credits = Account.Credits << data::entry{outpoint{tx.Entry.Key, i}, tx.Entry.Value};
        
        return Account;
    }
    
    bookkeeping::account<satoshi, timestamp> account::balance(const ledger& l) const {
        list<entry> debits = data::for_each([&l](const data::entry<outpoint, ledger::double_entry>& o) -> entry {
            return debit(prevout{l.transaction(o.Key.Reference), o.Key.Index, o.Value});
        }, Debits);
        
        list<entry> credits = data::for_each([](const data::entry<outpoint, ledger::double_entry>& o) -> entry {
            return credit(o.Value, o.Key.Index);
        }, Credits);
        
        bookkeeping::account<satoshi, timestamp> x{};
        
        for (const entry& e : debits) x.Entries = x.Entries << e;
        for (const entry& e : credits) x.Entries = x.Entries << e;
        
        return x;
    }
}

