#include <gigamonkey/wallet.hpp>

namespace Gigamonkey::Bitcoin {
    
    wallet::spent wallet::spend(list<payment> payments) const {
        
        if (!valid()) return {};
        
        list<output> outputs = for_each([](payment p) -> output {return output(p);}, payments);
        
        // check if any payment is below dust threshhold. 
        satoshi to_spend = 0;
        size_t outputs_size = 0;
        {
            list<output> op = outputs;
            do {
                satoshi value = op.first().Value;
                if (value < Dust) return {};
                to_spend += value;
                outputs_size += op.first().serialized_size();
            } while (!op.empty());
        }
        
        // can't spend more than we have. 
        if (to_spend > Funds.Value) return {};
        
        ptr<keysource> keys = Keys;
        uint32 num_change_outputs = std::min(21, std::max(1, static_cast<int>(outputs.size()) / 2));
        
        // generate change scripts
        list<change> change{};
        for (int i = 0; i < num_change_outputs; i++) 
            change = change << Change->create_redeemable(keys);
        
        // select outputs to redeem. 
        funds to_redeem;
        funds remainder;
        size_t inputs_size = 0;
        uint32 inputs_sigops = 0;
        satoshi fee;
        switch (Policy) {
            case all: {
                to_redeem = Funds;
                remainder = funds{};
                list<spendable> entries = to_redeem.Entries;
                while (!entries.empty()) {
                    inputs_size += entries.first().Redeemer->expected_size();
                    inputs_sigops += entries.first().Redeemer->sigops();
                    entries = entries.rest();
                }
                break;
            }
            case fifo: {
                remainder = Funds;
                do {
                    funds::selected x = remainder.select_next();
                    inputs_size += x.Selected.Redeemer->expected_size();
                    inputs_sigops += x.Selected.Redeemer->sigops();
                    to_redeem = to_redeem.insert(x.Selected);
                    remainder = x.Remainder;
                    fee = Fee.calculate(inputs_size + outputs_size + 8, inputs_sigops);
                } while (to_redeem.Value < to_spend + fee);
                break;
            }
            case random: {
                remainder = Funds;
                do {
                    funds::selected x = remainder.select_random();
                    inputs_size += x.Selected.Redeemer->expected_size();
                    inputs_sigops += x.Selected.Redeemer->sigops();
                    to_redeem = to_redeem.insert(x.Selected);
                    fee = Fee.calculate(inputs_size + outputs_size + 8, inputs_sigops);
                } while (to_redeem.Value < to_spend + fee);
                break;
            }
            case unset:
                return {}; // can't really happen.
        }
        
        // determine fee.
        satoshi to_keep = to_redeem.Value - to_spend - fee;
        
        // setup outputs.
        // TODO
        
        // add sighash directives (we just use all)
        list<data::entry<spendable, sighash::directive>> redeem_orders = for_each(
            [](spendable s) -> data::entry<spendable, sighash::directive> {
                return {s, sighash::all};
            }, to_redeem.Entries);
        
        // create tx
        ledger::double_entry vx = redeem(redeem_orders, outputs);
        if (!vx.valid()) return {};
        throw 0;
        //return spent{ledger::vertex{vx, }, wallet{remainder, Policy, keys, Fee, Change, Dust}}; // TODO
    }
    
}

