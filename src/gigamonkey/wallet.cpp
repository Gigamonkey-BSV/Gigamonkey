// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/wallet.hpp>
#include <math.h>

namespace Gigamonkey {
    
    wallet::spent wallet::spend(satoshi_per_byte fee_rate, list<Bitcoin::output> payments) const {
        using namespace Bitcoin;
        if (!valid()) return {};
        
        satoshi to_spend = 0;
        transaction_data_type outputs_size{0, 0};
        
        for (const output& p : payments) {
            outputs_size.count_output_script(p.Script);
            satoshi value = p.Value;
            // check if any payment is below dust threshhold. 
            if (value < Dust) return {};
            to_spend += value;
        }
        
        // can't spend more than we have. 
        if (to_spend > Funds.Value) return {};
        
        ptr<keysource> keys = Keys;
        
        // we only do on change output for now. 
        uint32 num_change_outputs = 1; //std::min(21, std::max(1, static_cast<int>(outputs.size()) / 2));
        
        // generate change scripts
        list<change> change_scripts{};
        for (int i = 0; i < num_change_outputs; i++) {
            change_scripts = change_scripts << Change->create_redeemable(keys);
            outputs_size.count_output_script(change_scripts.first().OutputScript);
        }
        
        // we use this to count the size of the tx as we build it. 
        transaction_data_type in_progress_tx_size_count = outputs_size;
        // we add the length of the outputs, locktime, and version. 
        in_progress_tx_size_count.Standard += 8 + var_int::size(payments.size() + change_scripts.size());
         
        funds to_redeem;
        list<spendable> remainder;
        satoshi tx_fee{0};
        
        // select outputs to redeem.
        { 
            switch (Policy) {
                case all: {
                    to_redeem = Funds;
                    list<spendable> entries = to_redeem.Entries;
                    while (!entries.empty()) {
                        in_progress_tx_size_count.count_input_script(entries.first().Redeemer->expected_size());
                        entries = entries.rest();
                    }
                    in_progress_tx_size_count.Standard += var_int::size(entries.size());
                    tx_fee = fee_rate * in_progress_tx_size_count;
                    break;
                }
                case fifo: {
                    remainder = Funds.Entries;
                    do {
                        spendable x = remainder.first();
                        remainder = remainder.rest();
                        in_progress_tx_size_count.count_input_script(x.Redeemer->expected_size());
                        to_redeem = to_redeem.insert(x);
                        tx_fee = fee_rate * (in_progress_tx_size_count + transaction_data_type{0, var_int::size(to_redeem.Entries.size())});
                    } while (to_redeem.Value < to_spend + tx_fee + Dust);
                    break;
                }
                case random: {
                    remainder = Funds.Entries;
                    do {
                        remainder = rotate_left(remainder, 
                            std::uniform_int_distribution<int>(0, remainder.size() - 1)(data::get_random_engine()));
                        spendable x = remainder.first();
                        remainder = remainder.rest();
                        in_progress_tx_size_count.count_input_script(x.Redeemer->expected_size());
                        to_redeem = to_redeem.insert(x);
                        tx_fee = fee_rate * (in_progress_tx_size_count + transaction_data_type{0, var_int::size(to_redeem.Entries.size())});
                    } while (to_redeem.Value < to_spend + tx_fee + Dust);
                    break;
                }
                case unset:
                    return {}; 
            }
        }
        
        // determine change output
        satoshi to_keep = to_redeem.Value - to_spend - tx_fee;
        
        // setup outputs.
        if (change_scripts.size() != 1) throw "we don't know how to do multiple change outputs yet.";
        
        // these will be the new funds that will appear in our wallet. 
        funds new_funds;
        list<output> outputs;
        
        {
            // here is our change output. 
            output change_output{to_keep, change_scripts.first().OutputScript};
            
            // We shuffle the outputs and remember which one belongs
            // to us by finding those which have a redeemer. 
            list<spendable> incomplete_outputs = shuffle<list<spendable>>(for_each([](const output& o) -> spendable {
                // we don't know our own txid yet, so can't fill in the outpoint. 
                return spendable{ledger::prevout{outpoint{}, o}, nullptr};
            }, payments) << spendable{ledger::prevout{outpoint{}, change_output}, change_scripts.first().Redeemer});
            
            index i = 0;
            for(const spendable& x : incomplete_outputs) {
                if (x.Redeemer != nullptr) new_funds = 
                    new_funds.insert(spendable{ledger::prevout{outpoint{{}, i}, x.Previous.Value}, x.Redeemer});
                outputs = outputs << x.Previous.Value;
                i++;
            };
        
        }
        
        // finally, we create tx
        ledger::vertex vx = redeem(to_redeem.Entries, spend_instructions{input::Finalized, sighash::all | sighash::fork_id}, outputs);
        if (!vx.valid()) return {};
        
        return spent{vx, new_funds, wallet{remainder, Policy, keys, Fee, Change, Dust}}; 
    }
    
}

