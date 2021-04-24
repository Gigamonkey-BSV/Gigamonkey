#include <gigamonkey/wallet.hpp>

namespace Gigamonkey::Bitcoin {
    
    satoshi operator*(satoshi_per_byte v, uint64 size) {
        if (v.Bytes == 0) throw data::math::division_by_zero{};
        if (v.Bytes == 1) return v.Satoshis * size;
        satoshi n = v.Satoshis * size;
        return n / v.Bytes + (n % v.Bytes == 0 ? 0 : 1);
    }
    
    struct transaction_data_type {
        uint64 Data;
        uint64 Standard;
        
        void count_output_script(const script& x) {
            (is_op_return(x) ? Data : Standard) += x.size();
            Standard += writer::var_int_size(x.size()) + 4;
        }
        
        void count_input_script(const uint64 script_size) {
            Standard += script_size + writer::var_int_size(script_size) + 40;
        }
    };
    
    satoshi operator*(fee v, transaction_data_type d) {
        return v.Data * d.Data + v.Standard * d.Standard;
    }
    
    wallet::spent wallet::spend(list<output> payments) const {
        
        if (!valid()) return {};
        satoshi to_spend = 0;
        transaction_data_type outputs_size{0, 0};
        
        list<output> outputs;
        
        for (const output& p : payments) {
            outputs = outputs << p;
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
        
        transaction_data_type incomplete_tx_size = outputs_size;
        incomplete_tx_size.Standard += 8 + writer::var_int_size(outputs.size() + change_scripts.size());
         
        funds to_redeem;
        funds remainder;
        satoshi tx_fee{0};
        
        // select outputs to redeem.
        { 
            switch (Policy) {
                case all: {
                    to_redeem = Funds;
                    remainder = funds{};
                    list<spendable> entries = to_redeem.Entries;
                    while (!entries.empty()) {
                        incomplete_tx_size.count_input_script(entries.first().Redeemer->expected_size());
                        entries = entries.rest();
                    }
                    tx_fee = Fee * incomplete_tx_size;
                    break;
                }
                case fifo: {
                    remainder = Funds;
                    do {
                        spendable x = Funds.Entries.first();
                        incomplete_tx_size.count_input_script(x.Redeemer->expected_size());
                        to_redeem = to_redeem.insert(x);
                        remainder = funds{}.insert(Funds.Entries.rest());
                        tx_fee = Fee * incomplete_tx_size;
                    } while (to_redeem.Value < to_spend + tx_fee + Dust);
                    break;
                }
                case random: {/*
                    remainder = Funds;
                    do {
                        std::uniform_int_distribution<uint32>(0, funds.Entries.size() - 1);
                        spendable x = remainder.select_random();
                        inputs_size += x.Selected.Redeemer->expected_size();
                        inputs_sigops += x.Selected.Redeemer->sigops();
                        to_redeem = to_redeem.insert(x.Selected);
                        fee = Fee.calculate(inputs_size + outputs_size + 8, inputs_sigops);
                    } while (to_redeem.Value < to_spend + fee);
                    break;*/
                }
                case unset:
                    return {}; 
            }
        }
        
        // determine change output
        satoshi to_keep = to_redeem.Value - to_spend - tx_fee;
        
        // setup outputs.
        if (change_scripts.size() != 1) throw "we don't know how to do multiple change outputs yet.";
        
        funds new_funds;
        
        {
        
            output change_output{to_keep, change_scripts.first().OutputScript};
            
            list<spendable> incomplete_outputs = data::functional::list::shuffle<list<spendable>>(for_each([](const output& o) -> spendable {
                return spendable{o, nullptr, outpoint{}};
            }, outputs) << spendable{change_output, change_scripts.first().Redeemer, outpoint{}});
            
            outputs = {};
            
            index i = 0;
            for(const spendable& x : incomplete_outputs) {
                if (x.Redeemer != nullptr) new_funds = new_funds.insert(spendable{static_cast<output>(x), x.Redeemer, outpoint{{}, i}});
                else outputs = outputs << static_cast<output>(x);
                i++;
            };
        
        }
        
        // add sighash directives and finalize all input directives
        // we could do a lot more with this. Someday! 
        list<data::entry<spendable, sighash::directive>> redeem_orders = for_each(
            [](spendable s) -> data::entry<spendable, sighash::directive> {
                spendable z = s;
                z.Sequence = input::Finalized;
                return {s, sighash::all};
            }, to_redeem.Entries);
        
        // create tx
        ptr<bytes> vx = redeem(redeem_orders, outputs);
        if (vx != nullptr) return {};
        
        return spent{vx, new_funds, wallet{remainder, Policy, keys, Fee, Change, Dust}}; 
    }
    
}

