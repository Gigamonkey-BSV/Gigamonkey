// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/signature.hpp>
#include <gigamonkey/script/pattern/pay_to_address.hpp>
#include <gigamonkey/wif.hpp>
#include <gigamonkey/script/machine.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    // sighash::all means that all outputs are signed, so none can be changed. 
    // sighash::none means that no outputs are signed, so any can be changed. 
    // sighash::single means that only the output at the same index as the input being evaluated is signed. 
    // sighash::anyone_can_pay means that the inputs are not signed, so they can be changed. 
    // sighash::fork_id was added with Bitcoin Cash and means that OP_CODESEPARATORs are not removed. 
    
    // possible for sighash::none. 
    bool expect_can_mutate_corresponding_output (sighash::directive d) {
        return sighash::base (d) == sighash::none;
    }
    
    // possible for sighash::none and sighash::single. 
    bool expect_can_mutate_other_output (sighash::directive d) {
        return sighash::base (d) != sighash::all;
    }
    
    // possible for sighash::none and sighash::single. 
    bool expect_can_add_input (sighash::directive d) {
        return sighash::is_anyone_can_pay (d);
    }
    
    bool expect_can_add_code_separator (sighash::directive d) {
        return !sighash::has_fork_id (d);
    }
    
    bool expect_can_change_amount (sighash::directive d) {
        return !sighash::has_fork_id (d);
    }
    
    incomplete::transaction add_input (const incomplete::transaction &tx) {
        return incomplete::transaction {tx.Version,
            tx.Inputs << incomplete::input {outpoint {digest256 {uint256 {2}}, 2}},
            tx.Outputs, tx.LockTime};
    }
    
    output mutate (const output &o) {
        return output {o.Value + satoshi {1}, pay_to_address::script (digest160 {pay_to_address (o.Script).Address + 1})};
    }
    
    incomplete::transaction mutate_output (const incomplete::transaction &tx, index i) {
        cross<output> outs;
        for (const output &out : tx.Outputs) outs.push_back (out);
        outs[i] = mutate (outs[i]);
        list<output> new_outs;
        for (const output &out : outs) new_outs <<= out;
        return incomplete::transaction {tx.Version, tx.Inputs, new_outs, tx.LockTime};
    }
    
    sighash::document add_code_separator (const sighash::document &doc) {
        return {doc.Transaction, doc.InputIndex, doc.RedeemedValue, compile (decompile (doc.ScriptCode) << OP_CODESEPARATOR)};
    }
    
    sighash::document change_value (const sighash::document &doc) {
        return {doc.Transaction, doc.InputIndex, doc.RedeemedValue + satoshi {1}, doc.ScriptCode};
    }
    
    TEST (SignatureTest, TestSighash) {
        index input_index = 0;
        satoshi redeemed_value {0xfeee};
        auto scriptx = pay_to_address::script (digest160 {uint160 {"0xdddddddddd000000000000000000006767676791"}});

        incomplete::transaction txi {
            {incomplete::input {
                outpoint {digest256 {uint256 {"0xaa00000000000000000000000000000000000000000000555555550707070707"}}, 0xcdcdcdcd},
                0xfedcba09}}, {
                output {1, pay_to_address::script (digest160 {uint160 {"0xbb00000000000000000000000000006565656575"}})},
                output {2, pay_to_address::script (digest160 {uint160 {"0xcc00000000000000000000000000002929292985"}})}},
            5};

        incomplete::transaction txi_mutate_same_output = mutate_output (txi, input_index);
        incomplete::transaction txi_mutate_different_output = mutate_output (txi, input_index + 1);
        incomplete::transaction txi_added_input = add_input (txi);

        sighash::document doc {txi, input_index, redeemed_value, scriptx};
        sighash::document doc_mutate_same_output {txi_mutate_same_output, input_index, redeemed_value, scriptx};
        sighash::document doc_mutate_different_output {txi_mutate_different_output, input_index, redeemed_value, scriptx};
        sighash::document doc_changed_value = change_value (doc);
        sighash::document doc_added_code_separator = add_code_separator (doc);
        sighash::document doc_added_input {txi_added_input, input_index, redeemed_value, scriptx};
        
        for (sighash::directive directive : list<sighash::directive> {
            directive (sighash::all, false, false),
            directive (sighash::all, true, true),
            directive (sighash::none, true, false),
            directive (sighash::none, true, true),
            directive (sighash::single, false, false),
            directive (sighash::single, false, true)}) {
            
            auto written = sighash::write (doc, directive);
            
            auto mutate_same_output = sighash::write (doc_mutate_same_output, directive);
            auto mutate_different_output = sighash::write (doc_mutate_different_output, directive);
            auto changed_value = sighash::write (doc_changed_value, directive);
            auto added_code_separator = sighash::write (doc_added_code_separator, directive);
            auto added_input = sighash::write (doc_added_input, directive);
            
            if (expect_can_mutate_corresponding_output (directive))
                EXPECT_EQ (written, mutate_same_output);
            else EXPECT_NE (written, mutate_same_output);

            if (expect_can_mutate_other_output (directive))
                EXPECT_EQ (written, mutate_different_output) << "expect \n\t" << written << " to equal \n\t" << mutate_different_output;
            else EXPECT_NE (written, mutate_different_output);
            
            if (expect_can_change_amount (directive))
                EXPECT_EQ (written, changed_value);
            else EXPECT_NE (written, changed_value);
            
            if (expect_can_add_code_separator (directive))
                EXPECT_EQ (written, added_code_separator);
            else EXPECT_NE (written, added_code_separator);
            
            if (expect_can_add_input (directive))
                EXPECT_EQ (written, added_input);
            else EXPECT_NE (written, added_input) << "expect \n\t" << written << " to not equal \n\t" << added_input;
            
            EXPECT_EQ (written, sighash::write (doc, directive));
            EXPECT_EQ (mutate_same_output, sighash::write (doc_mutate_same_output, directive));
            EXPECT_EQ (mutate_different_output, sighash::write (doc_mutate_different_output, directive));
            EXPECT_EQ (changed_value, sighash::write (doc_changed_value, directive));
            EXPECT_EQ (added_input, sighash::write (doc_added_input, directive));

            EXPECT_EQ (Hash256 (written), signature::hash (doc, directive));
            EXPECT_EQ (Hash256 (mutate_same_output), signature::hash (doc_mutate_same_output, directive));
            EXPECT_EQ (Hash256 (mutate_different_output), signature::hash (doc_mutate_different_output, directive));
            EXPECT_EQ (Hash256 (changed_value), signature::hash(doc_changed_value, directive));
            EXPECT_EQ (Hash256 (added_input), signature::hash (doc_added_input, directive));
            
        }
        
    }
    
    TEST (SignatureTest, TestFindAndDelete) {
        
        auto p1 = secp256k1::point (uint256 {123}, uint256 {456});
        auto p2 = secp256k1::point (uint256 {789}, uint256 {101});
        
        auto sig1 = signature (p1, directive (sighash::all));
        auto sig2 = signature (p2, directive (sighash::all));
        
        auto push_sig1 = instruction::push (sig1);
        auto push_sig2 = instruction::push (sig2);
        
        auto sig1p = compile (push_sig1);
        auto sig2p = compile (push_sig2);
        
        auto t1_1 = compile (program {OP_DUP, push_sig1, OP_ROLL});
        auto t1_2 = compile (program {push_sig1, OP_DUP, OP_ROLL});
        auto t1_3 = compile (program {OP_DUP, OP_ROLL, push_sig1});
        auto t1_4 = compile (program {push_sig1, OP_DUP, OP_ROLL, push_sig1});
        auto t1 = compile (program {OP_DUP, OP_ROLL});
        
        EXPECT_TRUE (find_and_delete (t1_1, sig1p) == t1);
        EXPECT_TRUE (find_and_delete (t1_2, sig1p) == t1);
        EXPECT_TRUE (find_and_delete (t1_3, sig1p) == t1);
        EXPECT_TRUE (find_and_delete (t1_4, sig1p) == t1);
        
    }

    TEST (SignatureTest, TestFlags) {
        // compressed pubkey
        // strict encoding
        // invalid sighash
        // fork id
        // DER
        // low S
        // null fail
    }

}


