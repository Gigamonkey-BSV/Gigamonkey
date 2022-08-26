// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/signature.hpp>
#include <gigamonkey/script/pattern.hpp>
#include <gigamonkey/wif.hpp>
#include <gigamonkey/script/machine.hpp>
#include <sv/script/script.h>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    // sighash::all means that all outputs are signed, so none can be changed. 
    // sighash::none means that no outputs are signed, so any can be changed. 
    // sighash::single means that only the output at the same index as the input being evaluated is signed. 
    // sighash::anyone_can_pay means that the inputs are not signed, so they can be changed. 
    // sighash::fork_id was added with Bitcoin Cash and means that OP_CODESEPARATORs are not removed. 
    
    // possible for sighash::none. 
    bool expect_can_mutate_corresponding_output(sighash::directive d) {
        return sighash::base(d) == sighash::none;
    }
    
    // possible for sighash::none and sighash::single. 
    bool expect_can_mutate_other_output(sighash::directive d) {
        return sighash::base(d) != sighash::all;
    }
    
    // possible for sighash::none and sighash::single. 
    bool expect_can_add_input(sighash::directive d) {
        return sighash::is_anyone_can_pay(d);
    }
    
    bool expect_can_add_code_separator(sighash::directive d) {
        return !sighash::has_fork_id(d);
    }
    
    bool expect_can_change_amount(sighash::directive d) {
        return !sighash::has_fork_id(d);
    }
    
    sighash::document add_input(const sighash::document& doc) {
        sighash::document x = doc;
        x.Transaction.Inputs <<= incomplete::input{outpoint{digest256{uint256{2}}, 2}};
        return x;
    }
    
    output mutate(const output& o) {
        return output{o.Value + satoshi{1}, pay_to_address::script(digest160{pay_to_address(o.Script).Address + 1})};
    }
    
    sighash::document mutate_output(const sighash::document& doc, index i) {
        sighash::document x = doc;
        cross<output> outs;
        for (const output &out : x.Transaction.Outputs) outs.push_back(out);
        outs[i] = mutate(outs[i]);
        list<output> new_outs;
        for (const output &out : outs) new_outs <<= out;
        x.Transaction.Outputs = new_outs;
        return x;
    }
    
    sighash::document add_code_separator(const sighash::document& doc) {
        return {doc.RedeemedValue, compile(decompile(doc.ScriptCode) << OP_CODESEPARATOR), doc.Transaction, doc.InputIndex};
    }
    
    sighash::document change_value(const sighash::document& doc) {
        return {doc.RedeemedValue + satoshi{1}, doc.ScriptCode, doc.Transaction, doc.InputIndex};
    }
    
    TEST(SignatureTest, TestSighash) {
        
        sighash::document doc{
            satoshi{0xfeee}, 
            pay_to_address::script(digest160{uint160{"0xdddddddddd000000000000000000006767676791"}}), 
            incomplete::transaction{
                {incomplete::input{
                    outpoint{digest256{uint256{"0xaa00000000000000000000000000000000000000000000555555550707070707"}}, 0xcdcdcdcd}, 0xfedcba09}}, {
                    output{1, pay_to_address::script(digest160{uint160{"0xbb00000000000000000000000000006565656575"}})}, 
                    output{2, pay_to_address::script(digest160{uint160{"0xcc00000000000000000000000000002929292985"}})}}, 
                5}, 0};
        
        auto doc_mutate_same_output = mutate_output(doc, doc.InputIndex);
        auto doc_mutate_different_output = mutate_output(doc, doc.InputIndex + 1);
        auto doc_changed_value = change_value(doc);
        auto doc_added_code_separator =add_code_separator(doc);
        auto doc_added_input = add_input(doc);
        
        for (sighash::directive directive : list<sighash::directive>{
            directive(sighash::all, false, false), 
            directive(sighash::all, true, true), 
            directive(sighash::none, true, false), 
            directive(sighash::single, false, true)}) {
            
            auto written = sighash::write(doc, directive);
            
            auto mutate_same_output = sighash::write(doc_mutate_same_output, directive);
            auto mutate_different_output = sighash::write(doc_mutate_different_output, directive);
            auto changed_value = sighash::write(doc_changed_value, directive);
            auto added_code_separator = sighash::write(doc_added_code_separator, directive);
            auto added_input = sighash::write(doc_added_input, directive);
            
            if (expect_can_mutate_corresponding_output(directive)) 
                EXPECT_EQ(written, mutate_same_output);
            else EXPECT_NE(written, mutate_same_output);
            
            if (expect_can_mutate_other_output(directive)) 
                EXPECT_EQ(written, mutate_different_output) << "expect \n\t" << written << " to equal \n\t" << mutate_different_output;
            else EXPECT_NE(written, mutate_different_output);
            
            if (expect_can_change_amount(directive)) 
                EXPECT_EQ(written, changed_value);
            else EXPECT_NE(written, changed_value);
            
            if (expect_can_add_code_separator(directive)) 
                EXPECT_EQ(written, added_code_separator);
            else EXPECT_NE(written, added_code_separator);
            
            if (expect_can_add_input(directive)) 
                EXPECT_EQ(written, added_input);
            else EXPECT_NE(written, added_input) << "expect \n\t" << written << " to not equal \n\t" << added_input;
            
            EXPECT_EQ(written, sighash::write(doc, directive));
            EXPECT_EQ(mutate_same_output, sighash::write(doc_mutate_same_output, directive));
            EXPECT_EQ(mutate_different_output, sighash::write(doc_mutate_different_output, directive));
            EXPECT_EQ(changed_value, sighash::write(doc_changed_value, directive));
            EXPECT_EQ(added_input, sighash::write(doc_added_input, directive));
            
            EXPECT_EQ(Hash256(written), signature::hash(doc, directive));
            EXPECT_EQ(Hash256(mutate_same_output), signature::hash(doc_mutate_same_output, directive));
            EXPECT_EQ(Hash256(mutate_different_output), signature::hash(doc_mutate_different_output, directive));
            EXPECT_EQ(Hash256(changed_value), signature::hash(doc_changed_value, directive));
            EXPECT_EQ(Hash256(added_input), signature::hash(doc_added_input, directive));
            
        }
        
    }
    
    TEST(SignatureTest, TestFindAndDelete) {
        
        auto p1 = secp256k1::point(uint256{123}, uint256{456});
        auto p2 = secp256k1::point(uint256{789}, uint256{101});
        
        auto sig1 = signature(p1, directive(sighash::all));
        auto sig2 = signature(p2, directive(sighash::all));
        
        auto push_sig1 = instruction::push(sig1);
        auto push_sig2 = instruction::push(sig2);
        
        auto sig1p = compile(push_sig1);
        auto sig2p = compile(push_sig2);
        
        auto t1_1 = compile(program{OP_DUP, push_sig1, OP_ROLL});
        auto t1_2 = compile(program{push_sig1, OP_DUP, OP_ROLL});
        auto t1_3 = compile(program{OP_DUP, OP_ROLL, push_sig1});
        auto t1_4 = compile(program{push_sig1, OP_DUP, OP_ROLL, push_sig1});
        auto t1 = compile(program{OP_DUP, OP_ROLL});
        
        EXPECT_TRUE(interpreter::find_and_delete(t1_1, sig1p) == t1);
        EXPECT_TRUE(interpreter::find_and_delete(t1_2, sig1p) == t1);
        EXPECT_TRUE(interpreter::find_and_delete(t1_3, sig1p) == t1);
        EXPECT_TRUE(interpreter::find_and_delete(t1_4, sig1p) == t1);
        
        auto xsig1 = CScript(sig1);
        auto xsig2 = CScript(sig2);
        
        auto x1_1 = CScript(t1_1.begin(), t1_1.end());
        auto x1_2 = CScript(t1_2.begin(), t1_2.end());
        auto x1_3 = CScript(t1_3.begin(), t1_3.end());
        auto x1_4 = CScript(t1_4.begin(), t1_4.end());
        auto x1 = CScript(t1.begin(), t1.end());
        
        x1_1.FindAndDelete(xsig1);
        x1_2.FindAndDelete(xsig1);
        x1_3.FindAndDelete(xsig1);
        x1_4.FindAndDelete(xsig1);
        
        EXPECT_TRUE(x1_1 == x1) << x1_1 << " vs " << x1;
        EXPECT_TRUE(x1_2 == x1) << x1_2 << " vs " << x1;
        EXPECT_TRUE(x1_3 == x1) << x1_3 << " vs " << x1;
        EXPECT_TRUE(x1_4 == x1) << x1_4 << " vs " << x1;
        
    }

}


