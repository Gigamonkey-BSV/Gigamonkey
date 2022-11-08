// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/script/pattern/pay_to_address.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/script/machine.hpp>
#include <data/crypto/NIST_DRBG.hpp>
#include <data/encoding/hex.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {
    
    TEST(ScriptTest, TestP2SH) {
    }
    
    TEST(ScriptTest, TestPush) {
    }
    
    TEST(ScriptTest, TestBitShift) {
    }
    
    TEST(ScriptTest, TestBin2Num2Bin) {
    }
    
    bytes multisig_script(const redemption_document &doc, list<secp256k1::secret> s, list<secp256k1::pubkey> p, const instruction &null_push) {
        program mp;
        mp <<= push_data(s.size());
        for (const secp256k1::pubkey &pk : p) mp <<= push_data(pk);
        mp <<= push_data(p.size());
        mp <<= OP_CHECKMULTISIGVERIFY;
        
        sighash::document sd = doc.add_script_code(compile(mp));
        
        program ms;
        ms <<= null_push;
        for (const secp256k1::secret &sk : s) ms <<= push_data(signature::sign(sk, sighash::all, sd));
        ms <<= OP_CODESEPARATOR;
        return compile(ms + mp);
    }
    
    bytes multisig_script(const redemption_document &doc, list<secp256k1::secret> s, list<secp256k1::pubkey> p) {
        return multisig_script(doc, s, p, OP_0);
    }
    
    TEST(SignatureTest, TestMultisig) {
        
        redemption_document doc{
            satoshi{0xfeee}, 
            incomplete::transaction{
                {incomplete::input{
                    outpoint{digest256{uint256{"0xaa00000000000000000000000000000000000000000000555555550707070707"}}, 0xcdcdcdcd}, 0xfedcba09}}, {
                    output{1, pay_to_address::script(digest160{uint160{"0xbb00000000000000000000000000006565656575"}})}, 
                    output{2, pay_to_address::script(digest160{uint160{"0xcc00000000000000000000000000002929292985"}})}}, 
                5}, 0};
        
        auto k1 = secp256k1::secret(uint256{123456});
        auto k2 = secp256k1::secret(uint256{789012});
        auto k3 = secp256k1::secret(uint256{345678});
        
        auto p1 = k1.to_public();
        auto p2 = k2.to_public();
        auto p3 = k3.to_public();
        
        struct multisig_test {
            int Number;
            bool Expected;
            redemption_document Doc;
            bytes Test;
            
            result run() {
                return evaluate({}, Test, Doc, 0);
            }
            
            void test() {
                result r = run();
                EXPECT_EQ(bool(r), Expected) << Number << ": script " << decompile(Test) << " expect " << Expected << "; results in " << r;
            }
            
            multisig_test(int num, bool ex, const redemption_document &doc, list<secp256k1::secret> s, list<secp256k1::pubkey> p) : 
                Number{num}, Expected{ex}, Doc{doc}, Test{multisig_script(doc, s, p)} {}
        };
        
        multisig_test{10,  true,  doc, {},           {}          }.test();
        multisig_test{20,  false, doc, {k1},         {}          }.test();
        multisig_test{30,  true,  doc, {},           {p1}        }.test();
        multisig_test{40,  true,  doc, {k1},         {p1}        }.test();
        multisig_test{50,  false, doc, {k2},         {p1}        }.test();
        multisig_test{60,  true,  doc, {},           {p1, p2}    }.test();
        multisig_test{70,  true,  doc, {k1},         {p1, p2}    }.test();
        multisig_test{80,  false, doc, {k3},         {p1, p2}    }.test();
        multisig_test{90,  true,  doc, {k1, k2},     {p1, p2}    }.test();
        multisig_test{100, false, doc, {k2, k1},     {p1, p2}    }.test();
        multisig_test{110, false, doc, {k1, k3},     {p1, p2}    }.test();
        multisig_test{120, false, doc, {k2, k3},     {p1, p2}    }.test();
        multisig_test{130, true,  doc, {},           {p1, p2, p3}}.test();
        multisig_test{140, true,  doc, {k1},         {p1, p2, p3}}.test();
        multisig_test{150, true,  doc, {k2},         {p1, p2, p3}}.test();
        multisig_test{160, true,  doc, {k3},         {p1, p2, p3}}.test();
        multisig_test{170, true,  doc, {k1, k3},     {p1, p2, p3}}.test();
        multisig_test{180, false, doc, {k3, k1},     {p1, p2, p3}}.test();
        multisig_test{190, true,  doc, {k1, k2, k3}, {p1, p2, p3}}.test();
        multisig_test{200, false, doc, {k3, k2, k1}, {p1, p2, p3}}.test();
        multisig_test{210, false, doc, {k2, k3, k1}, {p1, p2, p3}}.test();
        
        // TODO test that not adding the prefix fails
        // TODO test that adding a different prefix fails for the right flags. 
        // TODO test that signatures that fail should be null for certain flags. 
        
    }
    
}
