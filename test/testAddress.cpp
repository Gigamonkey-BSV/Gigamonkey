// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err58-cpp"

#include <gigamonkey/types.hpp>
#include <gigamonkey/spendable.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/signature.hpp>
#include <gigamonkey/script/pattern.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {
    
    TEST(AddressTest, TestAddresses) {
        
        // We start with a secret key. 
        secret key{secret::test, secp256k1::secret{secp256k1::coordinate{"0x00000000000000000000000000000000000000000000000000000000000101a7"}}};
        
        // There is a fake signature. This test should also
        // include a real signature but does not yet. 
        signature fake{};
        
        EXPECT_TRUE(key.valid());
        
        pubkey pubkey_compressed = key.to_public().compress();
        pubkey pubkey_uncompressed = key.to_public().decompress();
        
        EXPECT_TRUE(pubkey_compressed.valid());
        EXPECT_TRUE(pubkey_uncompressed.valid());
        
        EXPECT_EQ(pubkey_compressed, pubkey_uncompressed.compress());
        EXPECT_EQ(pubkey_uncompressed, pubkey_compressed.decompress());
        
        bytes script_p2pk_compressed = pay_to_pubkey::script(pubkey_compressed);
        bytes script_p2pk_uncompressed = pay_to_pubkey::script(pubkey_uncompressed);
        
        bytes redeem_p2pk = pay_to_pubkey::redeem(fake);
        
        address address_compressed{address::test, pubkey_compressed};
        address address_uncompressed{address::test, pubkey_uncompressed};
        
        bytes script_p2pkh_compressed = pay_to_address::script(address_compressed.Digest);
        bytes script_p2pkh_uncompressed = pay_to_address::script(address_uncompressed.Digest);
        
        bytes redeem_p2pkh_compressed = pay_to_address::redeem(fake, pubkey_compressed);
        
        bytes redeem_p2pkh_uncompressed = pay_to_address::redeem(fake, pubkey_uncompressed);
        
        EXPECT_TRUE(evaluate_script(redeem_p2pk, script_p2pk_compressed).valid());
        EXPECT_TRUE(evaluate_script(redeem_p2pkh_compressed, script_p2pkh_compressed).valid());
        
        EXPECT_TRUE(evaluate_script(redeem_p2pk, script_p2pk_uncompressed).valid());
        EXPECT_TRUE(evaluate_script(redeem_p2pkh_uncompressed, script_p2pkh_uncompressed).valid());
        
        EXPECT_FALSE(evaluate_script(redeem_p2pkh_compressed, script_p2pk_compressed).valid());
        EXPECT_FALSE(evaluate_script(redeem_p2pk, script_p2pkh_compressed).valid());
        
        EXPECT_FALSE(evaluate_script(redeem_p2pkh_uncompressed, script_p2pk_uncompressed).valid());
        EXPECT_FALSE(evaluate_script(redeem_p2pk, script_p2pkh_uncompressed).valid());
        
        EXPECT_FALSE(evaluate_script(redeem_p2pkh_uncompressed, script_p2pkh_compressed).valid());
        
        EXPECT_FALSE(evaluate_script(redeem_p2pkh_compressed, script_p2pkh_uncompressed).valid());
        
    }

}

#pragma clang diagnostic pop
