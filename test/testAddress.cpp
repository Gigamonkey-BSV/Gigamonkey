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
#include <gigamonkey/script.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {
    
    TEST(AddressTest, TestAddresses) {
        
        std::cout << "Begin address test. " << std::endl;
        
        // We start with a secret key. 
        secret key{secret::test, secp256k1::secret{secp256k1::coordinate{"0x00000000000000000000000000000000000000000000000000000000000101a7"}}};
        
        std::cout << "using key " << key.Secret << " for testing addresses" << std::endl;
        
        // There is a fake signature. This test should also
        // include a real signature but does not yet. 
        signature fake{bytes("It's not easy being green.")};
        
        EXPECT_TRUE(key.valid());
        
        pubkey pubkey_compressed = key.to_public().compress();
        pubkey pubkey_uncompressed = key.to_public().decompress();
        
        EXPECT_EQ(pubkey_compressed, pubkey_uncompressed.compress());
        EXPECT_EQ(pubkey_uncompressed, pubkey_compressed.decompress());
        
        std::cout << "attempting to pay to pubkey with pubkey compressed " << pubkey_compressed << std::endl;
        std::cout << "attempting to pay to pubkey with pubkey uncompressed " << pubkey_uncompressed << std::endl;
        
        std::cout << "pubkey compressed value is " << pubkey_compressed << std::endl;
        std::cout << "pubkey uncompressed value is " << pubkey_uncompressed << std::endl;
        
        bytes script_p2pk_compressed = pay_to_pubkey::script(pubkey_compressed);
        bytes script_p2pk_uncompressed = pay_to_pubkey::script(pubkey_uncompressed);
        
        bytes redeem_p2pk = pay_to_pubkey::redeem(fake);
        
        address address_compressed{address::test, pubkey_compressed};
        address address_uncompressed{address::test, pubkey_uncompressed};
        
        std::cout << "attempting to pay to address with address compressed " << address_compressed << std::endl;
        std::cout << "attempting to pay to address with address uncompressed " << address_uncompressed << std::endl;
        
        bytes script_p2pkh_compressed = pay_to_address::script(address_compressed.Digest);
        bytes script_p2pkh_uncompressed = pay_to_address::script(address_uncompressed.Digest);
        
        bytes redeem_p2pkh_compressed = pay_to_address::redeem(fake, pubkey_compressed);
        
        bytes redeem_p2pkh_uncompressed = pay_to_address::redeem(fake, pubkey_uncompressed);
        
        EXPECT_TRUE(evaluate_script(script_p2pk_compressed, redeem_p2pk).valid());
        EXPECT_TRUE(evaluate_script(script_p2pkh_compressed, redeem_p2pkh_compressed).valid());
        
        EXPECT_TRUE(evaluate_script(script_p2pk_uncompressed, redeem_p2pk).valid());
        EXPECT_TRUE(evaluate_script(script_p2pkh_uncompressed, redeem_p2pkh_uncompressed).valid());
        
        EXPECT_FALSE(evaluate_script(script_p2pk_compressed, redeem_p2pkh_compressed).valid());
        EXPECT_FALSE(evaluate_script(script_p2pkh_compressed, redeem_p2pk).valid());
        
        EXPECT_FALSE(evaluate_script(script_p2pk_uncompressed, redeem_p2pkh_uncompressed).valid());
        EXPECT_FALSE(evaluate_script(script_p2pkh_uncompressed, redeem_p2pk).valid());
        
        EXPECT_FALSE(evaluate_script(script_p2pkh_compressed, redeem_p2pkh_uncompressed).valid());
        
        EXPECT_FALSE(evaluate_script(script_p2pkh_uncompressed, redeem_p2pkh_compressed).valid());
        
    }

}

#pragma clang diagnostic pop
