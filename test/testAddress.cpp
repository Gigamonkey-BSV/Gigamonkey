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
        
        signature arbitrary{bytes("It's not easy being green.")};
        
        secret key{"0x00000000000000000000000000000000000000000000000000000000000101a7"};
        
        std::cout << "using key " << key << " for testing addresses" << std::endl;
        
        EXPECT_TRUE(key.valid());
        
        pubkey pubkey_compressed = key.to_public().compress();
        pubkey pubkey_uncompressed = key.to_public().decompress();
        
        std::cout << "attempting to pay to pubkey with pubkey compressed " << pubkey_compressed << std::endl;
        std::cout << "attempting to pay to pubkey with pubkey uncompressed " << pubkey_uncompressed << std::endl;
        
        std::cout << "pubkey compressed value is " << pubkey_compressed << std::endl;
        std::cout << "pubkey uncompressed value is " << pubkey_uncompressed << std::endl;
        
        bytes script_p2pk_compressed = pay_to_pubkey::script(pubkey_compressed);
        bytes script_p2pk_uncompressed = pay_to_pubkey::script(pubkey_uncompressed);
        
        bytes redeem_p2pk = pay_to_pubkey::redeem(arbitrary);
        
        address address_compressed{pubkey_compressed};
        address address_uncompressed{pubkey_uncompressed};
        
        std::cout << "attempting to pay to address with address compressed " << address_compressed << std::endl;
        std::cout << "attempting to pay to address with address uncompressed " << address_uncompressed << std::endl;
        
        bytes script_p2pkh_compressed = pay_to_address::script(address_compressed.Digest);
        bytes script_p2pkh_uncompressed = pay_to_address::script(address_uncompressed.Digest);
        
        bytes redeem_p2pkh_compressed = pay_to_address::redeem(arbitrary, pubkey_compressed);
        
        bytes redeem_p2pkh_uncompressed = pay_to_address::redeem(arbitrary, pubkey_uncompressed);
        
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
