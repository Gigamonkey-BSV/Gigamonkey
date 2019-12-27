// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err58-cpp"

#include <gigamonkey/types.hpp>
#include <gigamonkey/spendable.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/signatuer.hpp>
#include "gtest/gtest.h"

namespace gigamonkey::bitcoin {
    
    TEST(AddressTest, TestAddresses) {
        
        const auto pay_to_address_compressed =
            abstractions::pattern::pay_to_address<secret, pubkey, address, bytes>{};
        const auto pay_to_address_uncompressed =
            abstractions::pattern::pay_to_address<secret, uncompressed_pubkey, address, bytes>{};
        const auto pay_to_pubkey_compressed =
            abstractions::pattern::pay_to_pubkey<secret, pubkey, bytes>{};
        const auto pay_to_pubkey_uncompressed = 
            abstractions::pattern::pay_to_pubkey<secret, uncompressed_pubkey, bytes>{};
        
        std::string arbitrary{"It's not easy being green."};
        bytes tx{arbitrary.begin(), arbitrary.end()};
        satoshi to_be_redeemed = 2000000000000000;
        uint32 index = 3;
        
        secret key{"0x00000000000000000000000000000000000000000000000000000000000101a7"};
        
        std::cout << "using key " << key << " for testing addresses" << std::endl;
        
        EXPECT_TRUE(key.valid());
        
        pubkey pubkey_compressed = key.to_public();
        uncompressed_pubkey pubkey_uncompressed = key.to_public_uncompressed();
        
        std::cout << "attempting to pay to pubkey with pubkey compressed " << pubkey_compressed << std::endl;
        std::cout << "attempting to pay to pubkey with pubkey uncompressed " << pubkey_uncompressed << std::endl;
        
        std::cout << "pubkey compressed value is " << N{bytes_view{pubkey_compressed.Pubkey.Value.data(), 33}, boost::endian::order::big} << std::endl;
        std::cout << "pubkey uncompressed value is " << N{bytes_view{pubkey_uncompressed.Pubkey.Value.data(), 65}, boost::endian::order::big} << std::endl;
        
        // unimplemented exception thrown here. 
        script script_pay_to_pubkey_compressed = pay_to_pubkey_compressed.pay(pubkey_compressed);
        script script_pay_to_pubkey_uncompressed = pay_to_pubkey_uncompressed.pay(pubkey_uncompressed);
        
        script redeem_pay_to_pubkey_compressed = pay_to_pubkey_compressed.redeem(
            output{to_be_redeemed, script_pay_to_pubkey_compressed}, 
            input_index<bytes>{tx, index}, key);
        
        script redeem_pay_to_pubkey_uncompressed = pay_to_pubkey_uncompressed.redeem(
            output{to_be_redeemed, script_pay_to_pubkey_uncompressed}, 
            input_index<bytes>{tx, index}, key);
        
        address address_compressed = pubkey_compressed.address();
        address address_uncompressed = pubkey_uncompressed.address();
        
        std::cout << "attempting to pay to address with address compressed " << address_compressed << std::endl;
        std::cout << "attempting to pay to address with address uncompressed " << address_uncompressed << std::endl;
        
        script script_pay_to_address_compressed = pay_to_address_compressed.pay(address_compressed);
        script script_pay_to_address_uncompressed = pay_to_address_uncompressed.pay(address_uncompressed);
        
        script redeem_pay_to_address_compressed = pay_to_address_compressed.redeem(
            output{to_be_redeemed, script_pay_to_address_compressed}, 
            input_index<bytes>{tx, index}, key);
        
        script redeem_pay_to_address_uncompressed = pay_to_address_uncompressed.redeem(
            output{to_be_redeemed, script_pay_to_address_uncompressed}, 
            input_index<bytes>{tx, index}, key);
        
        machine m{input_index<bytes_view>{tx, index}, to_be_redeemed};
        
        EXPECT_TRUE(m.run(script_pay_to_pubkey_compressed, redeem_pay_to_pubkey_compressed));
        EXPECT_TRUE(m.run(script_pay_to_pubkey_uncompressed, redeem_pay_to_pubkey_uncompressed));
        EXPECT_TRUE(m.run(script_pay_to_address_compressed, redeem_pay_to_address_compressed));
        EXPECT_TRUE(m.run(script_pay_to_address_uncompressed, redeem_pay_to_address_uncompressed));
        
        EXPECT_FALSE(m.run(script_pay_to_pubkey_compressed, redeem_pay_to_pubkey_uncompressed));
        EXPECT_FALSE(m.run(script_pay_to_pubkey_uncompressed, redeem_pay_to_pubkey_compressed));
        EXPECT_FALSE(m.run(script_pay_to_address_compressed, redeem_pay_to_address_uncompressed));
        EXPECT_FALSE(m.run(script_pay_to_address_uncompressed, redeem_pay_to_address_compressed));
        
        EXPECT_FALSE(m.run(script_pay_to_pubkey_compressed, redeem_pay_to_address_compressed));
        EXPECT_FALSE(m.run(script_pay_to_pubkey_uncompressed, redeem_pay_to_address_uncompressed));
        EXPECT_FALSE(m.run(script_pay_to_address_compressed, redeem_pay_to_pubkey_compressed));
        EXPECT_FALSE(m.run(script_pay_to_address_uncompressed, redeem_pay_to_pubkey_uncompressed));
        
    }

}

#pragma clang diagnostic pop
