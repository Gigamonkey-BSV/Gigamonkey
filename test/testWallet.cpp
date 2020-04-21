// Copyright (c) 2019 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/wallet.hpp>
#include <gigamonkey/schema/random.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {
    
    TEST(WalletTest, TestWallet) {
        
        // random keys schema
        ptr<keysource> keys = random_keysource::make();
        
        // The type of change addresses our wallet will generate. 
        const output_pattern ChangePattern = pay_to_address;
        
        const wallet::spend_policy SpendPolicy = wallet::fifo;
        
        uint32 num_inputs = 10;
        satoshi redemption_value = 5000;
        uint256 fake_txid{7};
        
        // create outputs to redeem. 
        stack<change> previous{};
        funds mine{};
        for (uint32 i = 0; i < num_inputs; i++) {
            previous = previous << create_redeemable_output_script<ChangePattern>(keys);
            mine = mine.insert(spendable{*previous.first().Redeemer, 
                prevout{
                    output{redemption_value, previous.first().OutputScript}, 
                    outpoint{txid{fake_txid}, i}}});
            fake_txid += 1;
            redemption_value *= 3;
            redemption_value /= 2;
        }
        
        // create wallet 
        wallet w{mine, SpendPolicy, keys, fee{.1, 10}, ChangePattern};
        
        // make payment 
        
        // check transaction deserialization
        
        // check fee
        
        
    }

}
