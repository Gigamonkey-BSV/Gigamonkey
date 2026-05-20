// Copyright (c) 2019 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/wallet.hpp>
#include <gigamonkey/schema/random.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {
    
    TEST (Wallet, Wallet) {
        
        // random keys schema
        ptr<keysource> keys = random_keysource::make();
        
        // The type of change addresses our wallet will generate. 
        const ptr<output_pattern> ChangePattern = std::make_shared<pay_to_address_pattern> ();
        
        const wallet::spend_policy SpendPolicy = wallet::fifo;
        
        uint32 num_inputs = 10;
        satoshi redemption_value = 5000;
        uint256 fake_txid {7};
        
        fee fees {.1, 10};
        
        // create outputs to redeem. 
        stack<change> previous {};
        funds mine {};
        for (uint32 i = 0; i < num_inputs; i++) {
            previous = previous << ChangePattern->create_redeemable (keys);
            mine = mine.insert (spendable {*previous.first ().Redeemer,
                prevout {
                    output {redemption_value, previous.first ().OutputScript},
                    outpoint {txid {fake_txid}, i}}});
            fake_txid += 1;
            redemption_value *= 3;
            redemption_value /= 2;
        }
        
        // make outputs to spend
        stack<payment> payments {};
        uint32 num_payments = 5;
        satoshi payment_amount = 2000;
        for (uint32 i = 0; i < num_payments; i++) 
            payments = payments << payment{payment_amount, keys->first ().address ()};
        
        // negative tests:
        // TODO spend more than in wallet
        // TODO spend dust. 
        
        // create wallets 
        wallet w1 {mine, wallet::fifo, keys, fees, ChangePattern, 0};
        wallet w2 {mine, wallet::all, keys, fees, ChangePattern, 0};
        wallet w3 {mine, wallet::random, keys, fees, ChangePattern, 0};
        
        // make payment
        wallet::spent s1 = w1.spend (payments);
        wallet::spent s2 = w2.spend (payments);
        wallet::spent s3 = w3.spend (payments);
        
        // check transaction deserialization
        EXPECT_TRUE (s1.valid ());
        EXPECT_TRUE (s2.valid ());
        EXPECT_TRUE (s3.valid ());
        
        // check fee
        EXPECT_TRUE (fees.sufficient (s1.Vertex));
        EXPECT_TRUE (fees.sufficient (s2.Vertex));
        EXPECT_TRUE (fees.sufficient (s3.Vertex));
        
        // check remainders
        
    }

}
