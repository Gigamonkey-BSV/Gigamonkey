// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err58-cpp"

#include <gigamonkey/redeem.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/script/machine.hpp>
#include <data/crypto/NIST_DRBG.hpp>
#include <data/encoding/hex.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {

    TEST(AddressTest, TestAddresses) {
        using namespace interpreter;
        
        // We start with a secret key. 
        secret key{secret::test, secp256k1::secret{uint256{"0x00000000000000000000000000000000000000000000000000000000000101a7"}}};
        
        satoshi redeemed_value = 6767;
        
        EXPECT_TRUE(key.valid());
        
        pubkey pubkey_compressed = key.to_public().compress();
        pubkey pubkey_uncompressed = key.to_public().decompress();
        
        EXPECT_TRUE(pubkey_compressed.valid());
        EXPECT_TRUE(pubkey_uncompressed.valid());
        
        EXPECT_EQ(pubkey_compressed, pubkey_uncompressed.compress());
        EXPECT_EQ(pubkey_uncompressed, pubkey_compressed.decompress());
        
        // now we make four scripts. 
        bytes script_p2pk_compressed = pay_to_pubkey::script(pubkey_compressed);
        bytes script_p2pk_uncompressed = pay_to_pubkey::script(pubkey_uncompressed);
        
        address address_compressed{address::test, pubkey_compressed};
        address address_uncompressed{address::test, pubkey_uncompressed};
        
        bytes script_p2pkh_compressed = pay_to_address::script(address_compressed.Digest);
        bytes script_p2pkh_uncompressed = pay_to_address::script(address_uncompressed.Digest);
        
        // we only need 3 redeemers because the redeem script is the same for p2pk compressed and uncompressed. 
        redeem_pay_to_pubkey p2pk_redeemer(key);
        redeem_pay_to_address p2pkh_compressed_redeemer(key, pubkey_compressed);
        redeem_pay_to_address p2pkh_uncompressed_redeemer(key, pubkey_uncompressed);
        
        redemption_document doc{redeemed_value, 
            incomplete::transaction{
                transaction::LatestVersion, 
                list<incomplete::input>{incomplete::input{outpoint{txid{307}, 7}}}, 
                list<output>{}, 0}, 0};
        
        sighash::directive directive = sighash::all | sighash::fork_id;
        
        bytes redeem_p2pk_compressed = p2pk_redeemer.redeem(doc.add_script_code(script_p2pk_compressed), directive);
        bytes redeem_p2pk_uncompressed = p2pk_redeemer.redeem(doc.add_script_code(script_p2pk_uncompressed), directive);
        
        bytes redeem_p2pkh_compressed = p2pkh_compressed_redeemer.redeem(doc.add_script_code(script_p2pkh_compressed), directive);
        bytes redeem_p2pkh_uncompressed = p2pkh_uncompressed_redeemer.redeem(doc.add_script_code(script_p2pkh_uncompressed), directive);
        
        auto evaluate_p2pk_compressed = evaluate(redeem_p2pk_compressed, script_p2pk_compressed, doc);
        auto evaluate_p2pk_uncompressed = evaluate(redeem_p2pk_uncompressed, script_p2pk_uncompressed, doc);
        
        auto evaluate_p2pkh_compressed = evaluate(redeem_p2pkh_compressed, script_p2pkh_compressed, doc);
        auto evaluate_p2pkh_uncompressed = evaluate(redeem_p2pkh_uncompressed, script_p2pkh_uncompressed, doc);
        
        EXPECT_TRUE(evaluate_p2pk_compressed) << evaluate_p2pk_compressed;
        EXPECT_TRUE(evaluate_p2pk_uncompressed) << evaluate_p2pk_uncompressed;
        
        EXPECT_TRUE(evaluate_p2pkh_compressed) << evaluate_p2pkh_compressed;
        EXPECT_TRUE(evaluate_p2pkh_uncompressed) << evaluate_p2pkh_uncompressed;
        
        EXPECT_FALSE(evaluate(redeem_p2pk_uncompressed, script_p2pk_compressed, doc));
        EXPECT_FALSE(evaluate(redeem_p2pk_compressed, script_p2pk_uncompressed, doc));
        
        EXPECT_FALSE(evaluate(redeem_p2pkh_uncompressed, script_p2pkh_compressed, doc));
        EXPECT_FALSE(evaluate(redeem_p2pkh_compressed, script_p2pkh_uncompressed, doc));
        
        EXPECT_FALSE(evaluate(redeem_p2pkh_compressed, script_p2pk_compressed, doc));
        EXPECT_FALSE(evaluate(redeem_p2pkh_uncompressed, script_p2pk_uncompressed, doc));
        
        EXPECT_FALSE(evaluate(redeem_p2pk_compressed, script_p2pkh_compressed, doc));
        EXPECT_FALSE(evaluate(redeem_p2pk_uncompressed, script_p2pkh_uncompressed, doc));
        
        EXPECT_FALSE(evaluate(redeem_p2pkh_compressed, script_p2pk_uncompressed, doc));
        EXPECT_FALSE(evaluate(redeem_p2pkh_uncompressed, script_p2pk_compressed, doc));
        
        EXPECT_FALSE(evaluate(redeem_p2pk_compressed, script_p2pkh_uncompressed, doc));
        EXPECT_FALSE(evaluate(redeem_p2pk_uncompressed, script_p2pkh_compressed, doc));
        
    }
    /*
    TEST(AddressTest, TestRecoverBase58) {
        
        ptr<crypto::entropy> entropy = std::static_pointer_cast<crypto::entropy>(std::make_shared<crypto::fixed_entropy>(
            bytes_view(bytes::from_string("atehu=eSRCjt.r83085[934[498[35"))));
        
        crypto::nist::drbg random{crypto::nist::drbg::HMAC_DRBG, entropy, bytes{}, 305};
        
        digest160 pubkey_hash;
        
        random >> pubkey_hash.Value;
        
        string address = Bitcoin::address(Bitcoin::address::main, pubkey_hash).write();
        
        base58::check address_check(address);
        
        string characters = encoding::base58::characters();
        
        string replaced;
        {
        
            int replace_at = std::uniform_int_distribution<int>(0, address.size() - 1)(random);
            
            char replace_with;
            do {
                replace_with = characters[std::uniform_int_distribution<int>(0, 57)(random)];
            } while (replace_with == address[replace_at]);
            
            replaced = address;
            replaced[replace_at] = replace_with;
            
        }
        
        string inserted;
        {
            
            int insert_at = std::uniform_int_distribution<int>(0, address.size())(random);
            char to_insert = characters[std::uniform_int_distribution<int>(0, 57)(random)];
        
            inserted.resize(address.size() + 1);
            std::copy(address.begin(), address.begin() + insert_at, inserted.begin());
            std::copy(address.begin() + insert_at, address.end(), inserted.begin() + insert_at + 1);
            
            inserted[insert_at] = to_insert;
            
        }
        
        string deleted;
        {
            
            int delete_at = std::uniform_int_distribution<int>(0, address.size() - 1)(random);
            
            deleted.resize(address.size() - 1);
            
            std::copy(address.begin(), address.begin() + delete_at, deleted.begin());
            std::copy(address.begin() + delete_at + 1, address.end(), deleted.begin() + delete_at);
        }
        
        EXPECT_EQ(address_check, base58::check::recover(replaced));
        EXPECT_EQ(address_check, base58::check::recover(inserted));
        EXPECT_EQ(address_check, base58::check::recover(deleted));
        
    }*/

}

#pragma clang diagnostic pop
