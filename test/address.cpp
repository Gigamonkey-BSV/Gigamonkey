// Copyright (c) 2019 Katrina Swales
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err58-cpp"

#include <gigamonkey/wif.hpp>
#include <gigamonkey/p2p/checksum.hpp>
#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/script/pattern/pay_to_address.hpp>
#include <gigamonkey/script/pattern/pay_to_pubkey.hpp>
#include <gigamonkey/script/pattern/pay_to_script_hash.hpp>
#include <gigamonkey/script/typed_data_bip_276.hpp>
#include <data/crypto/NIST_DRBG.hpp>
#include <data/encoding/hex.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {

    sighash::document inline add_script_code (const redemption_document &doc, bytes script_code) {
        return sighash::document {doc.Transaction, doc.InputIndex, doc.RedeemedValue, decompile (script_code)};
    }

    struct test_standard_scripts {

        // We start with a secret key.
        secret key {net::Test, secp256k1::secret {uint256 {"0x00000000000000000000000000000000000000000000000000000000000101a7"}}};

        pubkey pubkey_compressed {key.to_public ().compress ()};
        pubkey pubkey_uncompressed {key.to_public ().decompress ()};

        satoshi redeemed_value {6767};

        // now we make four scripts.
        bytes script_p2pk_compressed {pay_to_pubkey::script (pubkey_compressed)};
        bytes script_p2pk_uncompressed {pay_to_pubkey::script (pubkey_uncompressed)};

        digest160 pubkey_hash_compressed {Hash160 (pubkey_compressed)};
        digest160 pubkey_hash_uncompressed {Hash160 (pubkey_uncompressed)};

        bytes script_p2pkh_compressed {pay_to_address::script (pubkey_hash_compressed)};
        bytes script_p2pkh_uncompressed {pay_to_address::script (pubkey_hash_uncompressed)};

        incomplete::transaction incomplete_tx {
            transaction::LatestVersion,
            list<incomplete::input> {incomplete::input {outpoint {Bitcoin::TXID {307}, 7}}},
            list<output> {}, 0};

        redemption_document doc {incomplete_tx, 0, redeemed_value};

        sighash::directive fork_id {sighash::all | sighash::fork_id};
        sighash::directive original {sighash::all};

        bytes redeem_p2pk_compressed_fork_id {pay_to_pubkey::redeem (key.sign (add_script_code (doc, script_p2pk_compressed), fork_id))};
        bytes redeem_p2pk_uncompressed_fork_id {pay_to_pubkey::redeem (key.sign (add_script_code (doc, script_p2pk_uncompressed), fork_id))};

        bytes redeem_p2pk_compressed_original {pay_to_pubkey::redeem (key.sign (add_script_code (doc, script_p2pk_compressed), original))};
        bytes redeem_p2pk_uncompressed_original {pay_to_pubkey::redeem (key.sign (add_script_code (doc, script_p2pk_uncompressed), original))};

        bytes redeem_p2pkh_compressed_fork_id {pay_to_address::redeem (
            key.sign (add_script_code (doc, script_p2pkh_compressed), fork_id),
            pubkey_compressed)};

        bytes redeem_p2pkh_uncompressed_fork_id {pay_to_address::redeem (
            key.sign (add_script_code (doc, script_p2pkh_uncompressed), fork_id),
            pubkey_uncompressed)};

        bytes redeem_p2pkh_compressed_original {pay_to_address::redeem (
            key.sign (add_script_code (doc, script_p2pkh_compressed), original),
            pubkey_compressed)};

        bytes redeem_p2pkh_uncompressed_original {pay_to_address::redeem (
            key.sign (add_script_code (doc, script_p2pkh_uncompressed), original),
            pubkey_uncompressed)};

        test_standard_scripts () {}

        void test_p2pk_and_p2pkh () {

            EXPECT_TRUE (key.valid ());

            EXPECT_TRUE (pubkey_compressed.valid ());
            EXPECT_TRUE (pubkey_uncompressed.valid ());

            EXPECT_EQ (pubkey_compressed, pubkey_uncompressed.compress ());
            EXPECT_EQ (pubkey_uncompressed, pubkey_compressed.decompress ());

            flag flag_original = flag::VERIFY_NONE;
            flag flag_fork_id = flag::ENABLE_SIGHASH_FORKID;

            // note: we need to use the right flags to support the original signature algorithm.
            auto evaluate_p2pk_compressed_fork_id = evaluate (redeem_p2pk_compressed_fork_id,
                script_p2pk_compressed, doc, flag_fork_id);

            auto evaluate_p2pk_uncompressed_fork_id = evaluate (redeem_p2pk_uncompressed_fork_id,
                script_p2pk_uncompressed, doc, flag_fork_id);

            auto evaluate_p2pkh_compressed_fork_id = evaluate (redeem_p2pkh_compressed_fork_id,
                script_p2pkh_compressed, doc, flag_fork_id);

            auto evaluate_p2pkh_uncompressed_fork_id = evaluate (redeem_p2pkh_uncompressed_fork_id,
                script_p2pkh_uncompressed, doc, flag_fork_id);

            auto evaluate_p2pk_compressed_original = evaluate (redeem_p2pk_compressed_original,
                script_p2pk_compressed, doc, flag_original);

            auto evaluate_p2pk_uncompressed_original = evaluate (redeem_p2pk_uncompressed_original,
                script_p2pk_uncompressed, doc, flag_original);

            auto evaluate_p2pkh_compressed_original = evaluate (redeem_p2pkh_compressed_original,
                script_p2pkh_compressed, doc, flag_original);

            auto evaluate_p2pkh_uncompressed_original = evaluate (redeem_p2pkh_uncompressed_original,
                script_p2pkh_uncompressed, doc, flag_original);

            EXPECT_TRUE (evaluate_p2pk_compressed_fork_id) << evaluate_p2pk_compressed_fork_id;
            EXPECT_TRUE (evaluate_p2pk_uncompressed_fork_id) << evaluate_p2pk_uncompressed_fork_id;

            EXPECT_TRUE (evaluate_p2pkh_compressed_fork_id) << evaluate_p2pkh_compressed_fork_id;
            EXPECT_TRUE (evaluate_p2pkh_uncompressed_fork_id) << evaluate_p2pkh_uncompressed_fork_id;

            EXPECT_TRUE (evaluate_p2pk_compressed_original) << evaluate_p2pk_compressed_original;
            EXPECT_TRUE (evaluate_p2pk_uncompressed_original) << evaluate_p2pk_uncompressed_original;

            EXPECT_TRUE (evaluate_p2pkh_compressed_original) << evaluate_p2pkh_compressed_original;
            EXPECT_TRUE (evaluate_p2pkh_uncompressed_original) << evaluate_p2pkh_uncompressed_original;

            // these next four fail because the signature is incorrect
            // due to the public key being included in the script code.
            EXPECT_FALSE (evaluate (redeem_p2pk_uncompressed_fork_id, script_p2pk_compressed, doc, flag_fork_id));
            EXPECT_FALSE (evaluate (redeem_p2pk_compressed_fork_id, script_p2pk_uncompressed, doc, flag_fork_id));

            EXPECT_FALSE (evaluate (redeem_p2pk_uncompressed_original, script_p2pk_compressed, doc, flag_original));
            EXPECT_FALSE (evaluate (redeem_p2pk_compressed_original, script_p2pk_uncompressed, doc, flag_original));

            // these fail because the address is wrong.
            EXPECT_FALSE (evaluate (redeem_p2pkh_uncompressed_fork_id, script_p2pkh_compressed, doc, flag_fork_id));
            EXPECT_FALSE (evaluate (redeem_p2pkh_compressed_fork_id, script_p2pkh_uncompressed, doc, flag_fork_id));

            EXPECT_FALSE (evaluate (redeem_p2pkh_uncompressed_original, script_p2pkh_compressed, doc, flag_original));
            EXPECT_FALSE (evaluate (redeem_p2pkh_compressed_original, script_p2pkh_uncompressed, doc, flag_original));

            EXPECT_FALSE (evaluate (redeem_p2pkh_compressed_fork_id, script_p2pk_compressed, doc, flag_fork_id));
            EXPECT_FALSE (evaluate (redeem_p2pkh_uncompressed_fork_id, script_p2pk_uncompressed, doc, flag_fork_id));

            EXPECT_FALSE (evaluate (redeem_p2pk_compressed_fork_id, script_p2pkh_compressed, doc, flag_fork_id));
            EXPECT_FALSE (evaluate (redeem_p2pk_uncompressed_fork_id, script_p2pkh_uncompressed, doc, flag_fork_id));

            EXPECT_FALSE (evaluate (redeem_p2pkh_compressed_fork_id, script_p2pk_uncompressed, doc, flag_fork_id));
            EXPECT_FALSE (evaluate (redeem_p2pkh_uncompressed_fork_id, script_p2pk_compressed, doc, flag_fork_id));

            EXPECT_FALSE (evaluate (redeem_p2pk_compressed_fork_id, script_p2pkh_uncompressed, doc, flag_fork_id));
            EXPECT_FALSE (evaluate (redeem_p2pk_uncompressed_fork_id, script_p2pkh_compressed, doc, flag_fork_id));

        }

        void test_p2sh () {

            digest160 p2pk_hash_compressed = Hash160 (script_p2pk_compressed);
            digest160 p2pk_hash_uncompressed = Hash160 (script_p2pk_uncompressed);

            digest160 p2pkh_hash_compressed = Hash160 (script_p2pkh_compressed);
            digest160 p2pkh_hash_uncompressed = Hash160 (script_p2pkh_uncompressed);

            bytes p2sh_p2pk_compressed = pay_to_script_hash::script (p2pk_hash_compressed);
            bytes p2sh_p2pk_uncompressed = pay_to_script_hash::script (p2pk_hash_uncompressed);
            bytes p2sh_p2pkh_compressed = pay_to_script_hash::script (p2pkh_hash_compressed);
            bytes p2sh_p2pkh_uncompressed = pay_to_script_hash::script (p2pkh_hash_uncompressed);

            // expect that these scripts are p2sh while the others are not.
            EXPECT_TRUE (is_P2SH (p2sh_p2pk_compressed));
            EXPECT_TRUE (is_P2SH (p2sh_p2pk_uncompressed));
            EXPECT_TRUE (is_P2SH (p2sh_p2pkh_compressed));
            EXPECT_TRUE (is_P2SH (p2sh_p2pkh_uncompressed));

            EXPECT_FALSE (is_P2SH (script_p2pk_compressed));
            EXPECT_FALSE (is_P2SH (script_p2pk_uncompressed));
            EXPECT_FALSE (is_P2SH (script_p2pkh_compressed));
            EXPECT_FALSE (is_P2SH (script_p2pkh_uncompressed));

            // the redeem script is the same redeem script with the locking script added as push data.
            bytes redeem_p2sh_p2pk_compressed_original = compile (decompile (redeem_p2pk_compressed_original) <<
                push_data (script_p2pk_compressed));

            bytes redeem_p2sh_p2pk_uncompressed_original = compile (decompile (redeem_p2pk_uncompressed_original) <<
                push_data (script_p2pk_uncompressed));

            bytes redeem_p2sh_p2pkh_compressed_original = compile (decompile (redeem_p2pkh_compressed_original) <<
                push_data (script_p2pkh_compressed));

            bytes redeem_p2sh_p2pkh_uncompressed_original = compile (decompile (redeem_p2pkh_uncompressed_original) <<
                push_data (script_p2pkh_uncompressed));

            flag flag_p2sh = flag::VERIFY_P2SH | flag::VERIFY_CLEANSTACK;
            flag flag_no_p2sh = flag::VERIFY_CLEANSTACK;

            EXPECT_TRUE (evaluate (redeem_p2sh_p2pk_compressed_original, p2sh_p2pk_compressed, flag_p2sh));
            EXPECT_TRUE (evaluate (redeem_p2sh_p2pk_uncompressed_original, p2sh_p2pk_uncompressed, flag_p2sh));
            EXPECT_TRUE (evaluate (redeem_p2sh_p2pkh_compressed_original, p2sh_p2pkh_compressed, flag_p2sh));
            EXPECT_TRUE (evaluate (redeem_p2sh_p2pkh_uncompressed_original, p2sh_p2pkh_uncompressed, flag_p2sh));

            // script should be invalid if the flag is not set.
            EXPECT_FALSE (evaluate (redeem_p2sh_p2pk_compressed_original, p2sh_p2pk_compressed, flag_no_p2sh));
            EXPECT_FALSE (evaluate (redeem_p2sh_p2pk_uncompressed_original, p2sh_p2pk_uncompressed, flag_no_p2sh));
            EXPECT_FALSE (evaluate (redeem_p2sh_p2pkh_compressed_original, p2sh_p2pkh_compressed, flag_no_p2sh));
            EXPECT_FALSE (evaluate (redeem_p2sh_p2pkh_uncompressed_original, p2sh_p2pkh_uncompressed, flag_no_p2sh));
        }

    };

    TEST (Address, Addresses) {
        test_standard_scripts {}.test_p2pk_and_p2pkh ();
    }

    // use the address tests above to test P2SH
    TEST (Address, P2SH) {
        test_standard_scripts {}.test_p2sh ();
    }
    
    TEST (Address, RecoverBase58) {
        
        ptr<data::entropy> entropy = std::static_pointer_cast<data::entropy> (std::make_shared<data::fixed_entropy> (
            byte_slice (bytes (string ("atehu=eSRCjt.r83085[934[498[35")))));
        
        crypto::NIST::DRBG random {crypto::NIST::DRBG::HMAC, {*entropy, bytes {}, 305}};
        
        digest160 pubkey_hash;
        
        random >> pubkey_hash;
        
        Bitcoin::address address {Bitcoin::net::Main, pubkey_hash};
        
        base58::check address_check (address);
        
        string characters = encoding::base58::characters ();
        
        string replaced;

        {
            int replace_at = std::uniform_int_distribution<int> (0, address.size () - 1) (random);
            
            char replace_with;
            do {
                replace_with = characters[std::uniform_int_distribution<int> (0, 57) (random)];
            } while (replace_with == address[replace_at]);
            
            replaced = address;
            replaced[replace_at] = replace_with;
            
        }
        
        string inserted;

        {
            int insert_at = std::uniform_int_distribution<int> (0, address.size ()) (random);
            char to_insert = characters[std::uniform_int_distribution<int> (0, 57) (random)];
        
            inserted.resize (address.size () + 1);
            std::copy (address.begin (), address.begin () + insert_at, inserted.begin ());
            std::copy (address.begin () + insert_at, address.end (), inserted.begin () + insert_at + 1);
            
            inserted[insert_at] = to_insert;
            
        }
        
        string deleted;

        {
            int delete_at = std::uniform_int_distribution<int> (0, address.size () - 1) (random);
            
            deleted.resize (address.size () - 1);
            
            std::copy (address.begin (), address.begin () + delete_at, deleted.begin ());
            std::copy (address.begin () + delete_at + 1, address.end (), deleted.begin () + delete_at);
        }
        
        EXPECT_EQ (address_check, base58::check::recover (replaced));
        EXPECT_EQ (address_check, base58::check::recover (inserted));
        EXPECT_EQ (address_check, base58::check::recover (deleted));
        
    }
    
    TEST (Script, BIP276) {
        
        digest160 digest_one {"0x1111111111111111111111111111111111111111"};
        digest160 digest_two {"0x2222222222222222222222222222222222222222"};
        
        bytes script_p2pkh_one = pay_to_address::script (digest_one);
        bytes script_p2pkh_two = pay_to_address::script (digest_two);
        
        string human_data_one = typed_data::write (typed_data::mainnet, script_p2pkh_one);
        string human_data_two = typed_data::write (typed_data::mainnet, script_p2pkh_two);
        
        EXPECT_NE (human_data_one, human_data_two);
        
        typed_data recovered_one = typed_data::read (human_data_one);
        typed_data recovered_two = typed_data::read (human_data_two);
        
        EXPECT_EQ (recovered_one.Data, script_p2pkh_one);
        EXPECT_EQ (recovered_two.Data, script_p2pkh_two);
        
    }

}

#pragma clang diagnostic pop
