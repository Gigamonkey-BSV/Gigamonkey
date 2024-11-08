// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <data/crypto/NIST_DRBG.hpp>
#include <gigamonkey/wif.hpp>
#include <gigamonkey/pay/BEEF.hpp>
#include <gigamonkey/pay/extended.hpp>
#include <gigamonkey/merkle/tree.hpp>
#include <gigamonkey/merkle/dual.hpp>
#include <gigamonkey/fees.hpp>
#include <gigamonkey/script/pattern/pay_to_address.hpp>
#include "gtest/gtest.h"
#include <type_traits>

namespace Gigamonkey {

    // We test extended format, SPV proof format, and BEEF format.

    // Bitcoin SPV proofs are in general a DAG. There are txs I will call
    // roots which represent the payment, and then there are antecedent
    // txs. The leaves of the proof are Merkle proofs. The nodes are
    // transactions that are confirmed but unmined.

    // Variables that need testing:
    //  * Number of txs in the payment (roots). These can be combinations
    //    of other test cases.
    //  * Leaves:
    //    * One leaf
    //    * two leaves, same tx
    //    * two leaves, different tx
    //  * Nodes:
    //    * depth 0, no nodes
    //    * depth 1, one node
    //    * depth 1, two nodes, same txs
    //    * depth 2, two nodes, different txs
    //    * depth 3, two nodes deeper in the graph that are
    //      * the same.
    //      * different.

    Bitcoin::transaction make_fake_root_tx (uint32 num_inputs, uint32 num_outputs, crypto::random &r);

    Bitcoin::transaction make_fake_node_tx (list<Bitcoin::prevout> inputs, uint32 num_outputs, Bitcoin::satoshi sats_per_output, crypto::random &r);

    Merkle::dual make_fake_merkle (uint32 txs_in_block, map<uint32, digest256> roots, crypto::random &r);

    Bitcoin::header make_next_fake_block (const digest256 &merkle_root, crypto::random &r);

    Bitcoin::prevout inline get_prevout (const Bitcoin::transaction &t, uint32_little i) {
        return Bitcoin::prevout {Bitcoin::outpoint {t.id (), i}, t.Outputs[i]};
    }

    void test_case (list<Bitcoin::transaction> payment, SPV::database &d) {
        // generate SPV proof.
        maybe<SPV::proof> proof = SPV::generate_proof (d, payment);
        EXPECT_TRUE (bool (proof)) << "proof should have been generated but was not";

        // make extended transactions
        list<extended::transaction> extended;
        EXPECT_NO_THROW (extended = list<extended::transaction> (*proof));

        // check extended transactions
        for (const extended::transaction &extx : extended) {
            auto extended_result = extx.valid ();
            EXPECT_TRUE (bool (extended_result)) << "extended transactions must be valid; result is " << extended_result;
        }

        // check SPV proof
        EXPECT_TRUE (proof->valid ()) << "proof should be valid but is not";

        // make BEEF
        BEEF beef {*proof};
        // check BEEF
        EXPECT_TRUE (beef.valid ());
        EXPECT_TRUE (beef.validate (d));

        // bytes and back
        EXPECT_EQ (beef, BEEF (bytes (beef)));

        // regenerate SPV proof.
        EXPECT_EQ (*proof, beef.read_SPV_proof (d));
    }

    TEST (SPVTest, TestSPV) {

        crypto::fixed_entropy e {bytes {hex_string {"abcdef0123456789abcdef0123456789"}}};
        crypto::NIST::DRBG r {crypto::NIST::DRBG::Hash, e};

        // We will need at least two fake blocks for testing containing
        // at least 3 mined txs. We will label these txs A, B, and C. Tx A
        // will be in a different block from B and C, which will be in the
        // same block. There should be other fake txs in these blocks. These
        // transactions will have merkle proofs but we don't have to generate
        // any other txs.

        Bitcoin::transaction tx_A = make_fake_root_tx (10, 13, r);
        Bitcoin::transaction tx_B = make_fake_root_tx (5, 7, r);
        Bitcoin::transaction tx_C = make_fake_root_tx (2, 8, r);

        auto merkle_1 = make_fake_merkle (25, {{4, tx_A.id ()}}, r);
        auto merkle_2 = make_fake_merkle (14, {{3, tx_B.id ()}, {7, tx_C.id ()}}, r);

        auto block_1 = make_next_fake_block (merkle_1.Root, r);
        auto block_2 = make_next_fake_block (merkle_2.Root, r);

        // make transactions H, I, J, N, O, P

        SPV::database::memory db {};

        EXPECT_TRUE (bool (db.insert (3, block_1)));
        EXPECT_TRUE (bool (db.insert (4, block_2)));

        for (const auto &leaf : merkle_1.leaves ()) db.insert (merkle_1[leaf.Digest]);
        for (const auto &leaf : merkle_2.leaves ()) db.insert (merkle_2[leaf.Digest]);

        db.insert (tx_A);
        db.insert (tx_B);
        db.insert (tx_C);

        // make all cases here
        list<Bitcoin::transaction> Payment;

        // case 1: D - depth 0, one leaf A
        Payment <<= make_fake_node_tx ({get_prevout (tx_A, 3)}, 1, 100000000, r);
/*
        // case 2: E - depth 0, one leaf but two inputs that redeem from B.
        Payment <<= make_fake_node_tx ({get_prevout (tx_B, 2), get_prevout (tx_B, 5)}, 1, 100000000, r);

        // case 3: F - depth 0, two leaves A and B.
        Payment <<= make_fake_node_tx ({get_prevout (tx_A, 1), get_prevout (tx_B, 6)}, 1, 100000000, r);

        // case 4: G - depth 0, two leaves B and C.
        Payment <<= make_fake_node_tx ({get_prevout (tx_B, 3), get_prevout (tx_C, 2)}, 1, 100000000, r);

        // define transactions H, I, J deriving from C, A and C, and B and C
        // respectively.

        Bitcoin::transaction tx_H = make_fake_node_tx ({get_prevout (tx_C, 1)}, 1, 90000000, r);
        Bitcoin::transaction tx_I = make_fake_node_tx ({get_prevout (tx_C, 3), get_prevout (tx_A, 2)}, 2, 90000000, r);
        Bitcoin::transaction tx_J = make_fake_node_tx ({get_prevout (tx_C, 4), get_prevout (tx_B, 4)}, 3, 60000000, r);

        // case 5: K - depth 1, one node H, one leaf.
        Payment <<= make_fake_node_tx ({get_prevout (tx_H, 0)}, 1, 80000000, r);

        // case 6: L - depth 1, one node I, two leaves.
        Payment <<= make_fake_node_tx ({get_prevout (tx_I, 0)}, 1, 80000000, r);

        // case 7: M - depth 1, one node J, two leaves.
        Payment <<= make_fake_node_tx ({get_prevout (tx_J, 0)}, 1, 50000000, r);

        // define transactions N, O, P deriving from I, J, J respectively.
        Bitcoin::transaction tx_N = make_fake_node_tx ({get_prevout (tx_I, 1)}, 2, 30000000, r);
        Bitcoin::transaction tx_O = make_fake_node_tx ({get_prevout (tx_J, 1)}, 1, 50000000, r);
        Bitcoin::transaction tx_P = make_fake_node_tx ({get_prevout (tx_J, 2)}, 1, 50000000, r);

        // case 8: Q - depth 2, nodes N, O
        Payment <<= make_fake_node_tx ({get_prevout (tx_N, 0), get_prevout (tx_O, 0)}, 1, 70000000, r);
        // case 9: R - depth 2, nodes N, P
        Payment <<= make_fake_node_tx ({get_prevout (tx_N, 1), get_prevout (tx_P, 0)}, 1, 70000000, r);

        for (Bitcoin::transaction t : Payment) test_case ({t}, db);*/

        // case 10: all the previous cases together.
        test_case (Payment, db);
    }

    // We start with a secret key.
    uint256 next_key {"0x00000600f00007000010e00080000200d0000003090000050000c00000400fc5"};

    // all keys that have been generated so far.
    std::map<digest160, Bitcoin::secret> keys;

    Bitcoin::secret get_next_key () {
        Bitcoin::secret key {Bitcoin::secret::test, secp256k1::secret {next_key}};
        keys[key.address ().Digest] = key;
        next_key++;
        return key;
    }

    digest160 get_next_address () {
        Bitcoin::secret key {Bitcoin::secret::test, secp256k1::secret {next_key}};
        digest160 address = key.address ().Digest;
        keys[address] = key;
        next_key++;
        return address;
    }

    Bitcoin::input random_input (crypto::random &r) {
        digest256 d;
        r >> d;
        uint32_little i;
        r >> i;

        bytes Script = Bitcoin::compile (Bitcoin::program {OP_1});

        return Bitcoin::input {Bitcoin::outpoint {d, i}, Script};
    }

    Bitcoin::transaction make_fake_root_tx (uint32 num_inputs, uint32 num_outputs, crypto::random &r) {
        list<Bitcoin::output> out;
        list<Bitcoin::input> in;

        for (uint32 i = 0; i < num_inputs; i++)
            in <<= random_input (r);

        for (uint32 i = 0; i < num_outputs; i++)
            out <<= Bitcoin::output {100000000, pay_to_address::script (get_next_address ())};

        return Bitcoin::transaction {1, in, out, 0};
    }

    Merkle::dual make_fake_merkle (uint32 txs_in_block, map<uint32, digest256> roots, crypto::random &r) {
        Merkle::leaf_digests ddd {};

        for (uint32 i = 0; i < txs_in_block; i++) {
            if (const auto *v = roots.contains (i); bool (v)) ddd <<= *v;
            else {
                digest256 d;
                r >> d;
                ddd <<= d;
            }
        }

        Merkle::dual dual (Merkle::tree {ddd});

        Merkle::map m {};
        for (const auto &[_, val] : roots) m = m.insert (val, dual.Paths[val]);

        return Merkle::dual {m, dual.Root};
    }

    stack<Bitcoin::header> Blocks;

    Bitcoin::header make_next_fake_block (const digest256 &merkle_root, crypto::random &r) {
        digest256 previous {0};
        if (data::size (Blocks) != 0) previous = Blocks.first ().hash ();
        Bitcoin::header h {1, previous, merkle_root, Bitcoin::timestamp {1}, work::compact::max (), 0};
        Blocks = Blocks << h;
        return h;
    }

    Bitcoin::sighash::directive directive = Bitcoin::directive (Bitcoin::sighash::all);

    Bitcoin::transaction make_fake_node_tx (list<Bitcoin::prevout> inputs, uint32 num_outputs, Bitcoin::satoshi sats_per_output, crypto::random &r) {
        list<Bitcoin::output> out;
        list<Bitcoin::incomplete::input> in;

        for (const Bitcoin::prevout &p : inputs)
            in <<= Bitcoin::incomplete::input {p.outpoint ()};

        for (uint32 i = 0; i < num_outputs; i++)
            out <<= Bitcoin::output {sats_per_output, pay_to_address::script (get_next_address ())};

        Bitcoin::incomplete::transaction tx {1, in, out, 0};

        list<bytes> scripts;

        uint32_little i = 0;
        for (const Bitcoin::prevout &p : inputs) {
            auto key = keys[pay_to_address {p.script ()}.Address];
            auto doc = Bitcoin::sighash::document {tx, i, p.value (), p.script ()};
            auto sig = key.sign (doc, directive);
            scripts <<= pay_to_address::redeem (sig, key.to_public ());
            i++;
        }

        return tx.complete (scripts);
    }
}

