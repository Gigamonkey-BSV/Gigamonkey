// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/signature.hpp>
#include <gigamonkey/script/pattern/pay_to_address.hpp>
#include <gigamonkey/script/pattern/pay_to_pubkey.hpp>
#include <gigamonkey/script/pattern/multisig.hpp>
#include <gigamonkey/wif.hpp>
#include <gigamonkey/script/machine.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    // sighash::all means that all outputs are signed, so none can be changed. 
    // sighash::none means that no outputs are signed, so any can be changed. 
    // sighash::single means that only the output at the same index as the input being evaluated is signed. 
    // sighash::anyone_can_pay means that the inputs are not signed, so they can be changed. 
    // sighash::fork_id was added with Bitcoin Cash and means that OP_CODESEPARATORs are not removed. 
    
    // possible for sighash::none. 
    bool expect_can_mutate_corresponding_output (sighash::directive d) {
        return sighash::base (d) == sighash::none;
    }
    
    // possible for sighash::none and sighash::single. 
    bool expect_can_mutate_other_output (sighash::directive d) {
        return sighash::base (d) != sighash::all;
    }
    
    // possible for sighash::none and sighash::single. 
    bool expect_can_add_input (sighash::directive d) {
        return sighash::is_anyone_can_pay (d);
    }
    
    bool expect_can_add_code_separator (sighash::directive d) {
        return !sighash::has_fork_id (d);
    }
    
    bool expect_can_change_amount (sighash::directive d) {
        return !sighash::has_fork_id (d);
    }
    
    incomplete::transaction add_input (const incomplete::transaction &tx) {
        return incomplete::transaction {tx.Version,
            tx.Inputs << incomplete::input {outpoint {digest256 {uint256 {2}}, 2}},
            tx.Outputs, tx.LockTime};
    }
    
    output mutate (const output &o) {
        return output {o.Value + satoshi {1}, pay_to_address::script (digest160 {pay_to_address (o.Script).Address + 1})};
    }
    
    incomplete::transaction mutate_output (const incomplete::transaction &tx, index i) {
        cross<output> outs;
        for (const output &out : tx.Outputs) outs.push_back (out);
        outs[i] = mutate (outs[i]);
        list<output> new_outs;
        for (const output &out : outs) new_outs <<= out;
        return incomplete::transaction {tx.Version, tx.Inputs, new_outs, tx.LockTime};
    }
    
    sighash::document add_code_separator (const sighash::document &doc) {
        return {doc.Transaction, doc.InputIndex, doc.RedeemedValue, doc.ScriptCode << OP_CODESEPARATOR};
    }
    
    sighash::document change_value (const sighash::document &doc) {
        return {doc.Transaction, doc.InputIndex, doc.RedeemedValue + satoshi {1}, doc.ScriptCode};
    }

    sighash::directive add_chronicle (sighash::directive d) {
        return d | sighash::chronicle;
    }

    bool is_original_sighash_algorithm (sighash::directive d) {
        return (d & sighash::chronicle) || !(d & sighash::fork_id);
    }
    
    // test that the chronicle signature is the same as the original algorithm.
    // 0x20 is always available.
    // if flag FORKID is not set, then 0x20 does nothing.
    // if flag FORKID is set, then use of 0x40 is also available.
    // if REQUIRE_FORKID is set, then the only way to get the
    // original signature algorithm is to use 0x20.
    TEST (Signature, Sighash) {

        index input_index = 0;
        satoshi redeemed_value {0xfeee};

        auto scriptx = decompile (pay_to_address::script (digest160 {uint160 {"0xdddddddddd000000000000000000006767676791"}}));

        incomplete::transaction txi {
            {incomplete::input {
                outpoint {digest256 {uint256 {"0xaa00000000000000000000000000000000000000000000555555550707070707"}}, 0xcdcdcdcd},
                0xfedcba09}}, {
                output {1, pay_to_address::script (digest160 {uint160 {"0xbb00000000000000000000000000006565656575"}})},
                output {2, pay_to_address::script (digest160 {uint160 {"0xcc00000000000000000000000000002929292985"}})}},
            5};

        incomplete::transaction txi_mutate_same_output = mutate_output (txi, input_index);
        incomplete::transaction txi_mutate_different_output = mutate_output (txi, input_index + 1);
        incomplete::transaction txi_added_input = add_input (txi);

        sighash::document doc {txi, input_index, redeemed_value, scriptx};
        sighash::document doc_mutate_same_output {txi_mutate_same_output, input_index, redeemed_value, scriptx};
        sighash::document doc_mutate_different_output {txi_mutate_different_output, input_index, redeemed_value, scriptx};
        sighash::document doc_changed_value = change_value (doc);
        sighash::document doc_added_code_separator = add_code_separator (doc);
        sighash::document doc_added_input {txi_added_input, input_index, redeemed_value, scriptx};
        
        for (sighash::directive directive : list<sighash::directive> {
            directive (sighash::all, false, false, false),
            directive (sighash::all, true, true, false),
            directive (sighash::none, true, false, false),
            directive (sighash::none, true, true, false),
            directive (sighash::single, false, false, false),
            directive (sighash::single, false, true, false)}) {
            
            auto written = sighash::write (doc, directive);
            
            auto mutate_same_output = sighash::write (doc_mutate_same_output, directive);
            auto mutate_different_output = sighash::write (doc_mutate_different_output, directive);
            auto changed_value = sighash::write (doc_changed_value, directive);
            auto added_code_separator = sighash::write (doc_added_code_separator, directive);
            auto added_input = sighash::write (doc_added_input, directive);
            
            if (expect_can_mutate_corresponding_output (directive))
                EXPECT_EQ (written, mutate_same_output);
            else EXPECT_NE (written, mutate_same_output);

            if (expect_can_mutate_other_output (directive))
                EXPECT_EQ (written, mutate_different_output) << "expect \n\t" << written << " to equal \n\t" << mutate_different_output;
            else EXPECT_NE (written, mutate_different_output);
            
            if (expect_can_change_amount (directive))
                EXPECT_EQ (written, changed_value);
            else EXPECT_NE (written, changed_value);
            
            if (expect_can_add_code_separator (directive))
                EXPECT_EQ (written, added_code_separator);
            else EXPECT_NE (written, added_code_separator);
            
            if (expect_can_add_input (directive))
                EXPECT_EQ (written, added_input);
            else EXPECT_NE (written, added_input) << "expect \n\t" << written << " to not equal \n\t" << added_input;
            
            EXPECT_EQ (mutate_same_output, sighash::write (doc_mutate_same_output, directive));
            EXPECT_EQ (mutate_different_output, sighash::write (doc_mutate_different_output, directive));
            EXPECT_EQ (changed_value, sighash::write (doc_changed_value, directive));
            EXPECT_EQ (added_input, sighash::write (doc_added_input, directive));

            auto hashed = signature::hash (doc, directive);

            EXPECT_EQ (Hash256 (written), hashed);
            EXPECT_EQ (Hash256 (mutate_same_output), signature::hash (doc_mutate_same_output, directive));
            EXPECT_EQ (Hash256 (mutate_different_output), signature::hash (doc_mutate_different_output, directive));
            EXPECT_EQ (Hash256 (changed_value), signature::hash(doc_changed_value, directive));
            EXPECT_EQ (Hash256 (added_input), signature::hash (doc_added_input, directive));

            sighash::directive chronicle_added = add_chronicle (directive);

            if (is_original_sighash_algorithm (directive)) {
                EXPECT_EQ (signature::hash (doc, chronicle_added), hashed);
            } else {
                EXPECT_NE (signature::hash (doc, chronicle_added), hashed);
            }
            
        }
        
    }

    struct DER_test_case {
        std::string signature;
        std::string R;
        std::string S;
    };

    TEST (Signature, DER) {
        for (const auto &test_case : cross<DER_test_case> {
            {
                .signature = "30080202010002020100",
                .R = "256",
                .S = "256"
            },
            {
                .signature = "30080202010102020101",
                .R = "257",
                .S = "257"
            },
            {
                .signature = "3008020201ff02020100",
                .R = "511",
                .S = "256"
            },
            {
                .signature = "300802020100020201ff",
                .R = "256",
                .S = "511"
            },
            {
                .signature = "3008020201fe020201fd",
                .R = "510",
                .S = "509"
            },
            {
                .signature = "3009020300800002020100",
                .R = "32768",
                .S = "256"
            },
            {
                .signature = "3009020201000203008000",
                .R = "256",
                .S = "32768"
            },
            {
                .signature = "300a02030080010203008002",
                .R = "32769",
                .S = "32770"
            }
        }) {

            secp256k1::signature sig {*encoding::hex::read (test_case.signature)};

            secp256k1::complex z = secp256k1::complex (sig);

            EXPECT_EQ (N (z.R.Value), N (test_case.R));
            EXPECT_EQ (N (z.S.Value), N (test_case.S));

            secp256k1::signature written {z};

            EXPECT_EQ (sig, written) << "expected " << sig << " == " << written;

        }
    }
    
    TEST (Signature, FindAndDelete) {
        
        auto p1 = secp256k1::complex (secp256k1::scalar {123}, secp256k1::scalar {456});
        auto p2 = secp256k1::complex (secp256k1::scalar {789}, secp256k1::scalar {101});
        
        auto sig1 = signature (p1, directive (sighash::all));
        auto sig2 = signature (p2, directive (sighash::all));
        
        auto push_sig1 = instruction::push (sig1);
        auto push_sig2 = instruction::push (sig2);
        
        auto t1_1 = segment {OP_DUP, push_sig1, OP_ROLL};
        auto t1_2 = segment {push_sig1, OP_DUP, OP_ROLL};
        auto t1_3 = segment {OP_DUP, OP_ROLL, push_sig1};
        auto t1_4 = segment {push_sig1, OP_DUP, OP_ROLL, push_sig1};
        auto t1 = segment {OP_DUP, OP_ROLL};
        
        EXPECT_TRUE (find_and_delete (t1_1, push_sig1) == t1);
        EXPECT_TRUE (find_and_delete (t1_2, push_sig1) == t1);
        EXPECT_TRUE (find_and_delete (t1_3, push_sig1) == t1);
        EXPECT_TRUE (find_and_delete (t1_4, push_sig1) == t1);
        
    }

    sighash::document inline add_script_code (const redemption_document &doc, bytes script_code) {
        return sighash::document {doc.Transaction, doc.InputIndex, doc.RedeemedValue, decompile (script_code)};
    }

    // We use this tx for the signature tests.
    incomplete::transaction test_txi {
        {incomplete::input {
            outpoint {digest256 {uint256 {"0xaa00000000000000000000000000000000000000000000555555550707070707"}}, 0xcdcdcdcd},
            0xfedcba09}}, {
            output {1, pay_to_address::script (digest160 {uint160 {"0xbb00000000000000000000000000006565656575"}})}},
        5};

    data::array<bytes, 2> multisig_script (
        const redemption_document &doc,
        list<secp256k1::secret> s,
        list<secp256k1::pubkey> p,
        const instruction &null_push = OP_0) {

        script mp = multisig (s.size (), p).script ();

        sighash::document sd = add_script_code (doc, mp);

        list<signature> sigs;

        for (const secp256k1::secret &sk : s) sigs <<= sign (sk, sighash::all, sd);
        script ms = multisig::redeem (sigs, null_push);

        return {ms, mp};
    }

    TEST (Signature, LowS) {

        secp256k1::secret x {3023332};
        secp256k1::pubkey p = x.to_public ();

        bytes lock = pay_to_pubkey (Bitcoin::pubkey (p)).script ();
        bytes lockm = multisig (1, {Bitcoin::pubkey (p)}).script ();

        size_t input_index = 0;
        satoshi redeemed_value {0xfeee};

        sighash::document doc {test_txi, 0, redeemed_value, decompile (lock)};
        sighash::document docm {test_txi, 0, redeemed_value, decompile (lockm)};

        redemption_document rd {test_txi, 0, redeemed_value};

        // normally we would expect these to be normalized by
        // default but that is not what we want to test, so
        // we have an extra step that ensures to normalize them.
        auto sigx = sign (x, sighash::directive (), doc);
        auto sigxm = sign (x, sighash::directive (), docm);

        // low S versions of the signatures.
        auto sig_raw = sigx.raw ().normalize ();
        auto sigm_raw = sigxm.raw ().normalize ();

        auto sig = signature {sig_raw, sighash::directive ()};
        auto sigm = signature {sigm_raw, sighash::directive ()};

        EXPECT_TRUE (secp256k1::signature::normalized (sig_raw));
        EXPECT_TRUE (secp256k1::signature::normalized (sigm_raw));

        auto z = secp256k1::complex (sig_raw);
        auto zm = secp256k1::complex (sigm_raw);

        auto sz = -z;
        auto szm = -zm;

        // from both signatures we now extract S and invert it.
        auto sigi_raw = secp256k1::signature (sz);
        auto sigmi_raw = secp256k1::signature (szm);

        EXPECT_FALSE (secp256k1::signature::normalized (sigi_raw));
        EXPECT_FALSE (secp256k1::signature::normalized (sigmi_raw));

        EXPECT_EQ (sig_raw, sigi_raw.normalize ());
        EXPECT_EQ (sigm_raw, sigmi_raw.normalize ());

        auto sigi = signature {sigi_raw, sighash::directive ()};
        auto sigmi = signature {sigmi_raw, sighash::directive ()};

        bytes unlock = pay_to_pubkey::redeem (sig);
        bytes unlockm = multisig::redeem ({sigm});

        bytes unlocki = pay_to_pubkey::redeem (sigi);
        bytes unlockmi = multisig::redeem ({sigmi});

        // now we run the scripts

        script_config low_S_only {flag::VERIFY_LOW_S};
        script_config either_way {flag {}};

        // TODO don't just test scripts, test verify_signature

        EXPECT_EQ (Error::OK, (evaluate (unlock, lock, rd, low_S_only))) << "CHECKSIG Low S provided and required";
        EXPECT_EQ (Error::OK, (evaluate (unlock, lock, rd, either_way))) << "CHECKSIG Low S provided and not required";

        EXPECT_EQ (Error::OK, (evaluate (unlockm, lockm, rd, low_S_only))) << "CHECKMULTISIG Low S provided and required";
        EXPECT_EQ (Error::OK, (evaluate (unlockm, lockm, rd, either_way))) << "CHECKMULTISIG Low S provided and not required";

        EXPECT_EQ (Error::SIG_HIGH_S, (evaluate (unlocki, lock, rd, low_S_only))) << "CHECKSIG High S provided and prohibited";
        EXPECT_EQ (Error::OK, (evaluate (unlocki, lock, rd, either_way))) << "CHECKSIG High S provided and not prohibited";

        EXPECT_EQ (Error::SIG_HIGH_S, (evaluate (unlockmi, lockm, rd, low_S_only))) << "CHECKMULTISIG High S provided and prohibited";
        EXPECT_EQ (Error::OK, (evaluate (unlockmi, lockm, rd, either_way))) << "CHECKMULTISIG High S provided and not prohibited";

    }

    TEST (Signature, CompressedPubkey) {
        secp256k1::secret x {3023332};

        // we have two kinds of pubkeys
        // the first of these should always be ok,
        // the second will only work when
        // VERIFY_COMPRESSED_PUBKEYTYPE is turned off.
        secp256k1::pubkey pc = x.to_public (true);
        secp256k1::pubkey pu = x.to_public (false);

        // locking scripts for CHECKSIG and CHECKMULTISIG
        // using the two public keys.
        bytes lockc = pay_to_pubkey (Bitcoin::pubkey (pc)).script ();
        bytes lockcm = multisig (1, {pc}).script ();

        bytes locku = pay_to_pubkey (Bitcoin::pubkey (pu)).script ();
        bytes lockum = multisig (1, {pu}).script ();

        // generate the unlocking scripts.
        size_t input_index = 0;
        satoshi redeemed_value {0xfeee};

        sighash::document dc {test_txi, 0, redeemed_value, decompile (lockc)};
        sighash::document dcm {test_txi, 0, redeemed_value, decompile (lockcm)};

        sighash::document du {test_txi, 0, redeemed_value, decompile (locku)};
        sighash::document dum {test_txi, 0, redeemed_value, decompile (lockum)};

        auto sigc = sign (x, sighash::directive (), dc);
        auto sigcm = sign (x, sighash::directive (), dcm);

        auto sigu = sign (x, sighash::directive (), du);
        auto sigum = sign (x, sighash::directive (), dum);

        bytes unlockc = pay_to_pubkey::redeem (sigc);
        bytes unlockcm = multisig::redeem ({sigcm});

        bytes unlocku = pay_to_pubkey::redeem (sigu);
        bytes unlockum = multisig::redeem ({sigum});

        // the flags we will be checking for this test
        script_config compressed_required {flag::VERIFY_COMPRESSED_PUBKEYTYPE | flag::VERIFY_STRICTENC};
        script_config compressed_not_required {flag::VERIFY_STRICTENC};

        redemption_document rd {test_txi, 0, redeemed_value};

        EXPECT_EQ (Error::OK, (evaluate (unlockc, lockc, rd, compressed_required))) << "CHECKSIG compressed and required";
        EXPECT_EQ (Error::OK, (evaluate (unlockc, lockc, rd, compressed_not_required))) << "CHECKSIG compressed and not required";

        EXPECT_EQ (Error::OK, (evaluate (unlockcm, lockcm, rd, compressed_required))) << "CHECKMULTISIG compressed and required";
        EXPECT_EQ (Error::OK, (evaluate (unlockcm, lockcm, rd, compressed_not_required))) << "CHECKMULTISIG compressed and not required";

        EXPECT_EQ (Error::NONCOMPRESSED_PUBKEY, (evaluate (unlocku, locku, rd, compressed_required))) << "CHECKSIG uncompressed and prohibited";
        EXPECT_EQ (Error::OK, (evaluate (unlocku, locku, rd, compressed_not_required))) << "CHECKSIG uncompressed and not prohibited";

        EXPECT_EQ (Error::NONCOMPRESSED_PUBKEY,
            (evaluate (unlockum, lockum, rd, compressed_required)))
                << "CHECKMULTISIG uncompressed and prohibited";

        EXPECT_EQ (Error::OK, (evaluate (unlockum, lockum, rd, compressed_not_required))) << "CHECKMULTISIG uncompressed and not prohibited";

    }

    TEST (Signature, NULLFAIL) {
        secp256k1::secret x {3023332};
        secp256k1::pubkey p = x.to_public ();

        // the locking script to succeed on a failed signature verification.
        bytes lock = compile (segment {push_data (p), Bitcoin::OP_CHECKSIG, Bitcoin::OP_NOT});

        // locking script for multisig
        bytes lockm = compile (segment {} << OP_1 << push_data (p) << OP_1 << OP_CHECKMULTISIG << OP_NOT);

        bytes unlock_null = compile (segment {OP_0});
        bytes unlock_not_null = compile (segment {OP_1});

        // two versions of multisig unlocking script.
        bytes unlockm_null = compile (segment {OP_0, OP_0});
        bytes unlockm_not_null = compile (segment {OP_0, OP_1});

        // not null scripts should work only when the flag is turned on, null scripts work in either case.
        script_config null_fail {flag::VERIFY_NULLFAIL | flag::VERIFY_STRICTENC};
        script_config not_null_fail {flag::VERIFY_STRICTENC};

        // generate the unlocking scripts.
        size_t input_index = 0;
        satoshi redeemed_value {0xfeee};

        redemption_document rd {test_txi, 0, redeemed_value};
        std::cout << "evaluate failing case with script " << decompile (unlock_null) << decompile (lock) << std::endl;
        EXPECT_EQ (Error::OK, (evaluate (unlock_null, lock, rd, null_fail))) << "CHECKSIG null invalid sig and required";

        EXPECT_EQ (Error::OK, (evaluate (unlock_null, lock, rd, not_null_fail))) << "CHECKSIG null invalid sig and not required";

        EXPECT_EQ (Error::OK, (evaluate (unlockm_null, lockm, rd, null_fail))) << "CHECKMULTISIG null invalid sig and required";
        EXPECT_EQ (Error::OK, (evaluate (unlockm_null, lockm, rd, not_null_fail))) << "CHECKMULTISIG null invalid sig and not required";

        EXPECT_EQ (Error::SIG_NULLFAIL,
            (evaluate (unlock_not_null, lock, rd, null_fail)))
                << "CHECKSIG not null invalid sig and prohibited";

        EXPECT_EQ (Error::OK, (evaluate (unlock_not_null, lock, rd, not_null_fail))) << "CHECKSIG not null invalid sig and not prohibited";

        EXPECT_EQ (Error::SIG_NULLFAIL,
            (evaluate (unlockm_not_null, lockm, rd, null_fail)))
                << "CHECKMULTISIG not null invalid sig and prohibited";

        EXPECT_EQ (Error::OK, (evaluate (unlockm_not_null, lockm, rd, not_null_fail))) << "CHECKMULTISIG not null invalid sig and not prohibited";
    }

    struct sighash_test {
        sighash::directive Directive;

        bool ValidForkIDDisabled;
        bool ValidForkIDRequired;
    };

    TEST (Signature, Checksig) {

        secp256k1::secret x {3023332};
        secp256k1::pubkey p = x.to_public ();

        bytes lock = pay_to_pubkey (Bitcoin::pubkey {p}).script ();
        bytes lockm = multisig (1, {p}).script ();

        size_t input_index = 0;
        satoshi redeemed_value {0xfeee};

        sighash::document doc {test_txi, 0, redeemed_value, decompile (lock)};
        sighash::document docm {test_txi, 0, redeemed_value, decompile (lockm)};

        redemption_document rd {test_txi, 0, redeemed_value};

        script_config no_fork_id {flag {}};
        script_config fork_id_enabled {flag::ENABLE_SIGHASH_FORKID};
        script_config fork_id_required {flag::ENABLE_SIGHASH_FORKID | flag::REQUIRE_SIGHASH_FORKID};

        for (const auto &test: list<sighash_test> {
            {directive (sighash::all, false, false, false), true,  false},
            {directive (sighash::all, false, true,  false), false, true},
            {directive (sighash::all, false, false, true),  true,  false},
            {directive (sighash::all, false, true,  true),  false, true}}) {

            bytes unlock = pay_to_pubkey::redeem (sign (x, test.Directive, doc));
            bytes unlockm = multisig::redeem ({sign (x, test.Directive, docm)});

            auto r = evaluate (unlock, lock, rd, no_fork_id);
            auto rm = evaluate (unlockm, lockm, rd, no_fork_id);

            if (test.ValidForkIDDisabled) {
                EXPECT_EQ (Error::OK, r) << "test CHECKSIG; forkid disabled -- success expected";
                EXPECT_EQ (Error::OK, rm) << "test CHECKMULTISIG; forkid disabled -- success expected";
            } else {
                EXPECT_EQ (Error::ILLEGAL_FORKID, r) << "test CHECKSIG; forkid disabled -- error expected";
                EXPECT_EQ (Error::ILLEGAL_FORKID, rm) << "test CHECKMULTISIG; forkid disabled -- error expected";
            }

            EXPECT_EQ (Error::OK, (evaluate (unlock, lock, rd, fork_id_enabled))) << "test CHECKSIG; forkid enabled -- success expected";
            EXPECT_EQ (Error::OK, (evaluate (unlockm, lockm, rd, fork_id_enabled))) << "test CHECKMULTISIG; forkid enabled -- success expected";

            r = evaluate (unlock, lock, rd, fork_id_required);
            rm = evaluate (unlockm, lockm, rd, fork_id_required);

            if (test.ValidForkIDRequired) {
                EXPECT_EQ (Error::OK, r) << "test CHECKSIG; forkid required -- success expected";
                EXPECT_EQ (Error::OK, rm) << "test CHECKMULTISIG; forkid required -- success expected";
            } else {
                EXPECT_EQ (Error::MUST_USE_FORKID, r) << "test CHECKSIG; forkid required -- error expected";
                EXPECT_EQ (Error::MUST_USE_FORKID, rm) << "test CHECKMULTISIG; forkid required -- error expected";
            }

        }

    }

    TEST (Signature, MultisigNULLDUMMY) {

        secp256k1::secret x {3023332};
        secp256k1::pubkey p = x.to_public ();

        bytes lock = multisig (1, {p}).script ();

        size_t input_index = 0;
        satoshi redeemed_value {0xfeee};

        sighash::document doc {test_txi, 0, redeemed_value, decompile (lock)};

        auto sig = sign (x, sighash::directive (), doc);

        bytes unlock = multisig::redeem ({sig});
        // it doesn't matter what we put here as long as it's not OP_0
        bytes unlockx = multisig::redeem ({sig}, OP_1);

        // now we run the scripts

        script_config null_dummy_required {flag::VERIFY_NULLDUMMY};
        script_config null_dummy_not_required {flag {}};

        redemption_document rd {test_txi, 0, redeemed_value};

        EXPECT_EQ (Error::OK, (evaluate (unlock, lock, rd, null_dummy_required))) << "CHECKSIG null dummy provided and required";
        EXPECT_EQ (Error::OK, (evaluate (unlock, lock, rd, null_dummy_not_required))) << "CHECKSIG null dummy provided and not required";

        EXPECT_EQ (Error::SIG_NULLDUMMY, (evaluate (unlockx, lock, rd, null_dummy_required))) << "CHECKSIG null dummy not provided and required";
        EXPECT_EQ (Error::OK, (evaluate (unlockx, lock, rd, null_dummy_not_required))) << "CHECKSIG null dummy not provided and not required";

    }

    TEST (Signature, Multisig) {
        incomplete::transaction tx {
            {incomplete::input {
                outpoint {
                    digest256 {uint256 {"0xaa00000000000000000000000000000000000000000000555555550707070707"}}, 0xcdcdcdcd},
                    0xfedcba09}}, {
                output {1, pay_to_address::script (digest160 {uint160 {"0xbb00000000000000000000000000006565656575"}})},
                output {2, pay_to_address::script (digest160 {uint160 {"0xcc00000000000000000000000000002929292985"}})}},
            5};

        redemption_document doc {tx, 0, satoshi {0xfeee}};

        auto k1 = secp256k1::secret (uint256 {123456});
        auto k2 = secp256k1::secret (uint256 {789012});
        auto k3 = secp256k1::secret (uint256 {345678});

        auto p1 = k1.to_public ();
        auto p2 = k2.to_public ();
        auto p3 = k3.to_public ();

        struct multisig_test {
            int Number;
            bool Expected;
            redemption_document Doc;
            data::array<bytes, 2> Test;

            Error run () {
                return evaluate (Test[0], Test[1], Doc, flag {});
            }

            void test () {
                Error r = run ();
                EXPECT_NE (bool (r), Expected) << Number << ": script " <<
                    decompile (Test[0]) << decompile (Test[1]) <<
                    " expect " << Expected << "; results in " << r;
            }

            multisig_test (int num, bool ex, const redemption_document &doc, list<secp256k1::secret> s, list<secp256k1::pubkey> p) :
                Number {num}, Expected {ex}, Doc {doc}, Test {multisig_script (doc, s, p)} {}
        };

        multisig_test {10,  true,  doc, {},           {}          }.test ();
        multisig_test {20,  false, doc, {k1},         {}          }.test ();
        multisig_test {30,  true,  doc, {},           {p1}        }.test ();
        multisig_test {40,  true,  doc, {k1},         {p1}        }.test ();
        multisig_test {50,  false, doc, {k2},         {p1}        }.test ();
        multisig_test {60,  true,  doc, {},           {p1, p2}    }.test ();
        multisig_test {70,  true,  doc, {k1},         {p1, p2}    }.test ();
        multisig_test {80,  false, doc, {k3},         {p1, p2}    }.test ();
        multisig_test {90,  true,  doc, {k1, k2},     {p1, p2}    }.test ();
        multisig_test {100, false, doc, {k2, k1},     {p1, p2}    }.test ();
        multisig_test {110, false, doc, {k1, k3},     {p1, p2}    }.test ();
        multisig_test {120, false, doc, {k2, k3},     {p1, p2}    }.test ();
        multisig_test {130, true,  doc, {},           {p1, p2, p3}}.test ();
        multisig_test {140, true,  doc, {k1},         {p1, p2, p3}}.test ();
        multisig_test {150, true,  doc, {k2},         {p1, p2, p3}}.test ();
        multisig_test {160, true,  doc, {k3},         {p1, p2, p3}}.test ();
        multisig_test {170, true,  doc, {k1, k3},     {p1, p2, p3}}.test ();
        multisig_test {180, false, doc, {k3, k1},     {p1, p2, p3}}.test ();
        multisig_test {190, true,  doc, {k1, k2, k3}, {p1, p2, p3}}.test ();
        multisig_test {200, false, doc, {k3, k2, k1}, {p1, p2, p3}}.test ();
        multisig_test {210, false, doc, {k2, k3, k1}, {p1, p2, p3}}.test ();

    }

    bytes transform_sig_verify (byte_slice b) {
        if (b.size () == 0) throw 0;

        byte verify;

        if (b[b.size () - 1] == OP_CHECKSIG) verify = OP_CHECKSIGVERIFY;
        if (b[b.size () - 1] == OP_CHECKMULTISIG) verify = OP_CHECKMULTISIGVERIFY;

        return data::write<bytes> (b.range (0, b.size () - 1), verify);
    }

    bytes transform_sig_verify (byte_slice b, byte result) {
        return data::write<bytes> (transform_sig_verify (b), result);
    }

    TEST (Signature, ChecksigVerify) {

        secp256k1::secret x {3023332};
        secp256k1::pubkey p = x.to_public ();

        size_t input_index = 0;
        satoshi redeemed_value {0xfeee};

        redemption_document rd {test_txi, 0, redeemed_value};

        auto get_unlock_p2pk = [] (const signature &x) {
            return pay_to_pubkey::redeem (x);
        };

        auto get_unlock_multisig = [] (const signature &x) {
            return multisig::redeem ({x});
        };

        struct test_case {
            bytes Script;
            std::function<bytes (const signature &)> Redeem;
        };

        for (const test_case &test : list<test_case> {
            {pay_to_pubkey (Bitcoin::pubkey (p)).script (), get_unlock_p2pk},
            {multisig (1, {Bitcoin::pubkey (p)}).script (), get_unlock_multisig}}) {

            bytes lock_error = transform_sig_verify (test.Script);

            bytes unlock_error = test.Redeem (sign (x, sighash::directive (),
                sighash::document {test_txi, 0, redeemed_value, decompile (lock_error)}));

            bytes lock_false = transform_sig_verify (test.Script, OP_FALSE);

            bytes unlock_false = test.Redeem (sign (x, sighash::directive (),
                sighash::document {test_txi, 0, redeemed_value, decompile (lock_false)}));

            bytes lock_true = transform_sig_verify (test.Script, OP_TRUE);

            bytes unlock_true = test.Redeem (sign (x, sighash::directive (),
                sighash::document {test_txi, 0, redeemed_value, decompile (lock_true)}));

            auto result_1 = evaluate (unlock_error, lock_error, flag {});

            EXPECT_EQ (Error::INVALID_STACK_OPERATION, result_1) << "OP_CHECKSIGVERIFY 1";

            EXPECT_EQ (Error::FAIL, (evaluate (unlock_false, lock_false, flag {}))) << "OP_CHECKSIGVERIFY 2";

            EXPECT_EQ (Error::OK, (evaluate (unlock_true, lock_true, flag {}))) << "OP_CHECKSIGVERIFY 3";
        }

    }

}

