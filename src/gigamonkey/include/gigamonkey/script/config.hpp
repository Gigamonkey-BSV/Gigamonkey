// Copyright (c) 2017 Amaury SÉCHET
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_CONFIG
#define GIGAMONKEY_SCRIPT_CONFIG

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <set>
#include <gigamonkey/numbers.hpp>
#include <gigamonkey/script/opcodes.h>

static_assert (sizeof (void*) >= 8, "32 bit systems are not supported");

namespace Gigamonkey::Bitcoin {

    // note: these flags do not perfectly correspond to the flags used in Bitcoin Core software.
    enum class flag : uint32 {
        VERIFY_NONE = 0,

        // Evaluate P2SH subscripts (softfork safe, BIP16).
        // outputs after genesis are not recognized as P2SH.
        VERIFY_P2SH = (1U << 0),

        // Passing a non-strict-DER signature or one with undefined hashtype to a
        // checksig operation causes script failure. Evaluating a pubkey that is not
        // (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script
        // failure.
        VERIFY_STRICTENC = (1U << 1),

        // Passing a non-strict-DER signature to a checksig operation causes script
        // failure (softfork safe, BIP62 rule 1)
        VERIFY_DERSIG = (1U << 2),

        // Passing a non-strict-DER signature or one with S > order/2 to a checksig
        // operation causes script failure
        // (softfork safe, BIP62 rule 5).
        // no longer required in script version 2.
        VERIFY_LOW_S = (1U << 3),

        // verify dummy stack item consumed by CHECKMULTISIG is of zero-length
        // (softfork safe, BIP62 rule 7).
        // no longer required in script version 2.
        VERIFY_NULLDUMMY = (1U << 4),

        // Using a non-push operator in the scriptSig causes script failure
        // (softfork safe, BIP62 rule 2).
        // no longer required in script version 2.
        VERIFY_SIGPUSHONLY = (1U << 5),

        // Require minimal encodings for all push operations (OP_0... OP_16,
        // OP_1NEGATE where possible, direct pushes up to 75 bytes, OP_PUSHDATA up
        // to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating any other
        // push causes the script to fail (BIP62 rule 3). In addition, whenever a
        // stack element is interpreted as a number, it must be of minimal length
        // (BIP62 rule 4).
        // (softfork safe)
        // no longer required in script version 2.
        VERIFY_MINIMALDATA = (1U << 6),

        // Discourage use of NOPs reserved for upgrades (NOP1-10)
        //
        // Provided so that nodes can avoid accepting or mining transactions
        // containing executed NOP's whose meaning may change after a soft-fork,
        // thus rendering the script invalid; with this flag set executing
        // discouraged NOPs fails the script. This verification flag will never be a
        // mandatory flag applied to scripts in a block. NOPs that are not executed,
        // e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
        VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),

        // Require that only a single stack element remains after evaluation. This
        // changes the success criterion from "At least one stack element must
        // remain, and when interpreted as a boolean, it must be true" to "Exactly
        // one stack element must remain, and when interpreted as a boolean, it must
        // be true".
        // (softfork safe, BIP62 rule 6)
        //
        // Note: CLEANSTACK should never be used without P2SH or WITNESS.
        //
        // no longer required in script version 2.
        VERIFY_CLEANSTACK = (1U << 8),

        // Verify CHECKLOCKTIMEVERIFY
        //
        // See BIP65 for details.
        // disabled after genesis
        VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

        // support CHECKSEQUENCEVERIFY opcode
        //
        // See BIP112 for details
        // disabled after genesis.
        VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

        // Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
        // no longer required in script version 2.
        VERIFY_MINIMALIF = (1U << 13),

        // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
        // no longer required in script version 2.
        VERIFY_NULLFAIL = (1U << 14),

        // Public keys in scripts must be compressed
        //
        // no longer required in script version 2.
        VERIFY_COMPRESSED_PUBKEYTYPE = (1U << 15),

        // Do we accept signature using SIGHASH_FORKID
        ENABLE_SIGHASH_FORKID = (1U << 16),

        // is forkid required?
        // no longer required after chronicle.
        REQUIRE_SIGHASH_FORKID = (1U << 17),

        // OP_RETURN on its own is no longer a valid script.
        SAFE_RETURN_DATA = (1U << 19),

        ENABLE_BIG_NUMBERS = (1U << 20),

        ENABLE_GENESIS_STACK_LIMITS = (1U << 21),

        ENABLE_CUSTOM_SCRIPT_LIMITS = (1U << 22),

        ENABLE_GENESIS_OPCODES = (1U << 24),

        ENABLE_CHRONICLE_OPCODES = (1U << 25),

        // Not actual flag. Used for marking largest flag value.
        FLAG_LAST = (1U << 26)

    };

    constexpr flag operator & (flag, flag);
    constexpr flag operator | (flag, flag);
    constexpr flag operator ~ (flag);

    std::ostream inline &operator << (std::ostream &o, flag x) {
        return o << uint32 (x);
    }

    // P2SH: enabled in Bitcoin core, disabled after Genesis for new scripts.
    constexpr bool verify_P2SH (flag);
    constexpr bool verify_signature_strict (flag);
    constexpr bool verify_signature_DER (flag);
    constexpr bool verify_signature_low_S (flag);
    constexpr bool verify_null_dummy (flag);
    constexpr bool verify_unlock_push_only (flag);
    constexpr bool verify_minimal_push (flag);
    constexpr bool verify_discourage_upgradable_NOPs (flag);
    constexpr bool verify_clean_stack (flag);
    constexpr bool verify_check_locktime_verify (flag);
    constexpr bool verify_check_sequence_verify (flag);
    constexpr bool verify_minimal_if (flag);
    constexpr bool verify_null_fail (flag);
    constexpr bool verify_compressed_pubkey (flag);

    constexpr bool fork_ID_enabled (flag);
    constexpr bool fork_ID_required (flag);

    constexpr bool custom_script_limits (flag);
    constexpr bool safe_return_data (flag);
    constexpr bool enable_genesis_stack (flag);
    constexpr bool enable_genesis_opcodes (flag);
    constexpr bool enable_chronical_opcodes (flag);

    enum class epoch {
        core,
        cash,
        exodus,
        genesis,
        chronicle
    };

    constexpr flag profile (epoch, uint32 tx_version);

    constexpr flag pre_genesis_profile ();
    constexpr flag genesis_profile ();

    /*
     * script configuration depends on 3 things
     *   * script version
     *   * flags
     *   * script limits
     *
     * The script version is a Bitcoin integer that is pushed to the
     * stack when OP_VER is called.
     *
     * flags have to do with updates to the scripting engine that were
     * added as Bitcoin was corrupted. Thus, specific configurations of
     * flags have to do with how the engine was expected to work at
     * different times.
     *
     * For flags, we define a profile in terms of two parameters:
     *   * utxo before or after genesis
     *   * version 1 or version 2
     * The genesis update has to do with many things, including pay to
     * script hash, big numbers, OP_RETURN behavior, and script limits.
     * Version 1 versus version 2 has to do with malleability checks.
     *
     * Script limits were fixed numbers considered to be part of the
     * protocol in BTC. In the genesis update these were changed to
     * adjustable parameters with maximum values that are much bigger
     * than before.
     *
     * The script_config can be initialized with parameters for
     * version, flags, and script_limits. There are also simplified
     * parameters which load standard profiles.
     *
     * Default configuration; version = 1 and use consensus parameters.
     *   script_config {}
     *
     * Infer flags from version. Assume after genesis
     * and use consensus parameters.
     *   script_config {version number};
     *
     * Assume version 1, use consensus parameters
     *   script_config {bool after_genesis};
     *
     * Use consensus parameters.
     *   script_config {version number, bool utxo_after_genesis};
     *
     * Use specific flags and use consensus parameters
     *   script_config {version number, flags};
     *
     * Use version 1
     *   script_config {bool after_genesis, bool consensus};
     *   script_config {flags bool consensus};
     *
     *   script_config {version number, bool after_genesis, bool consesus};
     *   script_config {version number, bool after_genesis, bool consesus};
     *
     * script_config can be constructed with these three
     * parameters with defauts that provide the values
     * corresponding to the latest versions. We also provide
     * the options to construct script_config in terms
     * of a more limited set of parameters that load various
     * historical versions of the interpreter.
     *
     * For flags, we define a profile in terms of two
     * parameters:
     *   * tx version 1 or version 2
     *   * epoch
     *
     */
    struct script_config final {
        integer Version;

        flag Flags;

        uint64 MaxOpsPerScript;
        uint64 MaxPubKeysPerMultiSig;
        uint64 MaxStackMemoryUsage;
        uint64 MaxScriptNumLength;
        uint64 MaxScriptSize;

        static integer default_version () {
            return extend (integer (1), 4);
        }

        script_config (
            const integer &version = default_version (),
            epoch update = epoch::genesis,
            bool consensus = false);

        script_config (
            int version,
            epoch update = epoch::genesis,
            bool consensus = false): script_config {extend (integer (version), 4), update, consensus} {}

        script_config (
            epoch update,
            bool consensus = false): script_config {default_version (), update, consensus} {}

        script_config (
            const integer &version,
            flag flags,
            bool consensus = false);

        script_config (
            int version,
            flag flags,
            bool consensus = false) : script_config {extend (integer (version), 4), flags, consensus} {}

        script_config (
            flag flags,
            bool consensus = false): script_config {default_version (), flags, consensus} {}

        script_config (
            const integer &version,
            flag flags,
            uint64 max_ops_per_script,
            uint64 max_pubkeys_per_multisig,
            uint64 max_stack_memory_usage,
            uint64 max_script_num_length,
            uint64 max_script_size);

        script_config (
            int version,
            flag flags,
            uint64 max_ops_per_script,
            uint64 max_pubkeys_per_multisig,
            uint64 max_stack_memory_usage,
            uint64 max_script_num_length,
            uint64 max_script_size): script_config {
            extend (integer (version), 4), flags,
            max_ops_per_script,
            max_pubkeys_per_multisig,
            max_stack_memory_usage,
            max_script_num_length,
            max_script_size} {}

        script_config (
            flag flags,
            uint64 max_ops_per_script,
            uint64 max_pubkeys_per_multisig,
            uint64 max_stack_memory_usage,
            uint64 max_script_num_length,
            uint64 max_script_size) : script_config {
            default_version (), flags,
            max_ops_per_script,
            max_pubkeys_per_multisig,
            max_stack_memory_usage,
            max_script_num_length,
            max_script_size} {}

        constexpr bool verify_P2SH () const;
        constexpr bool verify_unlock_push_only () const;
        constexpr bool verify_minimal_push () const;
        constexpr bool verify_clean_stack () const;
        constexpr bool check_locktime () const;
        constexpr bool check_sequence () const;

        bool disabled (op) const;

        bool operator == (const script_config &x) const {
            return Bitcoin::string_equal (Version, x.Version) && Flags == x.Flags &&
                MaxOpsPerScript == x.MaxOpsPerScript &&
                MaxPubKeysPerMultiSig == x.MaxPubKeysPerMultiSig &&
                MaxStackMemoryUsage == x.MaxStackMemoryUsage &&
                MaxScriptNumLength == x.MaxScriptNumLength &&
                MaxScriptSize == x.MaxScriptSize;
        }

    };

    constexpr flag inline operator & (flag x, flag y) {
        return flag (static_cast<uint32> (x) & static_cast<uint32> (y));
    }

    constexpr flag inline operator | (flag x, flag y) {
        return flag (static_cast<uint32> (x) | static_cast<uint32> (y));
    }

    constexpr flag inline operator ~ (flag x) {
        return flag (~static_cast<uint32> (x));
    }

    constexpr bool inline verify_P2SH (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_P2SH);
    }

    constexpr bool inline verify_signature_strict (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_STRICTENC);
    }

    constexpr bool inline verify_signature_DER (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_DERSIG);
    }

    constexpr bool inline verify_signature_low_S (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_LOW_S);
    }

    constexpr bool inline verify_null_dummy (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_NULLDUMMY);
    }

    constexpr bool inline verify_unlock_push_only (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_SIGPUSHONLY);
    }

    constexpr bool inline verify_minimal_push (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_MINIMALDATA);
    }

    constexpr bool inline verify_discourage_upgradable_NOPs (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_DISCOURAGE_UPGRADABLE_NOPS);
    }

    constexpr bool inline verify_clean_stack (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_CLEANSTACK);
    }

    constexpr bool inline verify_check_locktime_verify (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_CHECKLOCKTIMEVERIFY);
    }

    constexpr bool inline verify_check_sequence_verify (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_CHECKSEQUENCEVERIFY);
    }

    constexpr bool inline verify_minimal_if (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_MINIMALIF);
    }

    constexpr bool inline verify_null_fail (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_NULLFAIL);
    }

    constexpr bool inline verify_compressed_pubkey (flag P) {
        return static_cast<uint32> (P & flag::VERIFY_COMPRESSED_PUBKEYTYPE);
    }

    constexpr bool inline fork_ID_enabled (flag P) {
        return static_cast<uint32> (P & flag::ENABLE_SIGHASH_FORKID);
    }

    constexpr bool inline fork_ID_required (flag P) {
        return static_cast<uint32> (P & flag::REQUIRE_SIGHASH_FORKID);
    }

    constexpr bool inline safe_return_data (flag P) {
        return static_cast<uint32> (P & flag::SAFE_RETURN_DATA);
    }

    constexpr bool inline enable_genesis_stack (flag P) {
        return static_cast<uint32> (P & flag::ENABLE_GENESIS_STACK_LIMITS);
    }

    constexpr bool inline enable_genesis_opcodes (flag P) {
        return static_cast<uint32> (P & flag::ENABLE_GENESIS_OPCODES);
    }

    constexpr bool custom_script_limits (flag P) {
        return static_cast<uint32> (P & flag::ENABLE_CUSTOM_SCRIPT_LIMITS);
    }

    constexpr bool inline script_config::verify_P2SH () const {
        return Bitcoin::verify_P2SH (Flags);
    }

    constexpr bool inline script_config::verify_unlock_push_only () const {
        return Bitcoin::verify_unlock_push_only (Flags);
    }

    constexpr bool inline script_config::verify_minimal_push () const {
        return Bitcoin::verify_minimal_push (Flags);
    }

    constexpr bool inline script_config::verify_clean_stack () const {
        return Bitcoin::verify_clean_stack (Flags);
    }

    constexpr bool inline script_config::check_locktime () const {
        return Bitcoin::verify_check_locktime_verify (Flags);
    }

    constexpr bool inline script_config::check_sequence () const {
        return Bitcoin::verify_check_sequence_verify (Flags);
    }

    constexpr flag inline mandatory_pre_genesis () {
        return flag::VERIFY_P2SH | flag::VERIFY_STRICTENC |
        flag::ENABLE_SIGHASH_FORKID | flag::VERIFY_LOW_S | flag::VERIFY_NULLFAIL;
    }

    constexpr flag inline optional_pre_genesis () {
        return flag::VERIFY_DERSIG |
            flag::VERIFY_MINIMALDATA | flag::VERIFY_NULLDUMMY |
            flag::VERIFY_DISCOURAGE_UPGRADABLE_NOPS | flag::VERIFY_CLEANSTACK |
            flag::VERIFY_CHECKLOCKTIMEVERIFY | flag::VERIFY_CHECKSEQUENCEVERIFY;
    }

    constexpr flag inline pre_genesis_profile () {
        return mandatory_pre_genesis () | optional_pre_genesis () |
            flag::REQUIRE_SIGHASH_FORKID | flag::VERIFY_MINIMALIF |
            flag::VERIFY_SIGPUSHONLY | flag::VERIFY_COMPRESSED_PUBKEYTYPE;
    }

    // genesis turns off P2SH, OP_CHECKSEQUENCEVERIFY, and OP_CHECKLOCKTIMEVERIFY and turns on
    constexpr flag inline genesis_profile () {
        return flag::ENABLE_SIGHASH_FORKID | flag::REQUIRE_SIGHASH_FORKID |
            flag::VERIFY_STRICTENC | flag::VERIFY_LOW_S | flag::VERIFY_NULLFAIL |
            flag::VERIFY_DERSIG | flag::VERIFY_MINIMALDATA | flag::VERIFY_NULLDUMMY |
            flag::VERIFY_DISCOURAGE_UPGRADABLE_NOPS | flag::VERIFY_CLEANSTACK |
            flag::SAFE_RETURN_DATA | flag::ENABLE_GENESIS_OPCODES |
            flag::ENABLE_GENESIS_STACK_LIMITS | flag::ENABLE_CUSTOM_SCRIPT_LIMITS |
            flag::VERIFY_SIGPUSHONLY | flag::VERIFY_MINIMALIF | flag::VERIFY_COMPRESSED_PUBKEYTYPE;
    }

    constexpr flag inline disabled_in_chronicle () {
        return flag::VERIFY_LOW_S | flag::VERIFY_NULLFAIL | flag::VERIFY_MINIMALDATA |
            flag::VERIFY_NULLDUMMY | flag::VERIFY_CLEANSTACK | flag::VERIFY_SIGPUSHONLY |
            flag::VERIFY_MINIMALIF | flag::VERIFY_COMPRESSED_PUBKEYTYPE;
    }

    constexpr flag inline profile (epoch update, int32 tx_version = 1) {
        return (update == epoch::exodus ? pre_genesis_profile () :
            update == epoch::genesis ? genesis_profile () :
            update == epoch::chronicle ? (genesis_profile () | flag::ENABLE_CHRONICLE_OPCODES) : flag {}) &
            (tx_version == 2 ? ~disabled_in_chronicle () : tx_version == 1 ? flag {~0u} : flag {0u});
    }
}

#endif
