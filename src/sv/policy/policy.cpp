// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

// NOTE: This file is intended to be customised by the end user, and includes
// only local node policy logic

#include <sv/policy/policy.h>
#include <sv/script/script_num.h>
#include <sv/taskcancellation.h>
#include <sv/validation.h>
#include <sv/script_config.h>

/**
 * Check transaction inputs to mitigate two potential denial-of-service attacks:
 *
 * 1. scriptSigs with extra data stuffed into them, not consumed by scriptPubKey
 * (or P2SH script)
 * 2. P2SH scripts with a crazy number of expensive CHECKSIG/CHECKMULTISIG
 * operations
 *
 * Why bother? To avoid denial-of-service attacks; an attacker can submit a
 * standard HASH... OP_EQUAL transaction, which will get accepted into blocks.
 * The redemption script can be anything; an attacker could use a very
 * expensive-to-check-upon-redemption script like:
 *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
 */
bool IsStandard(const CScriptConfig &config, const CScript &scriptPubKey, int32_t nScriptPubKeyHeight, txnouttype &whichType) {
    std::vector<std::vector<uint8_t>> vSolutions;
    if (!Solver(scriptPubKey, IsGenesisEnabled(config, nScriptPubKeyHeight), whichType, vSolutions)) {
        return false;
    }

    if (whichType == TX_MULTISIG) {
        // we don't require minimal encoding here because Solver method is already checking minimal encoding
        int m = CScriptNum(vSolutions.front(), false).getint();
        int n = CScriptNum(vSolutions.back(), false).getint();
        // Support up to x-of-3 multisig txns as standard
        if (n < 1 || n > 3) return false;
        if (m < 1 || m > n) return false;
    } else if (whichType == TX_NULL_DATA) {
        if (!fAcceptDatacarrier) {
            return false;
        }
    }

    return whichType != TX_NONSTANDARD;
}

std::optional<bool> AreInputsStandard(
    const task::CCancellationToken& token,
    const CScriptConfig& config,
    const CTransaction& tx,
    const CCoinsViewCache &mapInputs,
    const int32_t mempoolHeight)
{
    if (tx.IsCoinBase()) {
        // Coinbases don't use vin normally.
        return true;
    }

    for (size_t i = 0; i < tx.vin.size(); i++) {
        auto prev = mapInputs.GetCoinWithScript( tx.vin[i].prevout );
        assert(prev.has_value());
        assert(!prev->IsSpent());

        std::vector<std::vector<uint8_t>> vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript &prevScript = prev->GetTxOut().scriptPubKey;

        if (!Solver(prevScript, IsGenesisEnabled(config, prev.value(), mempoolHeight),
                    whichType, vSolutions)) {
            return false;
        }

        if (whichType == TX_SCRIPTHASH) {
            // Pre-genesis limitations are stricter than post-genesis, so LimitedStack can use UINT32_MAX as max size.
            LimitedStack stack(UINT32_MAX);
            // convert the scriptSig into a stack, so we can inspect the
            // redeemScript
            auto res =
                EvalScript(
                    config,
                    false,
                    token,
                    stack,
                    tx.vin[i].scriptSig,
                    SCRIPT_VERIFY_NONE,
                    BaseSignatureChecker());
            if (!res.has_value())
            {
                return {};
            }
            else if (!res.value())
            {
                return false;
            }
            if (stack.empty()) {
                return false;
            }
            
            // isGenesisEnabled is set to false, because TX_SCRIPTHASH is not supported after genesis
            bool sigOpCountError;
            CScript subscript(stack.back().begin(), stack.back().end());
            uint64_t nSigOpCount = subscript.GetSigOpCount(true, false, sigOpCountError);
            if (sigOpCountError || nSigOpCount > MAX_P2SH_SIGOPS) {
                return false;
            }
        }
    }

    return true;
}

CFeeRate dustRelayFee = CFeeRate(DUST_RELAY_TX_FEE);
static_assert(DUST_RELAY_TX_FEE == DEFAULT_MIN_RELAY_TX_FEE, "lowering only fees increases dust");
