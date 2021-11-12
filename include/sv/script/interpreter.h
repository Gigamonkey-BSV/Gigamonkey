// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 Bitcoin Association
// Copyright (d) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include <sv/script/script_num.h>
#include <gigamonkey/script/flags.h>
#include <gigamonkey/script/error.h>
#include <sv/hash.h>
#include "sighashtype.h"
#include "limitedstack.h"
#include <data/cross.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class CPubKey;
class CScript;
class CScriptConfig;
class CTransaction;
class uint256;

namespace task
{
  class CCancellationToken;
}

class BaseSignatureChecker {
public:
    virtual bool CheckSig(const std::vector<uint8_t> &scriptSig,
                          const std::vector<uint8_t> &vchPubKey,
                          const CScript &scriptCode, bool enabledSighashForkid) const {
        return false;
    }

    virtual bool CheckLockTime(const CScriptNum &nLockTime) const {
        return false;
    }

    virtual bool CheckSequence(const CScriptNum &nSequence) const {
        return false;
    }

    virtual ~BaseSignatureChecker() {}
};

/**
* EvalScript function evaluates scripts against predefined limits that are
* set by either policy rules or consensus rules. Consensus parameter determines if
* consensus rules (value=true) must be used or if policy rules(value=false) should be used.
* Consensus should be true when validating scripts of transactions that are part of block
* and it should be false when validating scripts of transactions that are validated for acceptance to mempool
*/
std::optional<bool> EvalScript(
    const CScriptConfig& config,
    bool consensus,
    const task::CCancellationToken& token,
    LimitedStack& stack,
    const CScript& script,
    uint32_t flags,
    const BaseSignatureChecker& checker,
    LimitedStack& altstack,
    long& ipc,
    std::vector<bool>& vfExec,
    std::vector<bool>& vfElse,
    ScriptError* error = nullptr);
std::optional<bool> EvalScript(
    const CScriptConfig& config,
    bool consensus,
    const task::CCancellationToken& token,
    LimitedStack& stack,
    const CScript& script,
    uint32_t flags,
    const BaseSignatureChecker& checker,
    ScriptError* error = nullptr);
std::optional<bool> VerifyScript(
    const CScriptConfig& config,
    bool consensus,
    const task::CCancellationToken& token,
    const CScript& scriptSig,
    const CScript& scriptPubKey,
    uint32_t flags,
    const BaseSignatureChecker& checker,
    ScriptError* serror = nullptr);

#endif // BITCOIN_SCRIPT_INTERPRETER_H
