// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 Bitcoin Association
// Copyright (d) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_SCRIPT_INTERPRETER_H
#define BITCOIN_SCRIPT_INTERPRETER_H

#include <cstdint>
#include <sv/script/script_num.h>
#include <data/cross.hpp>
#include <gigamonkey/script/stack.hpp>
#include <gigamonkey/script/flags.h>
#include <gigamonkey/script/error.h>
#include <gigamonkey/script/config.hpp>

typedef Gigamonkey::Bitcoin::interpreter::element valtype;

typedef Gigamonkey::Bitcoin::interpreter::LimitedStack<valtype> LimitedStack;
typedef Gigamonkey::Bitcoin::interpreter::LimitedVector<valtype> LimitedVector;

class CPubKey;
class CScript;
class CTransaction;

/**
* EvalScript function evaluates scripts against predefined limits that are
* set by either policy rules or consensus rules. Consensus parameter determines if
* consensus rules (value=true) must be used or if policy rules(value=false) should be used.
* Consensus should be true when validating scripts of transactions that are part of block
* and it should be false when validating scripts of transactions that are validated for acceptance to mempool
*/
data::maybe<bool> EvalScript (
    const script_config &config,
    bool consensus,
    LimitedStack &stack,
    const CScript &script,
    uint32_t flags,
    LimitedStack &altstack,
    long &ipc,
    data::cross<bool> &vfExec,
    data::cross<bool> &vfElse,
    ScriptError *error = nullptr);

data::maybe<bool> EvalScript (
    const script_config &config,
    bool consensus,
    LimitedStack &stack,
    const CScript &script,
    uint32_t flags,
    ScriptError *error = nullptr);

data::maybe<bool> VerifyScript (
    const script_config &config,
    bool consensus,
    const CScript &scriptSig,
    const CScript &scriptPubKey,
    uint32_t flags,
    ScriptError *serror = nullptr);

#endif // BITCOIN_SCRIPT_INTERPRETER_H
