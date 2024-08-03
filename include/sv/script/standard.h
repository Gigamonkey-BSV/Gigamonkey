// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_SCRIPT_STANDARD_H
#define BITCOIN_SCRIPT_STANDARD_H

#include <cstdint>
#include <sv/script/script_num.h>
//#include <data/cross.hpp>
//#include <gigamonkey/script/stack.hpp>
#include <gigamonkey/script/flags.h>
#include <gigamonkey/script/error.h>
#include <gigamonkey/script/config.hpp>

static const bool DEFAULT_ACCEPT_DATACARRIER = true;

class CPubKey;
class CScript;
class CTransaction;
class CKeyID;
class CScript;

//!< bytes (+1 for OP_RETURN, +2 for the pushdata opcodes)
static const uint64_t DEFAULT_DATA_CARRIER_SIZE = UINT32_MAX;
extern bool fAcceptDatacarrier;

enum txnouttype {
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA,
};

const char *GetTxnOutputType (txnouttype t);

/**
 * Return public keys or hashes from scriptPubKey, for 'standard' transaction
 * types.
 */
bool Solver (const CScript &scriptPubKey, bool genesisEnabled, txnouttype &typeRet,
    std::vector<std::vector<uint8_t>> &vSolutionsRet);
    
//CScript GetScriptForRawPubKey (const CPubKey &pubkey);
//CScript GetScriptForMultisig (int nRequired, const std::vector<CPubKey> &keys);

#endif // BITCOIN_SCRIPT_STANDARD_H
