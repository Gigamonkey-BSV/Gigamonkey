// Copyright (c) 2017 The Bitcoin developers
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <sv/config.h>
//#include "chainparams.h"
#include <sv/consensus/consensus.h>
#include <sv/validation.h>
#include <sv/util.h>
//#include "consensus/merkle.h"

#include <boost/algorithm/string.hpp>
#include <limits>

namespace
{
    bool LessThan(
        int64_t argValue,
        std::string* err,
        const std::string& errorMessage,
        int64_t minValue)
    {
        if (argValue < minValue)
        {
            if (err)
            {
                *err = errorMessage;
            }
            return true;
        }
        return false;
    }

    bool LessThanZero(
        int64_t argValue,
        std::string* err,
        const std::string& errorMessage)
    {
        return LessThan( argValue, err, errorMessage, 0 );
    }
}

GlobalConfig::GlobalConfig() {
    Reset();
}

void GlobalConfig::Reset()
{
    feePerKB = CFeeRate {};
    blockMinFeePerKB = CFeeRate{DEFAULT_BLOCK_MIN_TX_FEE};
    preferredBlockFileSize = DEFAULT_PREFERRED_BLOCKFILE_SIZE;

    setDefaultBlockSizeParamsCalled = false;

    blockSizeActivationTime = 0;
    maxBlockSize = 0;
    defaultBlockSize = 0;
    maxGeneratedBlockSizeBefore = 0;
    maxGeneratedBlockSizeAfter = 0;
    maxGeneratedBlockSizeOverridden =  false;
    maxTxSizePolicy = DEFAULT_MAX_TX_SIZE_POLICY_AFTER_GENESIS;
    minConsolidationFactor = DEFAULT_MIN_CONSOLIDATION_FACTOR;
    maxConsolidationInputScriptSize = DEFAULT_MAX_CONSOLIDATION_INPUT_SCRIPT_SIZE;
    minConfConsolidationInput = DEFAULT_MIN_CONF_CONSOLIDATION_INPUT;
    acceptNonStdConsolidationInput = DEFAULT_ACCEPT_NON_STD_CONSOLIDATION_INPUT;

    dataCarrierSize = DEFAULT_DATA_CARRIER_SIZE;
    limitAncestorCount = DEFAULT_ANCESTOR_LIMIT;
    limitSecondaryMempoolAncestorCount = DEFAULT_SECONDARY_MEMPOOL_ANCESTOR_LIMIT;
    
    testBlockCandidateValidity = false;

    genesisActivationHeight = 0;

    mMaxParallelBlocks = DEFAULT_SCRIPT_CHECK_POOL_SIZE;
    mPerBlockScriptValidatorThreadsCount = DEFAULT_SCRIPTCHECK_THREADS;
    mPerBlockScriptValidationMaxBatchSize = DEFAULT_SCRIPT_CHECK_MAX_BATCH_SIZE;
    maxOpsPerScriptPolicy = DEFAULT_OPS_PER_SCRIPT_POLICY_AFTER_GENESIS;
    maxTxSigOpsCountPolicy = DEFAULT_TX_SIGOPS_COUNT_POLICY_AFTER_GENESIS;
    maxPubKeysPerMultiSig = DEFAULT_PUBKEYS_PER_MULTISIG_POLICY_AFTER_GENESIS;

    maxStackMemoryUsagePolicy = DEFAULT_STACK_MEMORY_USAGE_POLICY_AFTER_GENESIS;
    maxStackMemoryUsageConsensus = DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS;
    maxScriptSizePolicy = DEFAULT_MAX_SCRIPT_SIZE_POLICY_AFTER_GENESIS;

    maxScriptNumLengthPolicy = DEFAULT_SCRIPT_NUM_LENGTH_POLICY_AFTER_GENESIS;
    genesisGracefulPeriod = DEFAULT_GENESIS_GRACEFULL_ACTIVATION_PERIOD;

    mAcceptNonStandardOutput = true;

    mMaxCoinsViewCacheSize = 0;
    mMaxCoinsProviderCacheSize = DEFAULT_COINS_PROVIDER_CACHE_SIZE;

    maxProtocolRecvPayloadLength = DEFAULT_MAX_PROTOCOL_RECV_PAYLOAD_LENGTH;
    maxProtocolSendPayloadLength = DEFAULT_MAX_PROTOCOL_RECV_PAYLOAD_LENGTH * MAX_PROTOCOL_SEND_PAYLOAD_FACTOR;

    recvInvQueueFactor = DEFAULT_RECV_INV_QUEUE_FACTOR;

    mMaxMempool = DEFAULT_MAX_MEMPOOL_SIZE * ONE_MEGABYTE;
    mMaxMempoolSizeDisk = mMaxMempool * DEFAULT_MAX_MEMPOOL_SIZE_DISK_FACTOR;
    mMempoolMaxPercentCPFP = DEFAULT_MEMPOOL_MAX_PERCENT_CPFP;
    mMemPoolExpiry = DEFAULT_MEMPOOL_EXPIRY * SECONDS_IN_ONE_HOUR;
    mStopAtHeight = DEFAULT_STOPATHEIGHT;
    mPromiscuousMempoolFlags = 0;
    mIsSetPromiscuousMempoolFlags = false;

    mDisableBIP30Checks = std::nullopt;

}

bool GlobalConfig::SetMaxOpsPerScriptPolicy(int64_t maxOpsPerScriptPolicyIn, std::string* error)
{
    if (LessThanZero(maxOpsPerScriptPolicyIn, error, "Policy value for MaxOpsPerScript cannot be less than zero."))
    {
        return false;
    }
    uint64_t maxOpsPerScriptPolicyInUnsigned = static_cast<uint64_t>(maxOpsPerScriptPolicyIn);

    if (maxOpsPerScriptPolicyInUnsigned > MAX_OPS_PER_SCRIPT_AFTER_GENESIS)
    {
        if (error)
        {
            *error = "Policy value for MaxOpsPerScript must not exceed consensus limit of " + std::to_string(MAX_OPS_PER_SCRIPT_AFTER_GENESIS) + ".";
        }
        return false;
    }
    else if (maxOpsPerScriptPolicyInUnsigned == 0)
    {
        maxOpsPerScriptPolicy = MAX_OPS_PER_SCRIPT_AFTER_GENESIS;
    }
    else
    {
        maxOpsPerScriptPolicy = maxOpsPerScriptPolicyInUnsigned;
    }

    return true;
}

uint64_t GlobalConfig::GetMaxOpsPerScript(bool isGenesisEnabled, bool consensus) const
{
    if (!isGenesisEnabled)
    {
        return MAX_OPS_PER_SCRIPT_BEFORE_GENESIS; // no changes before genesis
    }

    if (consensus)
    {
        return MAX_OPS_PER_SCRIPT_AFTER_GENESIS; // use new limit after genesis
    }
    return maxOpsPerScriptPolicy;
}

bool GlobalConfig::SetMaxPubKeysPerMultiSigPolicy(int64_t maxPubKeysPerMultiSigIn, std::string* err)
{
    if (LessThanZero(maxPubKeysPerMultiSigIn, err, "Policy value for maximum public keys per multisig must not be less than zero"))
    {
        return false;
    }
    
    uint64_t maxPubKeysPerMultiSigUnsigned = static_cast<uint64_t>(maxPubKeysPerMultiSigIn);
    if (maxPubKeysPerMultiSigUnsigned > MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS)
    {
        if (err)
        {
            *err = "Policy value for maximum public keys per multisig must not exceed consensus limit of " + std::to_string(MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS) + ".";
        }
        return false;
    }
    else if (maxPubKeysPerMultiSigUnsigned == 0)
    {
        maxPubKeysPerMultiSig = MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS;
    }
    else
    {
        maxPubKeysPerMultiSig = maxPubKeysPerMultiSigUnsigned;
    }

    return true;
}

uint64_t GlobalConfig::GetMaxPubKeysPerMultiSig(bool isGenesisEnabled, bool consensus) const
{
    if (!isGenesisEnabled)
    {
        return MAX_PUBKEYS_PER_MULTISIG_BEFORE_GENESIS; // no changes before  genesis
    }

    if (consensus)
    {
        return MAX_PUBKEYS_PER_MULTISIG_AFTER_GENESIS; // use new limit after genesis
    }

    return maxPubKeysPerMultiSig;
}

bool GlobalConfig::SetMaxStackMemoryUsage(int64_t maxStackMemoryUsageConsensusIn, int64_t maxStackMemoryUsagePolicyIn, std::string* err)
{
    if (maxStackMemoryUsageConsensusIn < 0 || maxStackMemoryUsagePolicyIn < 0)
    {
        if (err)
        {
            *err = "Policy and consensus value for max stack memory usage must not be less than 0.";
        }
        return false;
    }

    if (maxStackMemoryUsageConsensusIn == 0)
    {
        maxStackMemoryUsageConsensus = DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS;
    }
    else
    {
        maxStackMemoryUsageConsensus = static_cast<uint64_t>(maxStackMemoryUsageConsensusIn);
    }

    if (maxStackMemoryUsagePolicyIn == 0)
    {
        maxStackMemoryUsagePolicy = DEFAULT_STACK_MEMORY_USAGE_CONSENSUS_AFTER_GENESIS;
    }
    else
    {
        maxStackMemoryUsagePolicy = static_cast<uint64_t>(maxStackMemoryUsagePolicyIn);
    }

    if (maxStackMemoryUsagePolicy > maxStackMemoryUsageConsensus)
    {
        if (err)
        {
            *err = "Policy value of max stack memory usage must not exceed consensus limit of " + std::to_string(maxStackMemoryUsageConsensus);
        }
        return false;
    }

    return true;
}

uint64_t GlobalConfig::GetMaxStackMemoryUsage(bool isGenesisEnabled, bool consensus) const
{
    // concept of max stack memory usage is not defined before genesis
    // before Genesis stricter limitations exist, so maxStackMemoryUsage can be infinite
    if (!isGenesisEnabled)
    {
        return INT64_MAX;
    }

    if (consensus)
    {
        return maxStackMemoryUsageConsensus;
    }

    return maxStackMemoryUsagePolicy;
}

void GlobalConfig::CheckSetDefaultCalled() const
{
    if (!setDefaultBlockSizeParamsCalled)
    {
        // If you hit this we created new instance of GlobalConfig without 
        // setting defaults
        throw std::runtime_error(
            "GlobalConfig::SetDefaultBlockSizeParams must be called before accessing block size related parameters");
    }
}

GlobalConfig& GlobalConfig::GetConfig()
{
    static GlobalConfig config {};
    return config;
}

bool GlobalConfig::SetMaxScriptNumLengthPolicy(int64_t maxScriptNumLengthIn, std::string* err)
{
    if (LessThanZero(maxScriptNumLengthIn, err, "Policy value for maximum script number length must not be less than 0."))
    {
        return false;
    }

    uint64_t maxScriptNumLengthUnsigned = static_cast<uint64_t>(maxScriptNumLengthIn);
    if (maxScriptNumLengthUnsigned > MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS)
    {
        if (err)
        {
            *err = "Policy value for maximum script number length must not exceed consensus limit of " + std::to_string(MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS) + ".";
        }
        return false;
    }
    else if (maxScriptNumLengthUnsigned == 0)
    {
        maxScriptNumLengthPolicy = MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS;
    }
    else if (maxScriptNumLengthUnsigned < MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS)
    {
        if (err)
        {
            *err = "Policy value for maximum script number length must not be less than " + std::to_string(MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS) + ".";
        }
        return false;
    }
    else
    {
        maxScriptNumLengthPolicy = maxScriptNumLengthUnsigned;
    }

    return true;
}

uint64_t GlobalConfig::GetMaxScriptNumLength(bool isGenesisEnabled, bool isConsensus) const
{
    if (!isGenesisEnabled)
    {
        return MAX_SCRIPT_NUM_LENGTH_BEFORE_GENESIS; // no changes before genesis
    }

    if (isConsensus)
    {
        return MAX_SCRIPT_NUM_LENGTH_AFTER_GENESIS; // use new limit after genesis
    }
    return maxScriptNumLengthPolicy; // use policy
}

bool GlobalConfig::SetMaxScriptSizePolicy(int64_t maxScriptSizePolicyIn, std::string* err) {
    if (LessThanZero(maxScriptSizePolicyIn, err, "Policy value for max script size must not be less than 0"))
    {
        return false;
    }
    uint64_t maxScriptSizePolicyInUnsigned = static_cast<uint64_t>(maxScriptSizePolicyIn);
    if (maxScriptSizePolicyInUnsigned > MAX_SCRIPT_SIZE_AFTER_GENESIS)
    {
        if (err)
        {
            *err = "Policy value for max script size must not exceed consensus limit of " + std::to_string(MAX_SCRIPT_SIZE_AFTER_GENESIS);
        }
        return false;
    }
    else if (maxScriptSizePolicyInUnsigned == 0 ) {
        maxScriptSizePolicy = MAX_SCRIPT_SIZE_AFTER_GENESIS;
    }
    else
    {
        maxScriptSizePolicy = maxScriptSizePolicyInUnsigned;
    }
    return true;
}

uint64_t GlobalConfig::GetMaxScriptSize(bool isGenesisEnabled, bool isConsensus) const {
    if (!isGenesisEnabled) 
    {
        return MAX_SCRIPT_SIZE_BEFORE_GENESIS;
    }
    if (isConsensus) 
    {
        return MAX_SCRIPT_SIZE_AFTER_GENESIS;
    }
    return maxScriptSizePolicy;
}
