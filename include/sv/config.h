// Copyright (c) 2017 Amaury SÉCHET
// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_CONFIG_H
#define BITCOIN_CONFIG_H

static_assert(sizeof(void*) >= 8, "32 bit systems are not supported");

#include "amount.h"
#include "consensus/consensus.h"
#include "policy/policy.h"
#include "script/standard.h"
//#include "validation.h"
#include "script_config.h"

#include <boost/noncopyable.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <set>

class CChainParams;
struct DefaultBlockSizeParams;

class GlobalConfig final : public boost::noncopyable, public CScriptConfig {
public:
    GlobalConfig();

    bool SetMaxOpsPerScriptPolicy(int64_t maxOpsPerScriptPolicyIn, std::string* error);
    uint64_t GetMaxOpsPerScript(bool isGenesisEnabled, bool consensus) const override;

    bool SetMaxPubKeysPerMultiSigPolicy(int64_t maxPubKeysPerMultiSigIn, std::string* error = nullptr);
    uint64_t GetMaxPubKeysPerMultiSig(bool isGenesisEnabled, bool consensus) const override;

    bool SetMaxStackMemoryUsage(int64_t maxStackMemoryUsageConsensusIn, int64_t maxStackMemoryUsagePolicyIn, std::string* err = nullptr);
    uint64_t GetMaxStackMemoryUsage(bool isGenesisEnabled, bool consensus) const override;

    bool SetMaxScriptSizePolicy(int64_t maxScriptSizePolicyIn, std::string* err = nullptr);
    uint64_t GetMaxScriptSize(bool isGenesisEnabled, bool isConsensus) const override;

    bool SetMaxScriptNumLengthPolicy(int64_t maxScriptNumLengthIn, std::string* err = nullptr);
    uint64_t GetMaxScriptNumLength(bool isGenesisEnabled, bool isConsensus) const override;

    // Reset state of this object to match a newly constructed one. 
    // Used in constructor and for unit testing to always start with a clean state
    void Reset(); 
    static GlobalConfig& GetConfig();

private:
    // All fileds are initialized in Reset()    
    CFeeRate feePerKB;
    CFeeRate blockMinFeePerKB;
    uint64_t preferredBlockFileSize;
    uint64_t factorMaxSendQueuesBytes;

    // Block size limits 
    // SetDefaultBlockSizeParams must be called before reading any of those
    bool  setDefaultBlockSizeParamsCalled;
    void  CheckSetDefaultCalled() const;

    // Defines when either maxGeneratedBlockSizeBefore or maxGeneratedBlockSizeAfter is used
    int64_t blockSizeActivationTime;
    uint64_t maxBlockSize;
    // Used when SetMaxBlockSize is called with value 0
    uint64_t defaultBlockSize;
    uint64_t maxGeneratedBlockSizeBefore;
    uint64_t maxGeneratedBlockSizeAfter;
    bool maxGeneratedBlockSizeOverridden;

    uint64_t maxTxSizePolicy;
    uint64_t minConsolidationFactor;
    uint64_t maxConsolidationInputScriptSize;
    uint64_t minConfConsolidationInput;
    bool acceptNonStdConsolidationInput;
    uint64_t dataCarrierSize;
    uint64_t limitAncestorCount;
    uint64_t limitSecondaryMempoolAncestorCount;

    bool testBlockCandidateValidity;

    int32_t genesisActivationHeight;

    int mMaxConcurrentAsyncTasksPerNode;

    int mMaxParallelBlocks;
    int mPerBlockScriptValidatorThreadsCount;
    int mPerBlockScriptValidationMaxBatchSize;

    uint64_t maxOpsPerScriptPolicy;

    uint64_t maxTxSigOpsCountPolicy;
    uint64_t maxPubKeysPerMultiSig;
    uint64_t genesisGracefulPeriod;

    std::chrono::milliseconds mMaxStdTxnValidationDuration;
    std::chrono::milliseconds mMaxNonStdTxnValidationDuration;

    uint64_t maxStackMemoryUsagePolicy;
    uint64_t maxStackMemoryUsageConsensus;

    uint64_t maxScriptSizePolicy;

    uint64_t maxScriptNumLengthPolicy;

    bool mAcceptNonStandardOutput;

    uint64_t mMaxCoinsViewCacheSize;
    uint64_t mMaxCoinsProviderCacheSize;

    uint64_t mMaxCoinsDbOpenFiles;

    uint64_t mMaxMempool;
    uint64_t mMaxMempoolSizeDisk;
    uint64_t mMempoolMaxPercentCPFP;
    uint64_t mMemPoolExpiry;
    uint64_t mMaxOrphanTxSize;
    int32_t mStopAtHeight;
    uint64_t mPromiscuousMempoolFlags;
    bool mIsSetPromiscuousMempoolFlags;

    std::set<uint256> mInvalidBlocks;

    std::set<std::string> mBannedUAClients;
    uint64_t maxMerkleTreeDiskSpace;
    uint64_t preferredMerkleTreeFileSize;
    uint64_t maxMerkleTreeMemoryCacheSize;

    std::set<std::string> invalidTxSinks;
    int64_t invalidTxFileSinkSize;

    // P2P parameters
    int64_t p2pHandshakeTimeout;
    unsigned int maxProtocolRecvPayloadLength;
    unsigned int maxProtocolSendPayloadLength;
    unsigned int recvInvQueueFactor;

    std::optional<bool> mDisableBIP30Checks;

};

#endif
