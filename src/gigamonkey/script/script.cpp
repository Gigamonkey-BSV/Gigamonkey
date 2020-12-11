// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/script.hpp>

#include <sv/script/interpreter.h>
#include <sv/taskcancellation.h>
#include <sv/streams.h>
#include <sv/policy/policy.h>
#include <sv/version.h>
#include <sv/script_config.h>

namespace Gigamonkey::Bitcoin {
    
    struct script_config : bsv::CScriptConfig {
        uint64_t GetMaxOpsPerScript(bool isGenesisEnabled, bool isConsensus) const {
            throw 0;
        }
        
        uint64_t GetMaxScriptNumLength(bool isGenesisEnabled, bool isConsensus) const {
            throw 0;
        }
        
        uint64_t GetMaxScriptSize(bool isGenesisEnabled, bool isConsensus) const {
            throw 0;
        }
        
        uint64_t GetMaxPubKeysPerMultiSig(bool isGenesisEnabled, bool isConsensus) const {
            throw 0;
        }
        
        uint64_t GetMaxStackMemoryUsage(bool isGenesisEnabled, bool isConsensus) const {
            throw 0;
        }
        
        script_config() {
            throw 0;
        }
    };
    
    evaluated evaluate_script(const script& unlock, const script& lock, const bsv::BaseSignatureChecker& checker) {
        evaluated Response;
        std::optional<bool> response = bsv::VerifyScript(
            script_config{}, // Config. 
            false, // true for consensus rules, false for policy rules.  
            bsv::task::CCancellationSource::Make()->GetToken(), 
            bsv::CScript(unlock.begin(), unlock.end()), 
            bsv::CScript(lock.begin(), lock.end()), 
            bsv::StandardScriptVerifyFlags(true, true), // Flags. I don't know what these should be. 
            checker, 
            &Response.Error);
        if (response.has_value()) {
            Response.Return = *response;
        } 
        return Response;
    }
    
    class DummySignatureChecker : public bsv::BaseSignatureChecker {
    public:
        DummySignatureChecker() {}

        bool CheckSig(const std::vector<uint8_t> &scriptSig,
                    const std::vector<uint8_t> &vchPubKey,
                    const bsv::CScript &scriptCode, bool enabledSighashForkid) const override {
            return true;
        }
    };
    
    evaluated evaluate_script(const script& unlock, const script& lock) {
        return evaluate_script(unlock, lock, DummySignatureChecker{});
    }
    
    evaluated evaluate_script(const script& unlock, const script& lock, const input_index& transaction) {
        // transaction needs to be made into some stream but I don't know what that is. It's a
        // template parameter in this constructor. 
        bsv::CDataStream stream{static_cast<const std::vector<uint8_t>&>(transaction.Transaction), bsv::SER_NETWORK, bsv::PROTOCOL_VERSION};
        bsv::CTransaction tx{bsv::deserialize, stream}; 
        return evaluate_script(lock, unlock, bsv::TransactionSignatureChecker(&tx, transaction.Index, bsv::Amount(int64(transaction.Output.Value))));
    }

}

