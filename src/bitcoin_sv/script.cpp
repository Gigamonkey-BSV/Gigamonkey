// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/script.hpp>
#include "script/interpreter.h"
#include "taskcancellation.h"
#include "streams.h"
#include "config.h"
#include "policy/policy.h"

// not in use but required by config.h dependency
bool fRequireStandard = true;

namespace Gigamonkey::Bitcoin {
    
    evaluated evaluate_script(const script& unlock, const script& lock, const BaseSignatureChecker& checker) {
        evaluated Response;
        std::optional<bool> response = VerifyScript(
            GlobalConfig::GetConfig(), // Config. 
            false, // true for consensus rules, false for policy rules.  
            task::CCancellationSource::Make()->GetToken(), 
            CScript(unlock.begin(), unlock.end()), 
            CScript(lock.begin(), lock.end()), 
            StandardScriptVerifyFlags(true, true), // Flags. I don't know what these should be. 
            checker, 
            &Response.Error);
        if (response.has_value()) {
            Response.Return = *response;
        } 
        return Response;
    }
    
    class DummySignatureChecker : public BaseSignatureChecker {
    public:
        DummySignatureChecker() {}

        bool CheckSig(const std::vector<uint8_t> &scriptSig,
                    const std::vector<uint8_t> &vchPubKey,
                    const CScript &scriptCode, bool enabledSighashForkid) const override {
            return true;
        }
    };
    
    evaluated evaluate_script(const script& unlock, const script& lock) {
        return evaluate_script(unlock, lock, DummySignatureChecker{});
    }
    
    evaluated evaluate_script(const script& unlock, const script& lock, const input_index& v) {
        CDataStream stream{(const char*)(v.Transaction.data()), 
            (const char*)(v.Transaction.data() + v.Transaction.size()), SER_NETWORK, PROTOCOL_VERSION};
        CTransaction ctx{deserialize, stream}; 
        return evaluate_script(lock, unlock, TransactionSignatureChecker(&ctx, v.Index, Amount(int64(v.value()))));
    }

}
