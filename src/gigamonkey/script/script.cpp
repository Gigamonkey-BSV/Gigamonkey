// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script.hpp>
#include <sv/script/interpreter.h>
#include <sv/taskcancellation.h>
#include <sv/streams.h>
#include <sv/policy/policy.h>
#include <sv/version.h>

namespace sv {
    class CScriptConfig {};
}

namespace Gigamonkey::Bitcoin {
    
    evaluated evaluate_script(const script& unlock, const script& lock, const sv::BaseSignatureChecker& checker) {
        evaluated Response;
        std::optional<bool> response = sv::VerifyScript(
            {}, // Config. 
            false, // true for consensus rules, false for policy rules.  
            sv::task::CCancellationSource::Make()->GetToken(), 
            sv::CScript(unlock.begin(), unlock.end()), 
            sv::CScript(lock.begin(), lock.end()), 
            sv::StandardScriptVerifyFlags(true, true), // Flags. I don't know what these should be. 
            checker, 
            &Response.Error);
        if (response.has_value()) {
            Response.Return = *response;
        } 
        return Response;
    }
    
    class DummySignatureChecker : public sv::BaseSignatureChecker {
    public:
        DummySignatureChecker() {}

        bool CheckSig(const std::vector<uint8_t> &scriptSig,
                    const std::vector<uint8_t> &vchPubKey,
                    const sv::CScript &scriptCode, bool enabledSighashForkid) const override {
            return true;
        }
    };
    
    evaluated evaluate_script(const script& unlock, const script& lock) {
        return evaluate_script(unlock, lock, DummySignatureChecker{});
    }
    
    evaluated evaluate_script(const script& unlock, const script& lock, const input_index& transaction) {
        // transaction needs to be made into some stream but I don't know what that is. It's a
        // template parameter in this constructor. 
        sv::CDataStream stream{static_cast<const std::vector<uint8_t>&>(transaction.Transaction), sv::SER_NETWORK, sv::PROTOCOL_VERSION};
        sv::CTransaction tx{sv::deserialize, stream}; 
        return evaluate_script(lock, unlock, sv::TransactionSignatureChecker(&tx, transaction.Index, sv::Amount(int64(transaction.Output.Value))));
    }

}

