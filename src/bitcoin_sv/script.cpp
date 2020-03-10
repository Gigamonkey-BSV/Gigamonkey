// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script.hpp>
#include "script/interpreter.h"
#include "script_config.h"
#include "policy/policy.h"

namespace Gigamonkey::Bitcoin {
    /*
    evaluated evaluate_script(script in, script out, const BaseSignatureChecker& checker) {
        evaluated Response;
        std::optional<bool> response = VerifyScript(
            {}, // Config. I don't know what this is. 
            true, // Specifices that we use consensus rules rather than our policy rules. 
            {}, // CCancellationToken. I don't know what this is. 
            CScript(out.begin(), out.end()), 
            CScript(in.begin(), in.end()), 
            StandardScriptVerifyFlags(true, true), // Flags. I don't know what these should be. 
            checker, 
            Response.Error);
        if (response.has_value()) {
            Response.Return = *response;
        } 
        return Response;
    }*/
    
    evaluated evaluate_script(script in, script out) {
        throw data::method::unimplemented{"evaluate_script"};
        //return evaluate_script(in, out, /* Need test signature checker. */);
    }
    
    evaluated evaluate_script(script in, script out, bytes_view transaction, uint32 index, satoshi amount) {
        throw data::method::unimplemented{"evaluate_script"};
        //CTransaction tx(transaction);
        //return evaluate_script(in, out, TransactionSignatureChecker(tx), index, amount);
    }

}
