// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <bitcoin.hpp>
#include <key.h>
#include <script/sighashtype.h>

#include <script/bitcoinconsensus.h>
#include <script/script.h>

#include "sv.hpp"

namespace bitcoin {
    
    // create a valid signature for a transaction. 
    signature sign(output out, transaction tx, index x, secret key) {
        timechain::output::serialized o{out};
        CTransaction ct = sv::read_transaction(tx); 
        std::vector<byte> vchSig;
        
        CKey k{};
        k.Set(key.begin(), key.end(), 
            true // TODO I don't think this should matter though. 
        );
        bytes_view script = o.script();
        CScript cs = sv::read_script(script);
        SigHashType x{};
        ::uint256 hash = SignatureHash(cs, ct, index, x, Amount{(uint64)(o.value())});
        if (!k.Sign(hash, vchSig)) {
            return {};
        }

        vchSig.push_back(uint8_t(x.getRawSigHashType()));
        
        return vchSig;
    }
    
    // verify that a script is valid. 
    bool verify(transaction, index, satoshi, output, input) {
        CTransaction tx = read_transaction(transaction);
        TransactionSignatureChecker Checker {};
        uint32_t Flags;
        return VerifyScript(input, output, Flags, Checker);
    }
    
}

#endif

