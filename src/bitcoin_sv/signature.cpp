// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/signature.hpp>
#include <sv/key.h>
#include <sv/pubkey.h>
#include <sv/script/interpreter.h>
#include <sv/streams.h>

namespace Gigamonkey::Bitcoin {
    
    digest256 signature::original_hash(const document &doc, sighash::directive d) {
        if (!sighash::valid(d) || sighash::has_fork_id(d)) return {};
        
        bytes serialized = bytes(doc.Transaction);
        
        CDataStream stream{(const char*)(serialized.data()), 
            (const char*)(serialized.data() + serialized.size()), SER_NETWORK, PROTOCOL_VERSION};
        
        CTransaction ctx{deserialize, stream};
        
        ::uint256 tmp = SignatureHash(CScript(doc.Previous.Script.begin(), doc.Previous.Script.end()), 
            ctx, doc.InputIndex, SigHashType(d), Amount((int64)doc.Previous.Value), nullptr, false);
        
        digest<32> out;
        std::copy(tmp.begin(), tmp.end(), out.begin());
        
        return out;
    }
    
    digest256 signature::Amaury_hash(const document &doc, sighash::directive d) {
        if (!sighash::valid(d)) return {};
        
        bytes serialized = bytes(doc.Transaction);
        
        CDataStream stream{(const char*)(serialized.data()), 
            (const char*)(serialized.data() + serialized.size()), SER_NETWORK, PROTOCOL_VERSION};
        
        CTransaction ctx{deserialize, stream};
        
        ::uint256 tmp = SignatureHash(CScript(doc.Previous.Script.begin(), doc.Previous.Script.end()), 
            ctx, doc.InputIndex, SigHashType(d | sighash::fork_id), Amount((int64)doc.Previous.Value), nullptr, true);
        
        digest<32> out;
        std::copy(tmp.begin(), tmp.end(), out.begin());
        
        return out;
    }

}
