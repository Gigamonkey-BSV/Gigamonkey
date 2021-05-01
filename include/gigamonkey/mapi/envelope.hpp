// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MAPI_JSONENVELOPE
#define GIGAMONKEY_MAPI_JSONENVELOPE

#include <gigamonkey/wif.hpp>

namespace Gigamonkey {
    struct JSONEnvelope {
        enum payload_encoding {
            none, 
            UTF_8,
            base64
        };
        
        string payload;
        secp256k1::signature signature;
        Bitcoin::pubkey publicKey;
        payload_encoding encoding;
        string mimetype;
        
        static bool verify(const string& payload, const secp256k1::signature& signature, const secp256k1::pubkey& publicKey, payload_encoding);
        
        bool valid() const {
            // TODO we skip checking signatures for now because we don't have a way of 
            // checking whether the provided key is the miner's id key. 
            return mimetype != "" && publicKey.valid();// && verify(payload, signature, publicKey, encoding);
        }
        
        JSONEnvelope() : payload{}, signature{}, publicKey{}, encoding{none}, mimetype{} {}
        
        JSONEnvelope(const string&);
        
        JSONEnvelope(const json& payload, Bitcoin::secret& secret);
        JSONEnvelope(const bytes& payload, Bitcoin::secret& secret);
        JSONEnvelope(const string& payload, const string& mimetype, Bitcoin::secret& secret);
    };
}

#endif
