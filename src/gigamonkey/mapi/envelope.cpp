// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/mapi/envelope.hpp>
#include <data/encoding/base64.hpp>
#include <data/encoding/unicode.hpp>

namespace Gigamonkey {
        
    bool JSONEnvelope::verify(const string& payload, const secp256k1::signature& signature, const secp256k1::pubkey& publicKey, payload_encoding enc) {        
        switch (enc) {
            default: return false;
            case base64 : {
                ptr<bytes> decoded = data::encoding::base64::read(payload);
                if (decoded == nullptr) return false;
                return publicKey.verify(Gigamonkey::SHA2_256(*decoded), signature);
            }
            case UTF_8 : 
                return publicKey.verify(Gigamonkey::SHA2_256(data::encoding::unicode::utf8_encode(payload)), signature);
        }
    }
    
    JSONEnvelope::JSONEnvelope(const string& e) : JSONEnvelope{} {
        
        json j = json::parse(e);
        
        if (!(j.is_object() &&
            j.contains("payload") && j["payload"].is_string() &&
            j.contains("signature") && j["signature"].is_string() && 
            j.contains("publicKey") && j["publicKey"].is_string() && 
            j.contains("encoding") && j["encoding"].is_string() && 
            j.contains("mimetype") && j["mimetype"].is_string())) return;
        
        ptr<bytes> sig = encoding::hex::read(string(j["signature"]));
        
        if (sig == nullptr) return;
        
        string enc = j["encoding"];
        
        if (enc == "UTF-8") encoding = UTF_8;
        else if (enc == "base64") encoding = base64;
        else return;
        
        payload = j["payload"];
        signature = secp256k1::signature{*sig};
        publicKey = Bitcoin::pubkey{string(j["publicKey"])};
        mimetype = j["mimetype"];
        
    }
    
}
