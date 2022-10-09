// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/mapi/envelope.hpp>
#include <gigamonkey/address.hpp>

namespace Gigamonkey::BitcoinAssociation {
    
    bool json_envelope::verify() const {
        if (!valid()) return false;
        
        if (!bool(publicKey)) return true;
        
        switch (encoding) {
            default: return false;
            
            case base64 : {
                ptr<bytes> decoded = encoding::base64::read(payload);
                if (decoded == nullptr) return false;
                return publicKey->verify(Gigamonkey::SHA2_256(*decoded), *signature);
            }
            
            case UTF_8 : 
                return publicKey->verify(Gigamonkey::SHA2_256(encoding::unicode::utf8_encode(payload)), *signature);
        }
    }
    
    json_envelope::json_envelope(const json &j) : json_envelope{} {
        if (!j.is_object() || !j.contains("payload") || !j.contains("encoding") || !j.contains("mimetype") || 
            !j["payload"].is_string() || !j["encoding"].is_string() || j["mimetype"].is_string())
            return;
        
        json_envelope envelope;
        
        if (j.contains("publicKey") || j.contains("signature")) {
            if (!j.contains("publicKey") || !j.contains("signature") || 
                !j["publicKey"].is_string() || !j["signature"].is_string())
                return;
            else {
                auto sig_hex = encoding::hex::read(string(j["signature"]));
                if (sig_hex == nullptr) return;
                envelope.signature = secp256k1::signature{*sig_hex};
                
                auto pk_hex = encoding::hex::read(string(j["publicKey"]));
                if (pk_hex == nullptr) return;
                envelope.publicKey = secp256k1::pubkey{*pk_hex};
            }
        }
        
        string encoding = j["encoding"];
        if (encoding == "base64") envelope.encoding = base64;
        else if (encoding == "UTF_8") envelope.encoding = UTF_8;
        else return;
        
        envelope.payload = j["payload"];
        envelope.mimetype = j["mimetype"];
        
        *this = envelope;
        
    }
    
    json_envelope::operator json() const {
        if (!valid()) return nullptr;
        
        json j{{"payload", payload}, {"mimetype", mimetype}};
        j["encoding"] = encoding == base64 ? "base64" : "UTF_8";
        
        if (bool(publicKey)) {
            j["publicKey"] = encoding::hex::write(*publicKey);
            j["signature"] = encoding::hex::write(*signature);
        }
        
        return j;
    }
    
}
