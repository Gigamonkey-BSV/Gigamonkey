// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/mapi/envelope.hpp>
#include <gigamonkey/address.hpp>

namespace Gigamonkey::BitcoinAssociation {
    
    bool json_envelope::verify() const {
        if (!valid()) return false;
        
        if (!bool(PublicKey)) return true;
        
        switch (Encoding) {
            default: return false;
            
            case base64 : {
                ptr<bytes> decoded = encoding::base64::read(Payload);
                if (decoded == nullptr) return false;
                return PublicKey->verify(Gigamonkey::SHA2_256(*decoded), *Signature);
            }
            
            case UTF_8 : 
                return PublicKey->verify(Gigamonkey::SHA2_256(encoding::unicode::utf8_encode(Payload)), *Signature);
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
                envelope.Signature = secp256k1::signature{*sig_hex};
                
                auto pk_hex = encoding::hex::read(string(j["publicKey"]));
                if (pk_hex == nullptr) return;
                envelope.PublicKey = secp256k1::pubkey{*pk_hex};
            }
        }
        
        string encoding = j["encoding"];
        if (encoding == "base64") envelope.Encoding = base64;
        else if (encoding == "UTF_8") envelope.Encoding = UTF_8;
        else return;
        
        envelope.Payload = j["payload"];
        envelope.Mimetype = j["mimetype"];
        
        *this = envelope;
        
    }
    
    json_envelope::operator json() const {
        if (!valid()) return nullptr;
        
        json j{{"payload", Payload}, {"mimetype", Mimetype}};
        j["encoding"] = Encoding == base64 ? "base64" : "UTF_8";
        
        if (bool(PublicKey)) {
            j["publicKey"] = encoding::hex::write(*PublicKey);
            j["signature"] = encoding::hex::write(*Signature);
        }
        
        return j;
    }
    
    bool json_json_envelope::valid() const {
        if (!json_envelope::valid()) return false;
        try {
            payload();
            return true;
        } catch (const json::exception &) {
            return false;
        }
    }
    
}
