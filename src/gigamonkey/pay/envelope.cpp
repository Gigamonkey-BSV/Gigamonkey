// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/pay/envelope.hpp>
#include <gigamonkey/address.hpp>

namespace Gigamonkey {
    
    bool JSON_envelope::verify () const {
        if (!valid ()) return false;
        
        if (!bool (PublicKey)) return true;
        
        switch (Encoding) {
            default: return false;
            
            case base64 : {
                maybe<bytes> decoded = encoding::base64::read (Payload);
                if (!bool (decoded)) return false;
                return PublicKey->verify (Gigamonkey::SHA2_256 (*decoded), *Signature);
            }
            
            case UTF_8 : 
                return PublicKey->verify (Gigamonkey::SHA2_256 (Payload), *Signature);
        }
    }
    
    JSON_envelope::JSON_envelope (const JSON &j) : JSON_envelope {} {
        if (!j.is_object () || !j.contains ("payload") || !j.contains ("encoding") || !j.contains ("mimetype") ||
            !j["payload"].is_string () || !j["encoding"].is_string () || !j["mimetype"].is_string ())
            return;
        
        JSON_envelope envelope;
        
        if (j.contains ("publicKey") || j.contains ("signature")) {
            if (!j.contains ("publicKey") || !j.contains ("signature") ||
                !j["publicKey"].is_string () || !j["signature"].is_string ())
                return;
            else {
                auto sig_hex = encoding::hex::read (string (j["signature"]));
                if (!bool (sig_hex)) return;
                envelope.Signature = secp256k1::signature {*sig_hex};
                
                auto pk_hex = encoding::hex::read (string (j["publicKey"]));
                if (!bool (pk_hex)) return;
                envelope.PublicKey = secp256k1::pubkey {*pk_hex};
            }
        }
        
        string encoding = j["encoding"];
        if (encoding == "base64") envelope.Encoding = base64;
        else if (encoding == "UTF-8") envelope.Encoding = UTF_8;
        else return;
        
        envelope.Payload = j["payload"];
        envelope.Mimetype = j["mimetype"];
        
        *this = envelope;
        
    }
    
    JSON_envelope::operator JSON () const {
        if (!valid ()) return nullptr;
        
        JSON j{{"payload", Payload}, {"mimetype", Mimetype}};
        j["encoding"] = Encoding == base64 ? "base64" : "UTF_8";
        
        if (bool (PublicKey)) {
            j["publicKey"] = encoding::hex::write (*PublicKey);
            j["signature"] = encoding::hex::write (*Signature);
        }
        
        return j;
    }
    
    bool JSON_JSON_envelope::valid () const {
        if (!JSON_envelope::valid ()) return false;
        try {
            payload ();
            return true;
        } catch (const JSON::exception &) {
            return false;
        }
    }
    /*
    string JSON_JSON_envelope::de_escape(const string &x) {
        std::cout << "de escape string \"" << x << "\"" << std::endl;
        
        char *z = new char[x.size() + 1];
        char *i = z;
        
        for (const char &ch : x) {
            if (ch == '\\') i++;
            *i = ch;
            i++;
        }
        
        *i = '\0';
        
        string r{z};
        delete[] z;
        
        std::cout << "de escaped string \"" << r << "\"" << std::endl;
        
        return r;
    }*/
    
}
