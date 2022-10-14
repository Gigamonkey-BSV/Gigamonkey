// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_MAPI_JSONENVELOPE
#define GIGAMONKEY_MAPI_JSONENVELOPE

#include <gigamonkey/secp256k1.hpp>
#include <data/encoding/base64.hpp>
#include <data/encoding/unicode.hpp>

// https://github.com/bitcoin-sv-specs/brfc-misc/tree/master/jsonenvelope

namespace Gigamonkey::BitcoinAssociation {
    template <typename X> using optional = std::optional<X>;
        
    struct json_envelope {
        enum payload_encoding {
            none, 
            UTF_8,
            base64
        };
        
        string Payload;
        payload_encoding Encoding;
        string Mimetype;
        
        optional<secp256k1::pubkey> PublicKey;
        optional<secp256k1::signature> Signature;
        
        bool valid() const;
        bool verify() const;
        
        // encode as base64, no signature.
        json_envelope(const bytes &Payload, const string &Mimetype);
        
        // encode as UTF_8, no signature.
        json_envelope(const string &Payload, const string &Mimetype);
        
        // encode as base64 with signature.
        json_envelope(const bytes &Payload, const string &Mimetype, secp256k1::secret &secret);
        
        // encode as UTF_8 with signature.
        json_envelope(const string &Payload, const string &Mimetype, secp256k1::secret &secret);
        
        json_envelope(const json &);
        operator json() const;
        
        static bool valid(const json&);
        static bool verify(const json&);
        
        json_envelope() : Payload{}, Encoding{none}, Mimetype{}, PublicKey{}, Signature{} {}
    };
    
    // A json_envelope that contains json data. 
    struct json_json_envelope : json_envelope {
        bool valid() const;
        
        json payload() const {
            return json::parse(json_envelope::Payload);
        }
        
        json_json_envelope(const json &payload): 
            json_envelope{payload.dump(), "application/json"} {};
        
        json_json_envelope(const json &payload, secp256k1::secret &secret): 
            json_envelope{payload.dump(), "application/json", secret} {}
        
        json_json_envelope(const json_envelope &j) : json_envelope{j} {}
    };
        
    bool inline json_envelope::valid() const {
        return Encoding != none && ((bool(Signature) && bool(PublicKey)) || (!bool(Signature) && !bool(PublicKey)));
    }
    
    bool inline json_envelope::valid(const json &j) {
        return json_envelope{j}.valid();
    }
    
    bool inline json_envelope::verify(const json &j) {
        return json_envelope{j}.verify();
    }
    
    inline json_envelope::json_envelope(const bytes &pl, const string &mime) : 
        Payload{encoding::base64::write(pl)}, Encoding{base64}, Mimetype{mime}, PublicKey{}, Signature{} {}
    
    inline json_envelope::json_envelope(const string &pl, const string &mime) :
        Payload{pl}, Encoding{UTF_8}, Mimetype{mime}, PublicKey{}, Signature{} {}
    
    inline json_envelope::json_envelope(const bytes &pl, const string &mime, secp256k1::secret &secret) :
        Payload{encoding::base64::write(pl)}, Encoding{base64}, Mimetype{mime}, 
        PublicKey{secret.to_public()}, Signature{secret.sign(Gigamonkey::SHA2_256(pl))} {}
    
    inline json_envelope::json_envelope(const string &pl, const string &mime, secp256k1::secret &secret) :
        Payload{pl}, Encoding{UTF_8}, Mimetype{mime}, PublicKey{secret.to_public()}, 
        Signature{secret.sign(Gigamonkey::SHA2_256(encoding::unicode::utf8_encode(pl)))} {}
}

#endif
