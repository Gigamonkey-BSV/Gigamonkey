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
        
        string payload;
        payload_encoding encoding;
        string mimetype;
        
        optional<secp256k1::pubkey> publicKey;
        optional<secp256k1::signature> signature;
        
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
        
        json_envelope() : payload{}, encoding{none}, mimetype{}, publicKey{}, signature{} {}
    };
    
    // A json_envelope that contains json data. 
    struct json_json_envelope : json_envelope {
        bool valid() const;
        json payload() const;
        
        json_json_envelope(const json &payload);
        json_json_envelope(const json &payload, secp256k1::secret &secret);
        
        json_json_envelope(const json_envelope &j) : json_envelope{j} {}
    };
        
    bool inline json_envelope::valid() const {
        return encoding != none && ((bool(signature) && bool(publicKey)) || (!bool(signature) && !bool(publicKey)));
    }
    
    bool inline json_envelope::valid(const json &j) {
        return json_envelope{j}.valid();
    }
    
    bool inline json_envelope::verify(const json &j) {
        return json_envelope{j}.verify();
    }
    
    inline json_envelope::json_envelope(const bytes &pl, const string &mime) : 
        payload{encoding::base64::write(pl)}, encoding{base64}, mimetype{mime}, publicKey{}, signature{} {}
    
    inline json_envelope::json_envelope(const string &pl, const string &mime) :
        payload{pl}, encoding{UTF_8}, mimetype{mime}, publicKey{}, signature{} {}
    
    inline json_envelope::json_envelope(const bytes &pl, const string &mime, secp256k1::secret &secret) :
        payload{encoding::base64::write(pl)}, encoding{base64}, mimetype{mime}, 
        publicKey{secret.to_public()}, signature{secret.sign(Gigamonkey::SHA2_256(pl))} {}
    
    inline json_envelope::json_envelope(const string &pl, const string &mime, secp256k1::secret &secret) :
        payload{pl}, encoding{UTF_8}, mimetype{mime}, publicKey{secret.to_public()}, 
        signature{secret.sign(Gigamonkey::SHA2_256(encoding::unicode::utf8_encode(pl)))} {}
}

#endif
