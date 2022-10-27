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
        
    struct JSON_envelope {
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
        JSON_envelope(const bytes &Payload, const string &Mimetype);
        
        // encode as UTF_8, no signature.
        JSON_envelope(const string &Payload, const string &Mimetype);
        
        // encode as base64 with signature.
        JSON_envelope(const bytes &Payload, const string &Mimetype, secp256k1::secret &secret);
        
        // encode as UTF_8 with signature.
        JSON_envelope(const string &Payload, const string &Mimetype, secp256k1::secret &secret);
        
        JSON_envelope(const JSON &);
        operator JSON() const;
        
        static bool valid(const JSON&);
        static bool verify(const JSON&);
        
        JSON_envelope() : Payload{}, Encoding{none}, Mimetype{}, PublicKey{}, Signature{} {}
    };
    
    // A JSON_envelope that contains JSON data. 
    struct JSON_JSON_envelope : JSON_envelope {
        bool valid() const;
        
        JSON payload() const {
            return JSON::parse(JSON_envelope::Payload);
        }
        
        JSON_JSON_envelope(const JSON &payload): 
            JSON_envelope{payload.dump(), "application/JSON"} {};
        
        JSON_JSON_envelope(const JSON &payload, secp256k1::secret &secret): 
            JSON_envelope{payload.dump(), "application/JSON", secret} {}
        
        JSON_JSON_envelope(const JSON_envelope &j) : JSON_envelope{j} {}
    };
        
    bool inline JSON_envelope::valid() const {
        return Encoding != none && ((bool(Signature) && bool(PublicKey)) || (!bool(Signature) && !bool(PublicKey)));
    }
    
    bool inline JSON_envelope::valid(const JSON &j) {
        return JSON_envelope{j}.valid();
    }
    
    bool inline JSON_envelope::verify(const JSON &j) {
        return JSON_envelope{j}.verify();
    }
    
    inline JSON_envelope::JSON_envelope(const bytes &pl, const string &mime) : 
        Payload{encoding::base64::write(pl)}, Encoding{base64}, Mimetype{mime}, PublicKey{}, Signature{} {}
    
    inline JSON_envelope::JSON_envelope(const string &pl, const string &mime) :
        Payload{pl}, Encoding{UTF_8}, Mimetype{mime}, PublicKey{}, Signature{} {}
    
    inline JSON_envelope::JSON_envelope(const bytes &pl, const string &mime, secp256k1::secret &secret) :
        Payload{encoding::base64::write(pl)}, Encoding{base64}, Mimetype{mime}, 
        PublicKey{secret.to_public()}, Signature{secret.sign(Gigamonkey::SHA2_256(pl))} {}
    
    inline JSON_envelope::JSON_envelope(const string &pl, const string &mime, secp256k1::secret &secret) :
        Payload{pl}, Encoding{UTF_8}, Mimetype{mime}, PublicKey{secret.to_public()}, 
        Signature{secret.sign(Gigamonkey::SHA2_256(encoding::unicode::utf8_encode(pl)))} {}
}

#endif
