// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SIGNATURE
#define GIGAMONKEY_SIGNATURE

#include "secp256k1.hpp"
#include "sighash.hpp"

namespace Gigamonkey::Bitcoin {
    
    // a Bitcoin signature. It consists of an secp256k1::signature with a
    // sighash directive at the end. This is what goes in an input script. 
    struct signature : bytes {
        // aka 73
        constexpr static size_t MaxSize = secp256k1::signature::MaxSize + 1;
        
        static Bitcoin::sighash::directive directive(bytes_view x) {
            return x.size() > 0 ? x[x.size() - 1] : 0;
        }
        
        static bytes_view raw(bytes_view x) {
            return x.size() > 0 ? x.substr(0, x.size() - 1) : bytes_view{};
        }
        
        secp256k1::signature raw() const {
            return secp256k1::signature{raw(*this)};
        }
        
        secp256k1::point point() const {
            return secp256k1::point(raw());
        }
        
        Bitcoin::sighash::directive directive() const {
            return directive(*this);
        }
        
        signature() : bytes{} {}
        explicit signature(const bytes_view data) : bytes{data} {}
        
        signature(const secp256k1::point raw, sighash::directive d) : bytes(secp256k1::signature::serialized_size(raw) + 1) {
            bytes_writer w(bytes::begin(), bytes::end());
            w << raw << d;
        }
        
        signature(const secp256k1::signature raw, sighash::directive d) : bytes(raw.size() + 1) {
            bytes_writer w(bytes::begin(), bytes::end());
            w << raw << d;
        }
        
        static bool DER(bytes_view x) {
            return x.size() > 0 && secp256k1::signature::minimal(raw(x));
        } 
        
        static signature sign(const secp256k1::secret& s, sighash::directive d, const sighash::document&);
        
        static bool inline verify(const bytes_view sig, const bytes_view pub, const sighash::document& doc) {
            return secp256k1::pubkey::verify(pub, hash(doc, directive(sig)), raw(sig));
        }
        
        // the hash that gets signed. 
        static digest256 hash(const sighash::document &doc, sighash::directive d);
        
    };
    
    signature inline signature::sign(const secp256k1::secret& s, sighash::directive d, const sighash::document& doc) {
        return signature{s.sign(hash(doc, d)), d};
    }
    
    std::ostream inline &operator<<(std::ostream& o, const signature& x) {
        return o << "signature{" << data::encoding::hex::write(bytes_view(x)) << "}";
    }
    
}

#endif
