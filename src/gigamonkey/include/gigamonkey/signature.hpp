// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SIGNATURE
#define GIGAMONKEY_SIGNATURE

#include <gigamonkey/secp256k1.hpp>
#include <gigamonkey/sighash.hpp>

namespace Gigamonkey::Bitcoin {
    
    // a Bitcoin signature. It consists of an secp256k1::signature with a
    // sighash directive at the end. This is what goes in an input script. 
    struct signature : bytes {
        // aka 73
        constexpr static size_t MaxSize = secp256k1::signature::MaxSize + 1;
        
        static Bitcoin::sighash::directive directive (bytes_view x);
        static bytes_view raw (bytes_view x);
        
        secp256k1::signature raw () const;
        secp256k1::point point () const;
        Bitcoin::sighash::directive directive () const;
        
        signature ();
        explicit signature (const bytes_view data);
        signature (const secp256k1::point raw, sighash::directive d);
        
        signature (const secp256k1::signature raw, sighash::directive d);
        
        static signature sign (const secp256k1::secret &s, sighash::directive d, const sighash::document &);
        
        static bool verify (const bytes_view sig, const bytes_view pub, const sighash::document &doc);
        static bool DER (bytes_view x);
        
        // the hash that gets signed. 
        static digest256 hash (const sighash::document &doc, sighash::directive d);
        
    };

    std::ostream &operator << (std::ostream &o, const signature &x);
    
    signature inline signature::sign (const secp256k1::secret &s, sighash::directive d, const sighash::document &doc) {
        return signature {s.sign (hash (doc, d)), d};
    }

    Bitcoin::sighash::directive inline signature::directive (bytes_view x) {
        return x.size () > 0 ? x[x.size () - 1] : 0;
    }

    bytes_view inline signature::raw (bytes_view x) {
        return x.size () > 0 ? x.substr (0, x.size () - 1) : bytes_view {};
    }

    secp256k1::signature inline signature::raw () const {
        return secp256k1::signature {raw (*this)};
    }

    secp256k1::point inline signature::point () const {
        return secp256k1::point (raw ());
    }

    Bitcoin::sighash::directive inline signature::directive () const {
        return directive (*this);
    }

    inline signature::signature () : bytes {} {}
    inline signature::signature (const bytes_view data) : bytes {data} {}

    inline signature::signature (const secp256k1::point raw, sighash::directive d) :
        bytes (secp256k1::signature::serialized_size (raw) + 1) {
        iterator_writer w (bytes::begin (), bytes::end ());
        w << raw << d;
    }

    inline signature::signature (const secp256k1::signature raw, sighash::directive d) : bytes (raw.size () + 1) {
        iterator_writer w (bytes::begin (), bytes::end ());
        w << raw << d;
    }

    bool inline signature::DER (bytes_view x) {
        return x.size () > 0 && secp256k1::signature::minimal (raw (x));
    }

    bool inline signature::verify (const bytes_view sig, const bytes_view pub, const sighash::document &doc) {
        return secp256k1::pubkey::verify (pub, hash (doc, directive (sig)), raw (sig));
    }

    std::ostream inline &operator << (std::ostream &o, const signature &x) {
        return o << "signature {" << data::encoding::hex::write (bytes_view (x)) << "}";
    }
    
}

#endif
