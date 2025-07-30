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
        
        static Bitcoin::sighash::directive directive (slice<const byte> x);
        static slice<const byte> raw (slice<const byte> x);
        
        secp256k1::signature raw () const;
        secp256k1::point point () const;
        Bitcoin::sighash::directive directive () const;
        
        signature ();
        explicit signature (const slice<const byte> data);
        signature (const secp256k1::point raw, sighash::directive d);
        
        signature (const secp256k1::signature raw, sighash::directive d);
        
        static signature sign (const secp256k1::secret &s, sighash::directive d, const sighash::document &);
        
        static bool verify (const slice<const byte> sig, const slice<const byte> pub, const sighash::document &doc);
        static bool DER (slice<const byte> x);
        
        // the hash that gets signed. 
        static digest256 hash (const sighash::document &doc, sighash::directive d);
        
    };

    std::ostream &operator << (std::ostream &o, const signature &x);
    
    signature inline signature::sign (const secp256k1::secret &s, sighash::directive d, const sighash::document &doc) {
        return signature {s.sign (hash (doc, d)), d};
    }

    Bitcoin::sighash::directive inline signature::directive (slice<const byte> x) {
        return x.size () > 0 ? x[x.size () - 1] : 0;
    }

    slice<const byte> inline signature::raw (slice<const byte> x) {
        return x.size () > 0 ? x.range (0, x.size () - 1) : slice<const byte> {};
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
    inline signature::signature (slice<const byte> data) : bytes {data} {}

    inline signature::signature (const secp256k1::point raw, sighash::directive d) :
        bytes (secp256k1::signature::serialized_size (raw) + 1) {
        it_wtr w (bytes::begin (), bytes::end ());
        w << raw << d;
    }

    inline signature::signature (const secp256k1::signature raw, sighash::directive d) : bytes (raw.size () + 1) {
        it_wtr w (bytes::begin (), bytes::end ());
        w << raw << d;
    }

    bool inline signature::DER (slice<const byte> x) {
        return x.size () > 0 && secp256k1::signature::minimal (raw (x));
    }

    bool inline signature::verify (const slice<const byte> sig, const slice<const byte> pub, const sighash::document &doc) {
        return secp256k1::pubkey::verify (pub, hash (doc, directive (sig)), raw (sig));
    }

    std::ostream inline &operator << (std::ostream &o, const signature &x) {
        return o << "signature {" << encoding::hex::write (byte_slice (x)) << "}";
    }
    
}

#endif
