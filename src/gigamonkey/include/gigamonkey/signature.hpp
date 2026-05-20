// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SIGNATURE
#define GIGAMONKEY_SIGNATURE

#include <gigamonkey/secp256k1.hpp>
#include <gigamonkey/sighash.hpp>
#include <gigamonkey/script/config.hpp>
#include <gigamonkey/script/error.h>

namespace Gigamonkey::Bitcoin {
    
    // a Bitcoin signature. It consists of an secp256k1::signature with a
    // sighash directive at the end. This is what goes in an input script. 
    struct signature : bytes {
        // aka 73
        constexpr static size_t MaxSize = secp256k1::signature::MaxSize + 1;
        
        static Bitcoin::sighash::directive directive (byte_slice x);
        static byte_slice raw (byte_slice x);
        
        secp256k1::signature raw () const;
        secp256k1::complex complex () const;
        Bitcoin::sighash::directive directive () const;
        
        signature ();
        explicit signature (const byte_slice data);
        signature (const secp256k1::complex raw, sighash::directive d);
        
        signature (const secp256k1::signature raw, sighash::directive d);
        
        static bool verify (const byte_slice sig, const byte_slice pub, const sighash::document &doc);
        static bool DER (byte_slice x);
        
        // the hash that gets signed. 
        static digest256 hash (const sighash::document &doc, sighash::directive d);
        
    };

    signature sign (const secp256k1::secret &s, sighash::directive d, const sighash::document &);

    // the signature verification algorithm used by the script interpreter.
    Error verify (
        byte_slice sig,
        byte_slice pub,
        const sighash::document &doc,
        // strict signatures are enabled by default because we don't have any other format implemented.
        flag flags = flag::VERIFY_STRICTENC | flag::VERIFY_DERSIG);

    std::ostream &operator << (std::ostream &o, const signature &x);
    
    signature inline sign (const secp256k1::secret &s, sighash::directive d, const sighash::document &doc) {
        return signature {s.sign (signature::hash (doc, d)), d};
    }

    Bitcoin::sighash::directive inline signature::directive (byte_slice x) {
        return x.size () > 0 ? x[x.size () - 1] : 0;
    }

    byte_slice inline signature::raw (byte_slice x) {
        return x.size () > 0 ? x.range (0, x.size () - 1) : byte_slice {};
    }

    secp256k1::signature inline signature::raw () const {
        return secp256k1::signature {raw (*this)};
    }

    secp256k1::complex inline signature::complex () const {
        return secp256k1::complex (raw ());
    }

    Bitcoin::sighash::directive inline signature::directive () const {
        return directive (*this);
    }

    inline signature::signature () : bytes {} {}
    inline signature::signature (byte_slice data) : bytes {data} {}

    inline signature::signature (const secp256k1::complex raw, sighash::directive d) {
        secp256k1::signature sig {raw};
        this->resize (sig.size () + 1);
        it_wtr w (bytes::begin (), bytes::end ());
        w << sig << d;
    }

    inline signature::signature (const secp256k1::signature raw, sighash::directive d) : bytes (raw.size () + 1) {
        it_wtr w (bytes::begin (), bytes::end ());
        w << raw << d;
    }

    bool inline signature::DER (byte_slice x) {
        return x.size () > 0 && secp256k1::signature::minimal (raw (x));
    }

    bool inline signature::verify (const byte_slice sig, const byte_slice pub, const sighash::document &doc) {
        return secp256k1::pubkey::verify (pub, hash (doc, directive (sig)), raw (sig));
    }

    std::ostream inline &operator << (std::ostream &o, const signature &x) {
        return o << "signature {" << encoding::hex::write (byte_slice (x)) << "}";
    }
    
}

#endif
