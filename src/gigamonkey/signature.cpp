// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/signature.hpp>

namespace Gigamonkey::Bitcoin {
    
    digest256 signature::hash (const sighash::document &doc, sighash::directive d) {
        //
        if (!doc.valid () || (sighash::base (d) == sighash::single && doc.InputIndex >= doc.Transaction.Outputs.size ()))
            return {};

        digest256 dig; {
            Hash256_writer w {dig};
            sighash::write (w, doc, d);
        } return dig;
    }

    Error verify (slice<const byte> sig, slice<const byte> pub, const sighash::document &doc, flag P) {

        if (verify_compressed_pubkey (P) && !secp256k1::pubkey::compressed (pub))
            return Error::NONCOMPRESSED_PUBKEY;

        if (verify_signature_strict (P) && !secp256k1::pubkey::valid (pub))
            return Error::PUBKEYTYPE;

        // if we pass an empty signature to the secp256k1 library, the program exits.
        if (sig.size () < 2)
            return Error::FAIL;

        auto d = signature::directive (sig);
        auto raw = signature::raw (sig);

        if (!sighash::valid (d))
            return Error::SIG_HASHTYPE;

        if (!fork_ID_enabled (P) && sighash::has_fork_id (d))
            return Error::ILLEGAL_FORKID;

        if (fork_ID_required (P) && !sighash::has_fork_id (d))
            return Error::MUST_USE_FORKID;

        if ((verify_signature_DER (P) ||
            verify_signature_low_S (P) ||
            verify_signature_strict (P)) && !signature::DER (sig))
            return Error::SIG_DER;

        if (verify_signature_low_S (P))
            if (!secp256k1::signature::normalized (raw))
                return Error::SIG_HIGH_S;

        if (signature::verify (sig, pub, doc))
            return Error::OK;

        if (verify_null_fail (P)) if (sig.size () != 0)
            return Error::SIG_NULLFAIL;

        return Error::FAIL;
    }

}
