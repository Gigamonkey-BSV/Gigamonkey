// Copyright (c) 2026 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PATTERN_MULTISIG
#define GIGAMONKEY_SCRIPT_PATTERN_MULTISIG

#include <gigamonkey/script/pattern.hpp>

namespace Gigamonkey {

    struct multisig {

        static bytes script (size_t min, const list<Bitcoin::pubkey> p) {
            using namespace Bitcoin;
            segment mp {};
            mp <<= push_data (min);
            for (const secp256k1::pubkey &pk : p) mp <<= push_data (pk);
            mp <<= push_data (p.size ());
            mp <<= OP_CHECKMULTISIG;
            return compile (mp);
        }

        // minimum number of signatures allowed.
        size_t Signatures;

        // all pubkeys
        list<Bitcoin::pubkey> Pubkeys;

        bool valid () const {
            return Pubkeys.valid () && Signatures <= Pubkeys.size () && Pubkeys.size () > 0;
        }

        bytes script () const {
            return script (Signatures, Pubkeys);
        }

        // size of s must be equal to Signatures.
        static bytes redeem (const list<Bitcoin::signature> s, const Bitcoin::instruction &null_push = Bitcoin::OP_0) {
            using namespace Bitcoin;
            segment ms;
            ms <<= null_push;
            for (const Bitcoin::signature &sk : s) ms <<= push_data (sk);
            return compile (ms);
        }

        constexpr static uint64 redeem_expected_size (size_t sigs) {
            return (1 + Bitcoin::signature::MaxSize) * sigs + 1;
        }
    };

}

#endif

