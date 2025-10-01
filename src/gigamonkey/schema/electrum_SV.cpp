
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/schema/electrum_sv.hpp>
#include <data/crypto/PKCS5_PBKDF2_HMAC.hpp>

// electrum SV uses a different method of working with a seed phrase with the same interface as BIP_39
namespace Gigamonkey::HD::Electrum_SV {

    // NOTE: this is not the same as electrum SV's corresponding function. It is hard to reproduce.
    UTF8 inline normalize_text (const UTF8 &x) {
        return UTF8 (x);
    }

    seed read (const UTF8 &words, const UTF8 &passphrase) {

        auto x = crypto::PKCS5_PBKDF2_HMAC<64, CryptoPP::SHA512>
            (normalize_text (words) + UTF8 {"electrum"} + normalize_text (passphrase), 2048);

        seed z;
        z.resize (64);
        std::copy (x.begin (), x.end (), z.begin ());
        return z;
    }

}

