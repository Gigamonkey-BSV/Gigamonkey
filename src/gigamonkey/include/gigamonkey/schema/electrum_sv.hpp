// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_ELECTRUM_SV
#define GIGAMONKEY_SCHEMA_ELECTRUM_SV

#include <gigamonkey/schema/bip_39.hpp>
#include <data/encoding/unicode.hpp>
#include <data/io/unimplemented.hpp>

namespace Gigamonkey {
    using unicode = data::unicode;
    using UTF8 = data::UTF8;
}

// electrum SV uses a different method of working with a seed phrase with the same interface as BIP_39
namespace Gigamonkey::HD::Electrum_SV {

    const cross<UTF8> &english_words ();

    seed read (const UTF8 &words, const UTF8 &passphrase = {});
    UTF8 generate (entropy, BIP_39::language lang = BIP_39::language::english);
    bool valid (UTF8 words, BIP_39::language lang = BIP_39::language::english);

    UTF8 generate (entropy, BIP_39::language lang) {
        throw data::method::unimplemented {"Electrum_SV::generate"};
    }

    bool inline valid (UTF8 words, BIP_39::language lang) {
        throw data::method::unimplemented {"Electrum_SV::valid"};
    }

}

#endif

