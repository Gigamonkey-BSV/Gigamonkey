// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_ELECTRUM_SV
#define GIGAMONKEY_SCHEMA_ELECTRUM_SV

#include <gigamonkey/schema/bip_39.hpp>
#include <data/encoding/unicode.hpp>

// electrum SV uses a different method of working with a seed phrase with the same interface as BIP_39
namespace Gigamonkey::HD::Electrum_SV {

    const cross<std::string> &english_words ();

    byte_array<64> read (const unicode &words, const unicode &passphrase = {});
    unicode generate (entropy, BIP_39::language lang = BIP_39::language::english);
    bool valid (unicode words, BIP_39::language lang = BIP_39::language::english);

}

#endif

