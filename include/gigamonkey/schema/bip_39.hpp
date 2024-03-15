// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_BIP_39
#define GIGAMONKEY_SCHEMA_BIP_39

#include <gigamonkey/schema/hd.hpp>

// BIP 39 defines a way of generating a BIP 32 master key from a seed phrase.
namespace Gigamonkey::HD::BIP_39 {
    
    enum language {
        english,
        japanese
    };
    
    seed read (std::string words, const string &passphrase = "", language lang = language::english);
    
    std::string generate (entropy, language lang = language::english);
    bool valid (std::string words, language lang = language::english);
    
    const cross<std::string> &english_words ();
    const cross<std::string> &japanese_words ();
}

// electrum SV uses a different method of working with a seed phrase with the same interface as BIP_39
namespace Gigamonkey::HD::Electrum_SV {

    seed read (std::string words, const string &passphrase = "", BIP_39::language lang = BIP_39::language::english);
    std::string generate (entropy, BIP_39::language lang = BIP_39::language::english);
    bool valid (std::string words, BIP_39::language lang = BIP_39::language::english);

    const cross<std::string> &english_words ();
}

#endif
