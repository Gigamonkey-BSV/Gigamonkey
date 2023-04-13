// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_BIP_39
#define GIGAMONKEY_SCHEMA_BIP_39

#include <gigamonkey/schema/hd.hpp>

// HD is a format for infinite sequences of keys that 
// can be derived from a single master. This key format
// will be depricated but needs to be supported for 
// older wallets. 
namespace Gigamonkey::HD::BIP_39 {
    
    enum language {
        english,
        japanese,
        electrum_sv_english
    };
    
    seed read (std::string words, const string &passphrase = "", language lang = language::english);
    
    std::string generate (entropy, language lang = language::english);
    bool valid (std::string words, language lang = language::english);
    
    const cross<std::string> &english_words ();
    const cross<std::string> &japanese_words ();
}

#endif
