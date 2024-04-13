// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_BIP_39
#define GIGAMONKEY_SCHEMA_BIP_39

#include <gigamonkey/schema/hd.hpp>
#include <gigamonkey/schema/bip_44.hpp>

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

namespace Gigamonkey::HD {

    BIP_44::master_secret inline simply_cash_wallet (const string &words, BIP_32::type net = BIP_32::main) {
        return BIP_44::root {BIP_32::secret::from_seed (BIP_39::read (words), net)}.master (BIP_44::simply_cash_coin_type, 0);
    }

    BIP_44::master_secret inline moneybutton_wallet (const string &words, BIP_32::type net = BIP_32::main) {
        return BIP_44::root {BIP_32::secret::from_seed (BIP_39::read (words), net)}.master (BIP_44::moneybutton_coin_type, 0);
    }

    BIP_44::master_secret inline relay_x_wallet (const string &words, BIP_32::type net = BIP_32::main) {
        return BIP_44::root {BIP_32::secret::from_seed (BIP_39::read (words), net)}.master (BIP_44::relay_x_coin_type, 0);
    }

    // Note: electrum sv has its own set of words. It is able to load wallets that were
    // made with the standard set of words, but we do not load electrum words here yet.
    BIP_44::master_secret electrum_sv_wallet (const string &words, const string &passphrase = ""); // TODO

    BIP_44::master_secret centbee_wallet (const string &words, uint32 pin); // TODO
}

#endif
