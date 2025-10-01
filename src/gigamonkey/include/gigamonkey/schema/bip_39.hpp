// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_BIP_39
#define GIGAMONKEY_SCHEMA_BIP_39

#include <gigamonkey/schema/hd.hpp>
#include <gigamonkey/schema/bip_44.hpp>
#include <data/encoding/unicode.hpp>

namespace Gigamonkey {
    using UTF8 = data::UTF8;
}

// BIP 39 defines a way of generating a BIP 32 master key from a seed phrase.
namespace Gigamonkey::HD::BIP_39 {
    
    enum language {
        english,
        japanese
    };
    
    seed read (UTF8 words, const UTF8 &passphrase = "", language lang = language::english);
    
    data::UTF8 generate (entropy, language lang = language::english);
    bool valid (UTF8 words, language lang = language::english);
    
    const cross<UTF8> &english_words ();
    const cross<UTF8> &japanese_words ();
}

namespace Gigamonkey::HD {

    BIP_44::account_secret inline simply_cash_wallet (const string &words, uint32 account = 0, Bitcoin::net net = Bitcoin::net::Main) {
        return BIP_44::master {BIP_32::secret::from_seed (BIP_39::read (words), net)}.account (BIP_44::simply_cash_coin_type, account);
    }

    BIP_44::account_secret inline moneybutton_wallet (const string &words, uint32 account = 0, Bitcoin::net net = Bitcoin::net::Main) {
        return BIP_44::master {BIP_32::secret::from_seed (BIP_39::read (words), net)}.account (BIP_44::moneybutton_coin_type, account);
    }

    BIP_44::account_secret inline relay_x_wallet (const string &words, uint32 account = 0, Bitcoin::net net = Bitcoin::net::Main) {
        return BIP_44::master {BIP_32::secret::from_seed (BIP_39::read (words), net)}.account (BIP_44::relay_x_coin_type, account);
    }

    // Note: electrum sv has its own set of words.
    BIP_44::account_secret electrum_sv_wallet (const string &words, const string &passphrase = ""); // TODO

    // CentBee uses a non-standard derivation path.
    BIP_44::account_secret inline centbee_wallet (const string &words, uint32 pin, Bitcoin::net net = Bitcoin::net::Main) {
        return BIP_32::secret::from_seed
            (BIP_39::read (words, std::to_string (pin)), net).derive ({BIP_44::purpose, BIP_44::centbee_coin_type});
    }
}

#endif
