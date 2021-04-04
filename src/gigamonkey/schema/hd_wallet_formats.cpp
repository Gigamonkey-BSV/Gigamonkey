// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/schema/hd_wallet_formats.hpp>

namespace Gigamonkey::Bitcoin::hd::SimplyCash {


    SimplyCash::SimplyCash(std::string words) {
        Gigamonkey::Bitcoin::hd::seed seed=Gigamonkey::Bitcoin::hd::bip39::read(words);
        rootKey=bip32::secret::from_seed(seed, bip32::main);
    }

    bip32::secret SimplyCash::derive(int type, int index) {
        bip32::secret result=bip32::derive(rootKey,bip32::harden(44));
        result=bip32::derive(result,bip32::harden(145));
        result=bip32::derive(result,bip32::harden(0));
        result=bip32::derive(result,type);
        result=bip32::derive(result,index);
        return result;
    }
}