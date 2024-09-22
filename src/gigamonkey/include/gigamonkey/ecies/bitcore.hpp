// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_ECIES_BITCORE
#define GIGAMONKEY_ECIES_BITCORE

#include <gigamonkey/hash.hpp>
#include <gigamonkey/secp256k1.hpp>
#include <data/encoding/base58.hpp>

namespace Gigamonkey::ECIES::bitcore {
    
    bytes encrypt(const bytes message, const secp256k1::pubkey& to);
        
    bytes decrypt(const bytes message, const secp256k1::secret& to);
    
}

#endif

