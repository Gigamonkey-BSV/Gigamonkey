// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/ecies/bitcore.hpp>

namespace Gigamonkey::ECIES::bitcore {
    
    bytes encrypt(const bytes message, const secp256k1::pubkey& to) {
        throw method::unimplemented{"bitcore::encrypt"};
    }
        
    bytes decrypt(const bytes message, const secp256k1::secret& to) {
        throw method::unimplemented{"bitcore::decrypt"};
    }
    
}

