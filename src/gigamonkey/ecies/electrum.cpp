// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/ecies/electrum.hpp>
#include "gigamonkey/schema/electrum.hpp"

namespace Gigamonkey::ECIES::electrum {
    
    bytes encrypt(const bytes message, const secp256k1::pubkey& to) {
        throw method::unimplemented{"electrum::encrypt"};
    }
        
    bytes decrypt(const bytes message, const secp256k1::secret& to) {
        throw method::unimplemented{"electrum::decrypt"};
    }
    
}




