// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/schema/hd.hpp>

namespace Gigamonkey::Bitcoin::hd::bip32 {
    
    secret derive(const secret&, uint32) {
        throw method::unimplemented{"bip32::derive secret"};
    }
    
    pubkey derive(const pubkey&, uint32) {
        throw method::unimplemented{"bip32::derive pubkey"};
    }
    
}

namespace Gigamonkey::Bitcoin::hd::bip39 {
    
    bip32::secret read(cross<std::string> words) {
        throw method::unimplemented{"bip39::read"};
    }
    
    cross<std::string> write(bip32::secret) {
        throw method::unimplemented{"bip39::write"};
    }
    
}


