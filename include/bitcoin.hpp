// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_BITCOIN
#define BITCOIN_BITCOIN

#include <string>
#include <string_view>
#include <array>

namespace bitcoin {
    
    using byte = uint8_t;
    using index = uint32_t;
    using satoshi = uint64_t;
    
    using bytes = std::basic_string<byte>;
    using bytes_view = std::basic_string_view<byte>;
    
    using output = bytes_view;
    using input = bytes_view;
    using transaction = bytes_view;
    using signature = bytes;
    
    using secret = std::array<byte, 32>;
    
    // create a valid signature for a transaction. 
    signature sign(output, transaction, index, secret);
    
    // verify a script. 
    bool verify(transaction, index, satoshi, output, input);
    
    // verify a script ignoring signature checking. 
    bool verify(output, input);
    
}

#endif
