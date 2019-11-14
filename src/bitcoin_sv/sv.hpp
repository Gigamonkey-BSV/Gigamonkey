// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef SATOSHI_SV_SV
#define SATOSHI_SV_SV

#include <uint256.h>
#include <script/interpreter.h>

namespace bitcoin {
    
    using digest = ::uint256;
    
    CTransaction read_transaction(bytes_view);
    CScript read_script(bytes_view);
} 

#endif

