// Copyright (c) 2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_SESSION
#define GIGAMONKEY_P2P_SESSION

#include <gigamonkey/p2p/p2p.hpp>

// types that are used for reading and writing serialized formats. 
namespace Gigamonkey::Bitcoin::p2p {
    
    struct reject {
        enum reason {
            none = 0x00, 
            malformed = 0x01,
            invalid = 0x10, 
            obsolete = 0x11, 
            duplicate = 0x12, 
            nonstandard = 0x40, 
            dust = 0x41, 
            insufficient_fee = 0x42, 
            checkpoint = 0x43
        }
        
        static to_string(reason);
        
        reject();
        reject(const message_type_string &, reason);
        reject(const message_type_string &, reason, bytes_view);
    };
}

#endif 
