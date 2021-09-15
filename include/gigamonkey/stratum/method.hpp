// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_METHOD
#define GIGAMONKEY_STRATUM_METHOD

#include <gigamonkey/stratum/error.hpp>

namespace Gigamonkey::Stratum {
    using request_id = uint64;
    
    // List of stratum methods (incomplete)
    enum method {
        unset,
        mining_authorize, 
        mining_configure, 
        mining_subscribe, 
        mining_notify, 
        mining_submit, 
        mining_set_difficulty, 
        mining_set_version_mask, 
        mining_set_extranonce, 
        mining_suggest_difficulty, 
        mining_suggest_target, 
        client_get_version,
        client_reconnect, 
        client_get_transactions, 
        client_show_message
    };
    
    std::string method_to_string(method m);
    
    method method_from_string(std::string st);

}

#endif
