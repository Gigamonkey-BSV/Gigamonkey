// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/method.hpp>

namespace Gigamonkey::Stratum {
    
    std::string method_to_string(method m) {
        switch (m) {
            case mining_notify :
                return "mining.notify";
            case mining_submit :
                return "mining.submit";
            case mining_configure : 
                return "mining.configure";
            case mining_authorize :
                return "mining.authorize";
            case mining_subscribe :
                return "mining.subscribe";
            case mining_set_difficulty :
                return "mining.set_difficulty";
            case mining_set_extranonce :
                return "mining.set_extranonce";
            case mining_set_version_mask :
                return "mining.set_version_mask";
            case client_get_version :
                return "client.get_version";
            case client_show_message :
                return "client.show_message";
            default: 
                return "";
        }
    }
    
    method method_from_string(std::string st) {
        if (st == "mining.notify") return mining_notify;
        if (st == "mining.submit") return mining_submit;
        if (st == "mining.authorize") return mining_authorize;
        if (st == "mining.configure") return mining_configure;
        if (st == "mining.subscribe") return mining_subscribe;
        if (st == "mining.set_difficulty") return mining_set_difficulty;
        if (st == "mining.set_extranonce") return mining_set_extranonce;
        if (st == "mining.set_version_mask") return mining_set_version_mask;
        if (st == "client.get_version") return client_get_version;
        if (st == "client.show_message") return client_show_message;
        return unset;
    }
}
