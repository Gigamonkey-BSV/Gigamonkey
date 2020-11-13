// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/error.hpp>

namespace Gigamonkey::Stratum {
    
    std::string error_message_from_code(error_code) {
        return "";
    }
    
    void to_json(json& j, const error& p) {
        j = {};
        if (!data::valid(p)) return;
        if (p == error{none}) j = nullptr;
        else j = {uint32(p.Code), p.Message};
    }
    
    void from_json(const json& j, error& p) {
        p = {};
        if (j == nullptr) p = error{none};
        if (!j.is_array() || j.size() != 2 || !j[0].is_number_unsigned() || !j[1].is_string()) return;
        p = {static_cast<error_code>(uint32(j[0])), string(j[1])};
    }
}
