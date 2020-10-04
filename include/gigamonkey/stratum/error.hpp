// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_ERROR
#define GIGAMONKEY_STRATUM_ERROR

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Stratum {
    
    // Stratum error codes (incomplete)
    enum error_code : uint32 {
        none
    };
    
    std::string error_message_from_code(error_code);
    
    struct error {
        error_code Code;
        string Message;
        
        error() : Code{}, Message{} {}
        error(error_code e, string m) : Code{e}, Message{m} {}
        explicit error(error_code e) : Code{e}, Message{error_message_from_code(e)} {}
        
        static bool valid(const json& j) {
            return j.is_array() && j.size() == 2 && j[0].is_number_unsigned() && j[1].is_string();
        }
        
        explicit operator json() const {
            return {uint32(Code), Message};
        }
    };
    
}

#endif 
