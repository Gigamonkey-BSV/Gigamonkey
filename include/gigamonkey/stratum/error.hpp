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
    
    struct error;
    
    inline bool operator==(const error& a, const error& b);
    inline bool operator!=(const error& a, const error& b);
    
    void to_json(json& j, const error& p); 
    void from_json(const json& j, error& p); 
    
    std::ostream& operator<<(std::ostream&, const error&);
    
    struct error {
        error_code Code;
        string Message;
        bool Valid;
        
        error() : Code{none}, Message{}, Valid{false} {}
        error(error_code e, string m) : Code{e}, Message{m}, Valid{true} {}
        explicit error(error_code e) : Code{e}, Message{error_message_from_code(e)}, Valid{true} {}
    };
    
    inline bool operator==(const error& a, const error& b) {
        return a.Code == b.Code;
    }
    
    inline bool operator!=(const error& a, const error& b) {
        return a.Code != b.Code;
    }
    
    inline std::ostream& operator<<(std::ostream& o, const error& r) {
        json j;
        to_json(j, r);
        return o << j;
    }
    
}

#endif 
