// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_ERROR
#define GIGAMONKEY_STRATUM_ERROR

#include <gigamonkey/types.hpp>
#include <data/net/JSON.hpp>

namespace Gigamonkey {
    using JSON = data::JSON;
}

namespace Gigamonkey::Stratum {
    
    // Stratum error codes (from btc pool)
    enum error_code : uint32 {
        REJECT_NO_REASON = 0,

        JOB_NOT_FOUND_OR_STALE = 21,
        DUPLICATE_SHARE = 22,
        LOW_DIFFICULTY = 23,
        UNAUTHORIZED = 24,
        NOT_SUBSCRIBED = 25,

        ILLEGAL_METHOD = 26,
        ILLEGAL_PARAMS = 27,
        IP_BANNED = 28,
        INVALID_USERNAME = 29,
        INTERNAL_ERROR = 30,
        TIME_TOO_OLD = 31,
        TIME_TOO_NEW = 32,
        ILLEGAL_VERMASK = 33,

        INVALID_SOLUTION = 34,
        WRONG_NONCE_PREFIX = 35,

        JOB_NOT_FOUND = 36,
        STALE_SHARE = 37,

        UNKNOWN = 2147483647 // bin(01111111 11111111 11111111 11111111)
    };
    
    std::string error_message_from_code (error_code);
    
    struct error {
        error_code Code;
        string Message;
        
        error () : Code {}, Message {} {}
        error (error_code e, string m) : Code {e}, Message {m} {}
        explicit error (error_code e) : Code {e}, Message {error_message_from_code (e)} {}
        explicit error (const JSON &);
        
        static bool valid (const JSON &j) {
            return j.is_array () && j.size () == 2 && j[0].is_number_unsigned () && j[1].is_string ();
        }
        
        explicit operator JSON () const {
            return {uint32 (Code), Message};
        }
    };
    
    std::ostream inline &operator << (std::ostream &o, const error &e) {
        return o << "Stratum error " << e.Code << ": " << e.Message;
    }
    
}

#endif 
