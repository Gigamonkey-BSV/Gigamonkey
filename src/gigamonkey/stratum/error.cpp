// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/error.hpp>

namespace Gigamonkey::Stratum {
    
    std::string error_message_from_code(error_code x) {
        switch (x) {
            case REJECT_NO_REASON : return "rejected";

            case JOB_NOT_FOUND_OR_STALE : return "job not found or stale";
            case DUPLICATE_SHARE : return "duplicate share";
            case LOW_DIFFICULTY : return "low difficulty";
            case UNAUTHORIZED : return "unauthorized";
            case NOT_SUBSCRIBED : return "not subscribed";

            case ILLEGAL_METHOD : return "illegal method";
            case ILLEGAL_PARAMS : return "illegal params";
            case IP_BANNED : return "ip banned";
            case INVALID_USERNAME : return "invalid username";
            case INTERNAL_ERROR: return "internal error";
            case TIME_TOO_OLD : return "time too old" ;
            case TIME_TOO_NEW : return "time too new" ;
            case ILLEGAL_VERMASK : return "illegal version mask";

            case INVALID_SOLUTION : return "invalid solution";
            case WRONG_NONCE_PREFIX : return "wrong nonce prefix";

            case JOB_NOT_FOUND : return "job not found";
            case STALE_SHARE : return "stale share";

            case UNKNOWN : return "unknown";
            default: return "";
        }
    }
    
    error::error(const json &j) {
        if (!valid(j)) return;
        
        *this = error(j[0], j[1]);
    }
}
