// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_MESSAGE_ID
#define GIGAMONKEY_STRATUM_MESSAGE_ID

#include <gigamonkey/work/target.hpp>

namespace Gigamonkey::Stratum {
    
    struct request;
    struct response;
    
    // Message id is either an integer or string, must be a unique identifier. 
    struct message_id : JSON {
        
        message_id (const uint32 &d) : JSON (d) {}
        message_id (const string &x) : JSON (x) {}
        
        bool valid () const;
        
        static bool valid (const JSON &); 
        
    private:
        message_id () : JSON {} {}
        message_id (const JSON &j) : JSON (j) {}
        
        friend struct request;
        friend struct response;
    };
    
    bool inline message_id::valid (const JSON &j) {
        return j.is_number_unsigned () || j.is_string ();
    }
    
    bool inline message_id::valid () const {
        return valid (*this);
    }
    
}

#endif

