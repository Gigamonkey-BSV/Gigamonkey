// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/remote.hpp>

namespace Gigamonkey::Stratum {
    
    awaitable<void> remote_receive_handler::operator () (const JSON &next) {
        if (notification::valid (next)) {
            receive_notification (notification {next});
            co_return;
        }
        
        if (response::valid (next)) {
            method m;
            response r {next};
            {
                auto x = Request.find (r.id ());
                if (x == Request.end ()) throw exception {"response with unknown message id returned"};
                m = x->second;
                Request.erase (x);
            }
            
            receive_response (m, r);
            co_return;
        }
        
        if (Stratum::request::valid (next)) {
            co_await receive_request (Stratum::request {next});
            co_return;
        }
        
        throw exception {} << "invalid Stratum message received: " << next.dump ();
    }
    
    awaitable<request_id> remote_receive_handler::send_request (method m, parameters p) {
        message_id id (Requests);
        co_await Send->send (Stratum::request {id, m, p});
        Request[id] = m;
        co_return Requests++;
    }
    
}
