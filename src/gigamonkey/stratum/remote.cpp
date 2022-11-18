// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/remote.hpp>

namespace Gigamonkey::Stratum {
    
    void remote::receive(const JSON &next) {
        if (notification::valid(next)) {
            receive_notification(notification{next});
            return;
        }
        
        if (response::valid(next)) {
            method m;
            response r{next};
            {
                guard lock(Mutex);
                auto x = Request.find(r.id());
                if (x == Request.end()) throw exception{"response with unknown message id returned"};
                m = x->second;
                Request.erase(x);
            }
            
            receive_response(m, r);
            return;
        }
        
        if (Stratum::request::valid(next)) {
            receive_request(Stratum::request{next});
            return;
        }
        
        throw exception{} << "invalid Stratum message received: " << next.dump();
    }
    
    request_id remote::send_request(method m, parameters p) {
        guard lock(Mutex);
        message_id id(Requests);
        JSON_line_session::send(Stratum::request{id, m, p});
        Request[id] = m;
        return Requests++;
    }
    
}
