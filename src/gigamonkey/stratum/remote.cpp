// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/remote.hpp>

namespace Gigamonkey::Stratum {

    void remote::shutdown() {
        guard lock(Mutex);
        for (const std::pair<Stratum::request, promise<response>*>& p : AwaitingResponse) delete p.second;
    }
    
    void remote::handle_response(const response &p) {
        guard lock(Mutex);
        
        // find the message that is beind responded to. 
        auto it = std::find_if(AwaitingResponse.begin(), AwaitingResponse.end(), 
            [&p](const std::pair<Stratum::request, promise<response>*> r) -> bool {
                return p.id() == r.first.id();
            });
        
        if (it == AwaitingResponse.end()) throw 0; // should not happen. 
        
        it->second->set_value(p);
        delete it->second;
        AwaitingResponse.erase(it); 
        
    }
    
    void remote::receive(const json &next) {
        if (notification::valid(next)) handle_notification(notification{next});
        if (response::valid(next)) handle_response(response{next});
        if (Stratum::request::valid(next)) handle_request(Stratum::request{next});
        throw std::logic_error{string{"invalid Stratum message received: "} + string(next)};
    }
    
    response remote::request(method m, parameters p) {
        guard lock(Mutex);
        AwaitingResponse.push_back(std::pair{Stratum::request{message_id(Requests), m, p}, new promise<response>()});
        this->send(AwaitingResponse.back().first);
        Requests++;
        return AwaitingResponse.back().second->get_future().get();
    }
    
}
