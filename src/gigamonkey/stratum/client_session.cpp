
#include <gigamonkey/stratum/client_session.hpp>

namespace Gigamonkey::Stratum {
    
    void client_session::handle_notification(const notification &n) {
        if (mining::notify::valid(n)) return notify(mining::notify{n}.params());
        if (mining::set_difficulty::valid(n)) return set_difficulty(mining::set_difficulty{n}.params());
        if (mining::set_extranonce::valid(n)) return set_extranonce(mining::set_extranonce{n}.params());
        if (mining::set_version_mask::valid(n)) return set_version_mask(mining::set_version_mask{n}.params());
        if (client::show_message::valid(n)) return show_message(client::show_message{n}.params());
        throw std::logic_error{string{"unknown notification received: "} + string(n)};
    }
    
    void client_session::handle_request(const Stratum::request &r) {
        if (client::get_version_request::valid(r)) 
            return networking::json_line_session::send(client::get_version_response{r.id(), version()});
        
        networking::json_line_session::send(response{r.id(), nullptr, error{ILLEGAL_METHOD}});
        
        throw std::logic_error{string{"unknown request received: "} + string(r)};
    }
    
    bool client_session::initialize(
        const std::optional<extensions::requests> c, 
        const mining::authorize_request::parameters& ap, 
        const mining::subscribe_request::parameters& sp) {
        
        if (c) this->configure(*c);
        
        if (!this->authorize(ap)) {
            std::cout << "failed to authorize" << std::endl;
            return false;
        }
        
        auto subs = subscribe(sp);
        Subscriptions = subs.Subscriptions;
        set_extranonce(subs.ExtraNonce);
        return true;
    }
    
    extensions::results client_session::configure(const extensions::requests &q) {
        auto serialized = mining::configure_request::serialize(mining::configure_request::parameters{q});
        
        std::cout << "sending configure request " << serialized << std::endl;
        
        response s = request(mining_configure, serialized);
        
        if (!mining::configure_response::valid(s)) 
            throw std::logic_error{string{"invalid configure response received: "} + string(s)};
        
        auto r = extensions::results(mining::configure_response{s}.result());
        
        if (!mining::configure_response::valid_result(r, q))
            throw std::logic_error{string{"invalid response to "} + string(json{serialized}) + " received: " + string(s)};
        
        std::cout << "configure response received: " << r << std::endl;
        
        if (auto configuration = q.get<extensions::version_rolling>(); bool(configuration)) {
            std::cout << q["version-rolling"] << " requested; ";
            
            auto result = r.contains("version-rolling");
            
            if (result) std::cout << "no response received."; 
            else {
                std::cout << "response = " << *result << std::endl; 
                if (result->Accepted) {
                    auto x = extensions::configured<extensions::version_rolling>::read(*result->Parameters);
                    if (x) set_version_mask(x->Mask);
                    else std::cout << "invalid version-rolling response received: " << *result->Parameters << std::endl;
                }
            }
        }
        
        if (auto configuration = q.get<extensions::minimum_difficulty>(); bool(configuration)) {
            std::cout << q["minimum-difficulty"] << " requested; ";
            
            auto result = r.contains("minimum-difficulty");
            
            if (result) std::cout << "no response received."; 
            else {
                std::cout << "response = " << *result << std::endl; 
                if (result->Accepted) Minimum = configuration->Value;
            }
        }
        
        if (auto configuration = q.get<extensions::subscribe_extranonce>(); bool(configuration)) {
            std::cout << q["subscribe-extranonce"] << " requested; ";
            
            auto result = r.contains("subscribe-extranonce");
            
            if (result) std::cout << "no response received." ;
            else std::cout << "response = " << *result << std::endl; 
        }
        
        if (auto configuration = q.get<extensions::info>(); bool(configuration)) {
            std::cout << q["info"] << " requested; ";
            
            auto result = r.contains("info");
            
            if (result) std::cout << "no response received.";
            else std::cout << "response = " << *result << std::endl; 
        }
        
        return r;
    }
    
    bool client_session::authorize(const mining::authorize_request::parameters &x) {
        auto serialized = mining::authorize_request::serialize(x);
        
        std::cout << "sending authorize request " << serialized << std::endl;
        
        response r = request(mining_authorize, serialized);
        
        if (!mining::authorize_response::valid(r)) 
            throw std::logic_error{string{"invalid authorization response received: "} + string(r)};
        
        bool result = mining::authorize_response{r}.result();
        std::cout << (result ? "authorization successful!" : "authorization failed!") << std::endl;
        return result;
    }
    
    mining::subscribe_response::parameters client_session::subscribe(const mining::subscribe_request::parameters &x) {
        auto serialized = mining::subscribe_request::serialize(x);
        
        std::cout << "sending subscribe request " << serialized << std::endl;
        
        response r = request(mining_subscribe, serialized);
        
        if (!mining::subscribe_response::valid(r)) 
            throw std::logic_error{string{"invalid subscribe response received: "} + string(r)};
        
        std::cout << "subscribe response received " << r << std::endl;
        
        return mining::subscribe_response{r}.result();
    }
    
    bool client_session::set_minimum_difficulty(const extensions::configuration<extensions::minimum_difficulty> &m) {
        auto response = configure(extensions::requests{{}}.insert<extensions::minimum_difficulty>(m)).contains("minimum_difficulty");
        
        if (!response) return false;
        
        return response->Accepted;
    }
    
    bool client_session::submit(const share &x) {
        auto serialized = mining::submit_request::serialize(x);
        
        std::cout << "sending submit request " << serialized << std::endl;
        
        response r = request(mining_submit, serialized);
        
        SharesSubmitted++;
        
        if (!mining::submit_response::valid(r)) 
            throw std::logic_error{string{"invalid mining.submit response received: "} + string(r)};
        
        if (mining::submit_response{r}.result()) {
            SharesAccepted++;
            return true;
        }
        
        return false;
    }
    
}
