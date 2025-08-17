
#include <gigamonkey/stratum/client_session.hpp>

namespace Gigamonkey::Stratum {
    
    void client_session::receive_notification (const notification &n) {
        if (mining::notify::valid (n)) return receive_notify (mining::notify {n}.params ());
        if (mining::set_difficulty::valid (n)) return receive_set_difficulty (mining::set_difficulty {n}.params ());
        if (mining::set_extranonce::valid (n)) return receive_set_extranonce (mining::set_extranonce {n}.params ());
        if (mining::set_version_mask::valid (n)) return receive_set_version_mask (mining::set_version_mask {n}.params ());
        if (client::show_message::valid (n)) return receive_show_message (client::show_message {n}.params ());
        throw exception{} << "unknown notification received: " + n.dump ();
    }
    
    awaitable<void> client_session::receive_request (const Stratum::request &r) {
        if (client::get_version_request::valid (r))
            if (!co_await this->Send->send (client::get_version_response {r.id (), Options.Version}))
                throw exception {} << "failed to send message, channel closed";
        
        if (!co_await this->Send->send (response {r.id (), nullptr, error {ILLEGAL_METHOD}}))
            throw exception {} << "failed to send message, channel closed";
        
        throw exception {} << "unknown request received: " << r;
    }
    
    void client_session::receive_response (method m, const Stratum::response &r) {
        switch (m) {
            case mining_configure : {
                if (r.error ()) receive_configure_error (*r.error ());
                else receive_configure(extensions::results (mining::configure_response::result (r)));
            } break;
            case mining_authorize : {
                if (r.error ()) receive_authorize_error (*r.error ());
                else {
                    if (!mining::authorize_response::valid (r))
                        throw exception {} << "invalid authorization response received: " << r;
                    
                    receive_authorize (mining::authorize_response {r}.result ());
                }
            } break;
            case mining_subscribe : {
                if (r.error ()) receive_subscribe_error (*r.error ());
                else receive_subscribe (mining::subscribe_response::deserialize (r.result ()));
            } break;
            case mining_submit : {
                if (r.error ()) receive_submit (false);
                else receive_submit (r.result ());
            } break;
            default: throw exception {"Invalid method returned? Should not be possible."};
        }
    }
    
    void client_session::receive_configure (const extensions::results &r) {
        
        if (!Options.ConfigureRequest) throw exception {} << "configure response returned without knowing what was requested.";
        
        auto q = *Options.ConfigureRequest;
        
        if (!mining::configure_response::valid_result (r, q))
            throw exception {} << "invalid configure response received. ";
        
        if (auto configuration = q.get<extensions::version_rolling> (); bool (configuration)) {
            
            auto result = r.contains ("version-rolling");
            
            if (result) std::cout << "no response received."; 
            else {
                std::cout << "response = " << *result << std::endl; 
                if (result->Accepted) {
                    auto x = extensions::configured<extensions::version_rolling>::read (result->Parameters);
                    if (x) receive_set_version_mask (x->Mask);
                    else std::cout << "invalid version-rolling response received: " << result->Parameters << std::endl;
                }
            }
        }
        
        if (auto configuration = q.get<extensions::minimum_difficulty> (); bool (configuration)) {
            
            auto result = r.contains ("minimum-difficulty");
            
            if (result) std::cout << "no response received."; 
            else {
                if (result->Accepted) Minimum = configuration->Value;
            }
        }
        
        if (auto configuration = q.get<extensions::subscribe_extranonce> (); bool (configuration)) {
            std::cout << q["subscribe-extranonce"] << " requested; ";
            
            auto result = r.contains ("subscribe-extranonce");
            
            if (result) std::cout << "no response received." ;
            else std::cout << "response = " << *result << std::endl; 
        }
        
        if (auto configuration = q.get<extensions::info> (); bool (configuration)) {
            std::cout << q["info"] << " requested; ";
            
            auto result = r.contains("info");
            
            if (result) std::cout << "no response received.";
            else std::cout << "response = " << *result << std::endl; 
        }
        
        ExtensionResults = r;
    }
    
    void client_session::receive_authorize (bool r) {
        std::cout << (r ? "authorization successful!" : "authorization failed!") << std::endl;
        if (r) Authorized = true;
    }
    
    /*
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
    }*/
    
}
