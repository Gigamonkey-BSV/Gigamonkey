// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/server_session.hpp>

namespace Gigamonkey::Stratum {
    
    bool server_session::state::set_difficulty(const Stratum::difficulty& d) {
        if (!subscribed()) throw exception{"Cannot set difficulty before client is subscribed"};
        if (bool(MinimumDifficulty) && d < *MinimumDifficulty) return false;
        if (d == NextDifficulty) return false;
        NextDifficulty = d; 
        return true;
    }
    
    bool server_session::state::set_extranonce(const Stratum::extranonce &n) {
        if (!subscribed()) throw exception{"Cannot set extra nonce before client is subscribed"};
        if (NextExtranonce == n || (NextExtranonce == Stratum::extranonce{} && Extranonce == n)) return false;
        NextExtranonce = n;
        return true;
    }
    
    // return value is whether the version mask has changed. 
    bool server_session::state::set_version_mask(const extensions::version_mask &x) {
        auto current = version_mask();
        if (bool(current) && *current == x) return false;
        VersionRollingMaskParameters.set(x);
        return true;
    }
    
    void server_session::receive_response(method m, const Stratum::response &r) {
        if (m != client_get_version) 
            throw exception{} << "unknown response returned: " << method_to_string(m) << "; " << r.dump();
        
        if (!client::get_version_response::valid(r)) 
            throw exception{} << "invalid get_version response received: " << r;
        
        string client_version = client::get_version_response{r}.result();
        State.set_client_version(client_version);
        receive_get_version(client_version);
    }
    
    // authorize the client to the server. 
    // this is the original first method of the protocol. 
    mining::authorize_response server_session::authorize(const mining::authorize_request &r) {
        if (!r.valid()) return response{r.id(), nullptr, error{ILLEGAL_PARAMS}};
        
        if (State.authorized()) return response{r.id(), false, error{ILLEGAL_METHOD}};
        
        auto authorization = authorize(r.params());
        
        if (authorization) {
            State.set_name(r.params().Username);
            return mining::authorize_response{r.id(), true};
        }
        
        return mining::authorize_response{r.id(), *authorization};
    }
    /*
    // generate a configure response from a configure request message. 
    // this the optional first method of the protocol. 
    mining::configure_response server_session::configure(const mining::configure_request &r) {
        if (!State.extensions_supported()) return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
        
        if (!r.valid()) return response{r.id(), nullptr, error{ILLEGAL_PARAMS}};
        
        // minimum difficulty is allowed after the initial configure message. 
        auto params = r.params();
        if (State.configured() || !is_minimum_difficulty_only(params)) 
            return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
        
        auto config = State.configure(extensions::requests(params));
        if (config) return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
        return mining::configure_response{r.id(), mining::configure_response::parameters{*config}};
    }
    
    void server_session::receive_request(const Stratum::request &r) {
        std::unique_lock lock(Mutex);
        switch (r.method()) {
            case mining_submit: {
                response submit_response;
                
                if (!mining::submit_request::valid(r)) submit_response = response{r.id(), nullptr, error{ILLEGAL_PARAMS}};
                else if (!State.Options.CanSubmitWithoutAuthorization && !State.authorized())
                    submit_response = response{r.id(), nullptr, error{UNAUTHORIZED}};
                else if (!State.subscribed()) 
                    submit_response = response{r.id(), nullptr, error{NOT_SUBSCRIBED}};
                else {
                    auto submit_result = submit(mining::submit_request::params(r));
                    submit_response = (submit_result) ? 
                        mining::submit_response{r.id(), true} : 
                        mining::submit_response{r.id(), *submit_result};
                }
                
                return JSON_line_session::send(submit_response);
            }
            
            case mining_configure: 
                return JSON_line_session::send(configure(mining::configure_request{r}));
            
            case mining_authorize: 
                return JSON_line_session::send(authorize(mining::authorize_request{r}));
            
            case mining_subscribe: {
                if (!r.valid()) {
                    JSON_line_session::send(response{r.id(), nullptr, error{ILLEGAL_PARAMS}});
                    return;
                }
                
                if (State.subscribed()) {
                    JSON_line_session::send(response{r.id(), nullptr, error{ILLEGAL_METHOD}});
                }
                
                auto response = subscribe(mining::subscribe_request::params(r));
                
                State.Subscriptions = response.SubscribeParams.Subscriptions;
                JSON_line_session::send(mining::subscribe_response{r.id(), response.SubscribeParams});
                
                State.set_difficulty(response.InitialDifficulty);
                this->send_notification(mining_set_difficulty,
                    mining::set_difficulty::serialize(response.InitialDifficulty));
                
                State.notify(response.NotifyParams);
                this->send_notification(mining_notify, mining::notify::serialize(response.NotifyParams));
                
                return;
            };
            
            default : 
                JSON_line_session::send(response{r.id(), nullptr, error{ILLEGAL_METHOD}});
        }
    }
    
    // If this function has been called, then we already know that extensions are supported. 
    extensions::result server_session::state::configure_result(
        const string &extension, 
        const extensions::request &request) {
        
        switch (extensions::extension_from_string(extension)) {
            case extensions::version_rolling: {
                auto mask = Options.ExtensionsParameters->VersionRollingMask;
                if (!mask) return extensions::result{extensions::accepted{false}};
                
                VersionRollingMaskParameters.LocalMask = *mask;
                
                auto requested = extensions::configuration<extensions::version_rolling>::read(request);
                if (!requested) return extensions::result{extensions::accepted{"invalid version rolling request received"}};
                
                auto new_mask = VersionRollingMaskParameters.configure(*requested);
                if (!new_mask) return extensions::result{extensions::accepted{"cannot satisfy min bit requirement"}};
                return extensions::result{extensions::configured<extensions::version_rolling>{*new_mask}};
            } 
            
            case extensions::minimum_difficulty: {
                if (!Options.ExtensionsParameters->SupportExtensionMinimumDifficulty) 
                    return extensions::result{extensions::accepted{false}};
                
                auto requested = extensions::configuration<extensions::minimum_difficulty>::read(request);
                if (!requested) return extensions::result{extensions::accepted{"invalid minimum difficulty received"}};
                
                set_minimum_difficulty(requested->Value);
                return extensions::result{extensions::accepted{true}};
            }
            
            case extensions::subscribe_extranonce: 
                return extensions::result{extensions::accepted{
                    bool(Options.ExtensionsParameters->SupportExtensionSubscribeExtranonce)}};
            
            case extensions::info: 
                return extensions::result{extensions::accepted{
                    bool(Options.ExtensionsParameters->SupportExtensionInfo)}};
            
            default: return extensions::result{extensions::accepted{false}};
        }
    }
    
    optional<extensions::results> server_session::state::configure(const extensions::requests& p) {
        extensions::results results{};
        
        for (const data::entry<string, extensions::request> &x : p) 
            results = results.insert(x.Key, configure_result(x.Key, x.Value));
        
        Configured = true;
        
        return results;
    } 
    
    bool is_minimum_difficulty_only(const mining::configure_request::parameters &params) {
        return params.Supported.size() == 1 && params.Supported.first() == "minimum_difficulty";
    }
    
    void server_session::set_version_mask(const extensions::version_mask& p) {
        std::unique_lock lock(Mutex);
        if (!State.subscribed()) throw 0;
        auto new_mask = State.set_version_mask(p);
        if (!new_mask) throw std::logic_error{"new version mask fails to satisfy user's requirements"};
        this->send_notification(mining_set_version_mask, mining::set_version_mask::serialize(*new_mask));
    }
    
    void server_session::state::notify(const mining::notify::parameters& p) {
        if (p.Clean) Recent = set<byte_array<80>>{};
        Notifies.push(version_mask(), extranonce(), p);
        Extranonce = NextExtranonce;
        Difficulty = NextDifficulty;
    }
    
    server_session::state::found server_session::state::find(const share &x) const {
        bool stale = false;
        for (const auto &n : Notifies.Notifications) {
            if (n.Notification.JobID == x.JobID) {
                worker w = n.Mask ? 
                    worker(username(), n.ExtraNonce, *n.Mask) : 
                    worker(username(), n.ExtraNonce);
                return {proof{w, n.Notification, x}, stale};
            }
            
            if (n.Notification.Clean) stale = true;
        }
        
        return {};
    }
    
    // empty return value for an accepted share. 
    optional<error> server_session::submit(const share &x) {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        
        if (now - uint32(x.Share.Timestamp) > State.Options.MaxTimeDifferenceSeconds) return error{TIME_TOO_OLD};
        if (uint32(x.Share.Timestamp) - now > State.Options.MaxTimeDifferenceSeconds) return error{TIME_TOO_NEW};
        
        state::found f = State.find(x);
        if (!f.Found) return error{JOB_NOT_FOUND};
        if (f.Stale) return error{STALE_SHARE};
        
        byte_array<80> string = work::proof(f.Proof).string().write();
        
        if (State.Recent.contains(string)) return error{DUPLICATE_SHARE};
        State.Recent = State.Recent.insert(string);
        
        if (!f.Proof.valid(work::compact(work::difficulty(State.difficulty())))) return error{LOW_DIFFICULTY};
        if (f.Proof.valid()) solved(work::proof(f.Proof).Solution);
        
        return {};
    }*/
}
