// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/server_session.hpp>

namespace Gigamonkey::Stratum {
    string server_session::get_version() {
        response r = request(client_get_version, {});
        if (!client::get_version_response::valid(r)) 
            throw std::logic_error{string{"invalid get_version response received: "} + string(r)}; 
        return client::get_version_response{r}.result();
    }

    optional<extensions::version_mask> server_session::state::make_version_mask(
        extensions::version_mask x, 
        const extensions::configuration<extensions::version_rolling> &r) {
        extensions::version_mask new_mask = x & r.Mask;
        int bit_count = 0;
        for (int i = 0; i < 32; i++) if (((new_mask >> i) & 1) == 1) bit_count++;
        
        return bit_count < r.MinBitCount ? 
            optional<extensions::version_mask>{} : 
            optional<extensions::version_mask>{new_mask};
    }
    
    // Extension version_rolling allows clients to use ASICBoost. Server and client agree
    // on a mask that says what bits of the version field the client is allowed to alter. 
    extensions::version_mask server_session::state::version_mask() const {
        auto mask = ExtensionsParameters.get<extensions::version_rolling>();
        if (!mask) return 0;
        return mask->Mask;
    }
    
    optional<extensions::version_mask> server_session::state::set_version_mask(extensions::version_mask x) {
        if (!ExtensionsRequested) return {};
        auto mask = ExtensionsParameters.get<extensions::version_rolling>();
        if (!mask) return {};
        
        auto requested = ExtensionsRequested->get<extensions::version_rolling>();
        if (!requested) return {};
        
        auto new_mask = make_version_mask(x, *requested);
        if (new_mask) ExtensionsParameters = ExtensionsParameters.insert<extensions::version_rolling>(
            extensions::configured<extensions::version_rolling>{*new_mask});
        
        return new_mask;
    }
    
    extensions::result server_session::state::configure_result(
        const string &extension, 
        const extensions::request &request) {
        
        switch (extensions::extension_from_string(extension)) {
            case extensions::version_rolling: {
                auto mask = ExtensionsSupported.get<extensions::version_rolling>();
                if (!mask) return extensions::result{extensions::accepted{false}};
                
                auto requested = extensions::configuration<extensions::version_rolling>::read(request);
                if (!mask) return extensions::result{extensions::accepted{"invalid version rolling request received"}};
                
                auto new_mask = make_version_mask(mask->Mask, *requested);
                if (!new_mask) return extensions::result{extensions::accepted{"cannot satisfy min bit requirement"}};
                return extensions::result{extensions::configured<extensions::version_rolling>{*new_mask}};
            } 
            
            case extensions::minimum_difficulty: {
                auto min_diff = ExtensionsSupported.get<extensions::minimum_difficulty>();
                if (!min_diff) return extensions::result{extensions::accepted{false}};
                
                auto requested = extensions::configuration<extensions::minimum_difficulty>::read(request);
                if (!requested) return extensions::result{extensions::accepted{"invalid minimum difficulty received"}};
                
                set_minimum_difficulty(requested->Value);
                return extensions::result{extensions::accepted{true}};
            }
            
            case extensions::subscribe_extranonce: 
                return extensions::result{extensions::accepted{bool(ExtensionsSupported.get<extensions::subscribe_extranonce>())}};
            
            case extensions::info: 
                return extensions::result{extensions::accepted{bool(ExtensionsSupported.get<extensions::info>())}};
            
            default: return extensions::result{extensions::accepted{false}};
        }
    }
    
    // empty return value means extensions are not supported. 
    optional<extensions::results> server_session::state::configure(const extensions::requests& p) {
        if (!ExtensionsRequested) return {};
        
        ExtensionsRequested = p;
        
        for (const data::entry<string, extensions::request> &x : p) 
            ExtensionsParameters = extensions::results{
                static_cast<data::map<string, extensions::result>>(ExtensionsParameters).insert(x.Key, configure_result(x.Key, x.Value))};
        
        return ExtensionsParameters;
    } 
    
    // generate a configure response from a configure request message. 
    // this the optional first method of the protocol. 
    mining::configure_response server_session::configure(const mining::configure_request &r) {
        std::unique_lock lock(Mutex);
        if (!r.valid()) return response{r.id(), nullptr, error{ILLEGAL_PARAMS}};
        if (State.Phase != state::initial) return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
        auto config = State.configure(extensions::requests(r.params()));
        if (config) return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
        State.Phase = state::configured;
        return mining::configure_response{r.id(), mining::configure_response::parameters{*config}};
    }
    
    // authorize the client to the server. 
    // this is the original first method of the protocol. 
    mining::authorize_response server_session::authorize(const mining::authorize_request &r) {
        std::unique_lock lock(Mutex);
        if (!r.valid()) return response{r.id(), nullptr, error{ILLEGAL_PARAMS}};
        if (State.Phase > state::configured) return response{r.id(), false, error{ILLEGAL_METHOD}};
        State.Name = r.params().Username;
        auto authorization = authorize(r.params());
        
        if (authorization) {
            State.Phase = state::authorized;
            return mining::authorize_response{r.id(), true};
        }
        
        return mining::authorize_response{r.id(), *authorization};
    }
    
    // subscribe is the 3rd or 2nd method and it is when the client gets its
    // session id, which is also known as extra nonce 1. 
    mining::subscribe_response server_session::subscribe(const mining::subscribe_request &r) {
        std::unique_lock lock(Mutex);
        if (!r.valid()) return response{r.id(), nullptr, error{ILLEGAL_PARAMS}};
        if (State.Phase != state::authorized) {
            error_code e = State.Phase < state::authorized || State.Phase == state::configured ? UNAUTHORIZED : ILLEGAL_METHOD;
            return response{r.id(), nullptr, error{UNAUTHORIZED}};
        }
        State.Subscriptions = subscribe(mining::subscribe_request::params(r));
        return mining::subscribe_response{r.id(), *State.Subscriptions};
    }
    
    // empty return value for an accepted share. 
    optional<error> server_session::submit(const share &x) {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        
        if (now - uint32(x.Share.Timestamp) > min_time_difference) return error{TIME_TOO_OLD};
        if (uint32(x.Share.Timestamp) - now> min_time_difference) return error{TIME_TOO_NEW};
        
        state::found f = State.find(x);
        if (!f.Found) return error{JOB_NOT_FOUND};
        if (f.Stale) return error{STALE_SHARE};
        
        byte_array<80> string = work::proof(f.Proof).string().write();
        
        if (State.Recent.contains(string)) return error{DUPLICATE_SHARE};
        State.Recent = State.Recent.insert(string);
        
        if (!f.Proof.valid(work::compact(work::difficulty(State.difficulty())))) return error{LOW_DIFFICULTY};
        payment(State.username(), State.difficulty());
        if (f.Proof.valid()) solution(f.Proof);
        
        return {};
    }
    
    response server_session::respond(const Stratum::request &r) {
        switch (r.method()) {
            case mining_submit: {
                if (!mining::submit_request::valid(r)) return response{r.id(), nullptr, error{ILLEGAL_PARAMS}};
                
                if (State.Phase != state::working) {
                    error_code e = (State.Phase == state::initial || State.Phase == state::configured) ? 
                        UNAUTHORIZED : NOT_SUBSCRIBED;
                    return response{r.id(), nullptr, error{e}};
                }
                
                auto submit_result = submit(mining::submit_request::params(r));
                return (submit_result) ? 
                    mining::submit_response{r.id(), true} : 
                    mining::submit_response{r.id(), *submit_result};
            }
            case mining_configure: return configure(mining::configure_request{r});
            case mining_authorize: return authorize(mining::authorize_request{r});
            case mining_subscribe: return subscribe(mining::subscribe_request{r});
            default : return response{r.id(), nullptr, error{ILLEGAL_METHOD}};
        }
    }
    
    void server_session::set_version_mask(const extensions::version_mask& p) {
        std::unique_lock lock(Mutex);
        if (State.Phase != state::working) throw 0;
        auto new_mask = State.set_version_mask(p);
        if (!new_mask) return;
        this->send_notification(mining_set_version_mask, mining::set_version_mask::serialize(*new_mask));
    }
    
    server_session::state::found server_session::state::find(const share &x) const {
        bool stale = false;
        for (auto n = Notifies.Notifications.begin(); n != Notifies.Notifications.end(); n++) {
            if (n->Notification.JobID == x.JobID) 
                return {proof{worker(username(), n->ExtraNonce, n->Mask), n->Notification, x}, stale};
            if (n->Notification.Clean) stale = true;
        }
        
        return {};
    }
    
}
