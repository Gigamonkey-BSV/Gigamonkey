// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/extensions.hpp>
#include <gigamonkey/stratum/mining_configure.hpp>
#include <boost/algorithm/string.hpp>

namespace Gigamonkey::Stratum::mining {
        
    bool configure_request::parameters::valid (const Stratum::parameters &p) {
        if (p.size () != 2 || !p[0].is_array () || !p[1].is_object ()) return false;
        
        for (auto i = p[0].begin (); i != p[0].end(); i++) {
            if (!i->is_string ()) return false;
            for(auto j = p[0].begin (); j != i; j++) if (*j == *i) return false;
        }
        
        return true;
    }
        
    Stratum::parameters configure_request::serialize (const parameters &p) {
        Stratum::parameters z (2);
        z[1] = p.Parameters;
        z[0] = JSON::array_t (p.Supported.size ());
        int i = 0;
        for (const string &x : p.Supported) {
            z[0][i] = x;
            i++;
        }
        return z;
    }
    
    configure_request::parameters configure_request::deserialize (const Stratum::parameters &p) {
        if (!parameters::valid (p)) return {};
        parameters x;
        x.Parameters = JSON::object_t (p[1]);
        for (const JSON &j : JSON::array_t (p[0])) x.Supported = x.Supported << string (j);
        return x;
    }
        
    bool valid (const Stratum::parameters &params) {
        if (params.size () != 2 || !params[0].is_array () || !params[1].is_object ()) return false;
        for (const JSON &ex : params[0]) if (!ex.is_string ()) return false;
        return true;
    }
        
    bool configure_request::valid (const JSON &j) {
        if (!request::valid (j)) return false;
        Stratum::parameters params = j["params"];
        return parameters::valid (params);
    }
    
    configure_request::parameters::parameters (extensions::requests r) {
        for (const data::entry<string, extensions::request> &e : r) {
            Supported = Supported << e.Key;
            for (const data::entry<string, JSON> &j : e.Value) 
                Parameters[e.Key + string {"."} + j.Key] = j.Value;
        }
    }
    
    configure_request::parameters::operator extensions::requests () const {
        data::map<string, extensions::request> m;
        
        for (const string &supported : Supported) m = m.insert (supported, extensions::request{});
        
        for (const std::pair<string, JSON> &j : Parameters) {
            std::vector<std::string> z;
            boost::split(z, j.first, boost::is_any_of ("."));
            if (z.size() != 2) throw data::exception {"invalid format"};
            
            auto x = m.contains (z[0]);
            if (!x) throw data::exception {"invalid format"};
            *x = x->insert (z[1], j.second);
        }
        
        return {m};
    }
    
    configure_response::parameters::parameters(extensions::results r) {
        for (const data::entry<string, extensions::result> &e : r) {
            (*this)[e.Key] = JSON(e.Value.Accepted);
            if (!e.Value.Accepted) continue;
            for (const data::entry<string, JSON> &x : e.Value.Parameters) {
                (*this)[e.Key + string{"."} + x.Key] = x.Value;
            } 
        }
    }
    
    configure_response::parameters::operator extensions::results () const {
        std::map<string, extensions::accepted> accepted;
        std::map<string, extensions::result_params> params;
        
        for (const std::pair<string, JSON> &j : *this) {
            std::vector<std::string> z;
            boost::split (z, j.first, boost::is_any_of ("."));
            
            if (z.size () > 2 || z.size () == 0) throw data::exception {"invalid format"};
            
            if (z.size () == 1) {
                accepted[z[0]] = extensions::accepted {j.second};
                continue;
            }
            
            auto x = params.find (z[0]);
            if (x == params.end ()) params[z[0]] = extensions::result_params {{z[1], j.second}};
            else x->second = x->second.insert (z[1], j.second);
        } 
        
        for (const std::pair<string, extensions::result_params> &d : params) 
            if (accepted.find (d.first) == accepted.end ()) throw data::exception {"invalid format"};
        
        data::map<string, extensions::result> results;
        
        for (const std::pair<string, extensions::accepted> &d : accepted) {
            auto x = params.find (d.first);
            results = x != params.end () ? results.insert (d.first, extensions::result {d.second, x->second}) :
                results.insert (d.first, extensions::result {d.second});
        }
        
        return {results};
    }
    
}
