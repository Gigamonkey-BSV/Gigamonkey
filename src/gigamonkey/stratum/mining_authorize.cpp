// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/mining_authorize.hpp>

namespace Gigamonkey::Stratum::mining {
    Stratum::parameters authorize_request::serialize(const parameters& p) {
        if (p.Password) return {p.Username, *p.Password};
        return {p.Username};
    }
    
    authorize_request::parameters authorize_request::deserialize(const Stratum::parameters& p) {
        if (p.size() < 1 || p.size() > 2 || !p[0].is_string()) return parameters{};
        if (p.size() == 1) return parameters{string(p[0])};
        return parameters{string(p[0]), string(p[1])};
    }
    
    bool authorize_request::valid(const json& j) {
        auto p = request::params(j);
        if (p.size() < 1 || p.size() > 2 || !p[0].is_string()) return false;
        if (p.size() == 2 && !p[1].is_string()) return false;
        return true;
    }
    
    string username(const json& j) {
        auto p = request::params(j);
        if (p.size() == 0) return "";
        return string(p[1]);
    }
        
    std::optional<string> password(const json& j) {
        auto p = request::params(j);
        if (p.size() < 2) return {};
        return {string(p[1])};
    }
    
}
