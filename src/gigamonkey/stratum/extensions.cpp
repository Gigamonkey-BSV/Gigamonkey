// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/stratum/extensions.hpp>
#include <gigamonkey/stratum/mining_configure.hpp>

namespace Gigamonkey::Stratum::extensions {

    optional<version_mask> read_version_mask(const string& str) {
        if (str.size() != 8) return {};
        ptr<bytes> b = encoding::hex::read(str);
        if (b != nullptr) return {};
        int32_big n;
        std::copy(b->begin(), b->end(), n.begin());
        return {int32_little(n)};
    }
    
    mining::configure_request::parameters add(mining::configure_request::parameters& p, const configuration_request<version_rolling>& r) {
        if (data::contains(p.Supported, "version_rolling")) return {};
        p.Supported = p.Supported << "version_rolling";
        p.Parameters["version-rolling.mask"] = write_version_mask(r.Mask);
        p.Parameters["version-rolling.min-bit-count"] = r.MinBitCount;
        return p;
    }
    
    mining::configure_request::parameters add(mining::configure_request::parameters& p, const configuration_request<minimum_difficulty>& r) {
        if (data::contains(p.Supported, "minimum_difficulty")) return {};
        p.Supported = p.Supported << "minimum_difficulty";
        p.Parameters["minimum_difficulty.value"] = r;
        return p;
    }
    
    mining::configure_request::parameters add(mining::configure_request::parameters& p, const configuration_request<subscribe_extranonce>& r) {
        if (data::contains(p.Supported, "subscribe_extranonce")) return {};
        p.Supported = p.Supported << "subscribe_extranonce";
        return p;
    }
    
    mining::configure_request::parameters add(mining::configure_request::parameters& p, const configuration_request<info>& r) {
        if (data::contains(p.Supported, "info")) return {};
        p.Supported = p.Supported << "info";
        if (r.ConnectionURL) p.Parameters["info.connection-url"] = *r.ConnectionURL;
        if (r.HWVersion) p.Parameters["info.hw-version"] = *r.HWVersion;
        if (r.SWVersion) p.Parameters["info.sw-version"] = *r.SWVersion;
        if (r.HWID) p.Parameters["info.hw-id"] = *r.HWID;
        return p;
    }
    
    mining::configure_response::parameters add(mining::configure_response::parameters& p, const configuration_result<version_rolling>& r) {
        p["version_rolling"] = bool(r);
        if (bool(r)) p["version_rolling.mask"] = write_version_mask(*r);
        return p;
    }
    
    mining::configure_response::parameters add(mining::configure_response::parameters& p, const configuration_result<minimum_difficulty>& r) {
        p["minimum_difficulty"] = r.Accepted;
        return p;
    }
    
    mining::configure_response::parameters add(mining::configure_response::parameters& p, const configuration_result<subscribe_extranonce>& r) {
        p["subscribe_extranonce"] = r.Accepted;
        return p;
    }
    
    mining::configure_response::parameters add(mining::configure_response::parameters& p, const configuration_result<info>& r) {
        p["info"] = r.Accepted;
        return p;
    }
    
    optional<configuration_request<version_rolling>> get<version_rolling>::request(const mining::configure_request::parameters& r) {
        if (!data::contains(r.Supported, "version_rolling")) return {};
        
        json j(r.Parameters);
        if (!(j.contains("version-rolling.mask") && j["version-rolling.mask"].is_string()) 
            || !(j.contains("version-rolling.min-bit-count") && j["version-rolling.min-bit-count"].is_number_unsigned())) return {};
        
        auto mask = read_version_mask(j["version-rolling.mask"]);
        if (!mask) return {};
        
        return configuration_request<version_rolling>{*mask, byte(j["version-rolling.min-bit-count"])};
        
    }
        
    optional<configuration_result<version_rolling>> get<version_rolling>::result(const mining::configure_response::parameters& r) {
        json j(r);
        
        if (!j.contains("version-rolling") || !j["version-rolling"].is_boolean()) return {};
        if (!bool(j["version_rolling"])) return configuration_result<version_rolling>{};
        if (!j.contains("version-rolling.mask")) return {};
        return configuration_result<version_rolling>{read_version_mask(j["version-rolling.mask"])};
        
    }
    
    optional<configuration_request<minimum_difficulty>> get<minimum_difficulty>::request(const mining::configure_request::parameters& r) {
        if (!data::contains(r.Supported, "minimum_difficulty")) return {};
        
        json j(r.Parameters);
        if (j.contains("minimum-difficulty.value")) return configuration_request<minimum_difficulty>{j["minimum-difficulty.value"]};
        
        return {};
    }
    
    optional<configuration_result<minimum_difficulty>> get<minimum_difficulty>::result(const mining::configure_response::parameters& r) {
        json j(r);
        if (j.contains("minimum-difficulty") && j["minimum-difficulty"].is_boolean()) 
            return configuration_result<minimum_difficulty>{bool(j["minimum-difficulty"])};
        return {};
    }
    
    optional<configuration_request<subscribe_extranonce>> get<subscribe_extranonce>::request(const mining::configure_request::parameters& r) {
        if (!data::contains(r.Supported, "subscribe_extranonce")) return {};
        
        json j(r.Parameters);
        return configuration_request<subscribe_extranonce>{};
    }
    
    optional<configuration_result<subscribe_extranonce>> get<subscribe_extranonce>::result(const mining::configure_response::parameters& r) {
        json j(r);
        if (j.contains("subscribe-extranonce") && j["subscribe-extranonce"].is_boolean()) 
            return configuration_result<subscribe_extranonce>{bool(j["subscribe-extranonce"])};
        return {};
    }
    
    optional<configuration_request<info>> get<info>::request(const mining::configure_request::parameters& r) {
        if (!data::contains(r.Supported, "info")) return {};
        
        json j(r.Parameters);
        configuration_request<info> i;
        if (j.contains("info.connection-url")) i.ConnectionURL = j["info.connection-url"];
        if (j.contains("info.hw-version")) i.HWVersion = j["info.hw-version"];
        if (j.contains("info.sw-version")) i.SWVersion = j["info.sw-version"];
        if (j.contains("info.hw-id")) i.HWID = j["info.hw-id"];
        return i;
    }
    
    optional<configuration_result<info>> get<info>::result(const mining::configure_response::parameters& r) {
        json j(r);
        if (j.contains("info") && j["info"].is_boolean()) return configuration_result<info>{bool(j["info"])};
        return {};
    }
    
}

namespace Gigamonkey::Stratum::mining {
        
    Stratum::parameters configure_request::serialize(const parameters& p) {
        Stratum::parameters z(2);
        z[1] = p.Parameters;
        z[0] = json::array_t(p.Supported.size());
        int i = 0;
        for (const string& x : p.Supported) {
            z[0][i] = x;
            i++;
        }
        return z;
    }
    
    configure_request::parameters configure_request::deserialize(const Stratum::parameters& p) {
        if (!parameters::valid(p)) return {};
        parameters x;
        x.Parameters = json::object_t(p[1]);
        for (const json& j : json::array_t(p[0])) {
            x.Supported = x.Supported << string(j);
        }
        return x;
    }
        
    bool valid(const Stratum::parameters& params) {
        if (params.size() != 2 || !params[0].is_array() || !params[1].is_object()) return false;
        for (const json& ex : params[0]) if (!ex.is_string()) return false;
        return true;
    }
        
    bool configure_request::valid(const json& j) {
        if (!request::valid(j)) return false; 
        Stratum::parameters params = j["params"];
        return parameters::valid(params);
    }
    
}
