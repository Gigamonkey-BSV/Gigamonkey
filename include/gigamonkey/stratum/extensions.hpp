// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_EXTENSIONS
#define GIGAMONKEY_STRATUM_EXTENSIONS

#include <gigamonkey/stratum/stratum.hpp>
#include <gigamonkey/stratum/difficulty.hpp>
#include <variant>
    
// https://github.com/slushpool/stratumprotocol/blob/master/stratum-extensions.mediawiki

namespace Gigamonkey::Stratum::extensions {
    
    // the four extensions we know about. 
    enum extension : uint32 {
        version_rolling, 
        minimum_difficulty, 
        subscribe_extranonce, 
        info
    };
    
    std::string extension_to_string(extension m);
    
    extension extension_from_string(std::string st);
    
    struct accepted : public std::variant<bool, string, std::monostate> {
        using std::variant<bool, string, std::monostate>::variant;
        
        accepted();
        accepted(json j);
        
        bool valid() const;
        
        operator bool() const;
        operator json() const;
        
        bool has_error() const;
        string error() const;
    };
    
    using request = data::map<string, json>;
    using result_params = data::map<string, json>;
    
    template <extension> struct configuration {
        operator request() const {
            return {};
        }
        
        static std::optional<configuration> read(const request &p) {
            return {{}};
        }
    };
    
    template <extension> struct configured {
        operator result_params() const {
            return {};
        }
        
        static std::optional<configured> read(const result_params &p) {
            return {{}};
        }
    };
    
    using version_mask = int32_little;
    
    encoding::hex::fixed<4> write_version_mask(const version_mask &x);
    std::optional<version_mask> read_version_mask(const string&);
    
    template <> struct configuration<version_rolling> {
        version_mask Mask;
        byte MinBitCount;
        
        operator request() const;
        static std::optional<configuration> read(const request &p);
    };
    
    template <> struct configured<version_rolling> {
        version_mask Mask;
        
        operator result_params() const;
        static std::optional<configured> read(const result_params &p);
    };
    
    template <> struct configuration<minimum_difficulty> {
        difficulty Value;
        
        operator request() const;
        static std::optional<configuration> read(const request &p);
    };
    
    template <> struct configuration<info> {
        string ConnectionURL;
        string HWVersion;
        string SWVersion;
        string HWID;
        
        operator request() const;
        static std::optional<configuration> read(const request &p);
    };
    
    struct requests : public data::map<string, request> {
        using data::map<string, request>::map;
        requests(data::map<string, request> m) : data::map<string, request>{m} {}
        
        template <extension x>
        requests insert(const configuration<x> &n) const;
        
        template <extension x>
        std::optional<configuration<x>> get() const;
    };
    
    struct result {
        accepted Accepted;
        std::optional<result_params> Parameters;
        
        result(const result_params &p);
        result();
        result(accepted ac, const result_params &p = {});
        
        bool valid() const;
        
        bool operator==(const result &r) const {
            return Accepted == r.Accepted && Parameters == r.Parameters;
        }
        
        bool operator!=(const result &r) const {
            return !operator==(r);
        }
        
    };
    
    struct results : public data::map<string, result> {
        using data::map<string, result>::map;
        results(data::map<string, result> m);
        
        template <extension x>
        results insert(const configured<x> &n) const;
        
        template <extension x>
        results insert() const;
        
        template <extension x>
        results insert(const string &err) const;
        
        template <extension x>
        std::optional<configured<x>> get() const;
    };
    
    inline encoding::hex::fixed<4> write_version_mask(const version_mask& x) {
        return encoding::hex::write(x, encoding::hex::lower);
    }
    
    inline accepted::accepted() : std::variant<bool, string, std::monostate>{std::monostate{}} {}
        
    inline accepted::accepted(const json j) : accepted{} {
        if (j.is_boolean()) *this = (bool)(j);
        else if (j.is_string()) *this = (string)(j);
    }
        
    bool inline accepted::valid() const {
        return !std::holds_alternative<std::monostate>(*this);
    }
        
    inline accepted::operator bool() const {
        return std::holds_alternative<string>(*this) ? false : std::get<bool>(*this);
    }
        
    inline accepted::operator json() const {
        return std::holds_alternative<string>(*this) ? json(std::get<string>(*this)) : json(std::get<bool>(*this));
    }
        
    bool inline accepted::has_error() const {
        return std::holds_alternative<string>(*this);
    }
        
    string inline accepted::error() const {
        return has_error() ? std::get<string>(*this) : string{};
    }
    
    inline configuration<version_rolling>::operator request() const {
        return {{"mask", string(write_version_mask(Mask))}, {"min-bit-count", MinBitCount}};
    }
    
    inline configured<version_rolling>::operator result_params() const {
        return {{"mask", string(write_version_mask(Mask))}};
    }
    
    inline configuration<minimum_difficulty>::operator request() const {
        return {{"value", Value}};
    }
    
    inline configuration<info>::operator request() const {
        return {{"connection-url", ConnectionURL}, {"hw-version", HWVersion}, {"sw-version", SWVersion}, {"hw-id", HWID}};
    }
    
    template <extension x>
    requests inline requests::insert(const configuration<x> &n) const {
        return {data::map<string, request>::insert(extension_to_string(x), request(n))};
    }
    
    template <extension x>
    std::optional<configuration<x>> requests::get() const {
        string ext = extension_to_string(x);
        auto z = this->contains(ext);
        if (z) return configuration<x>::read(*z);
        return {};
    }
    
    inline result::result(const result_params &p) : Accepted{true}, Parameters{} {}
    inline result::result() : Accepted{false}, Parameters{} {}
    inline result::result(accepted ac, const result_params &p): Accepted{ac}, Parameters{p} {}
    
    bool inline result::valid() const {
        return Accepted.valid() && (!bool(Accepted) || bool(Parameters));
    }
    
    inline results::results(data::map<string, result> m) : data::map<string, result>{m} {}
    
    template <extension x>
    results results::insert(const configured<x> &n) const {
        return results{data::map<string, result>::insert(extension_to_string(x), result{data::map<string, json>(n)})};
    }
    
    template <extension x>
    results results::insert() const {
        return {data::map<string, result>::insert(extension_to_string(x), result{})};
    }
    
    template <extension x>
    results results::insert(const string &err) const {
        return {data::map<string, result>::insert(extension_to_string(x), result{accepted{err}})};
    }
    
    template <extension x>
    std::optional<configured<x>> results::get() const {
        string ext = extension_to_string(x);
        auto r = this->contains(ext);
        if (r) return {};
        if (!bool(r->Accepted)) return {};
        return {configured<x>::read(*r->Parameters)};
    }
    
    std::ostream inline &operator<<(std::ostream &o, const accepted &a) {
        return bool(a) ? (o << "accepted") : a.has_error() ? (o << "rejected: " << a.error()) : (o << "rejected");
    }
    
    std::ostream inline &operator<<(std::ostream &o, const result &a) {
        o << "[" << a.Accepted;
        if (a.Parameters) return o << ", " << *a.Parameters;
        return o << "]";
    }
    
}

#endif
