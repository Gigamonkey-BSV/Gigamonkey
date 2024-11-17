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
    
    std::string extension_to_string (extension m);
    
    extension extension_from_string (std::string st);
    
    struct accepted : public std::variant<bool, string, std::monostate> {
        using std::variant<bool, string, std::monostate>::variant;
        
        accepted ();
        accepted (JSON j);
        
        bool valid () const;
        
        operator bool () const;
        operator JSON () const;
        
        bool has_error () const;
        string error () const;
    };
    
    // request for a single extension. 
    using request = data::map<string, JSON>;
    using result_params = data::map<string, JSON>;
    
    template <extension> struct configuration {
        operator request () const {
            return {};
        }
        
        static maybe<configuration> read (const request &p) {
            return {{}};
        }
    };
    
    template <extension> struct configured {
        operator result_params () const {
            return {};
        }
        
        static maybe<configured> read (const result_params &p) {
            return {{}};
        }
    };
    
    using version_mask = int32_little;
    
    encoding::hex::fixed<4> write_version_mask (const version_mask &x);
    maybe<version_mask> read_version_mask (const string &);
    
    template <> struct configuration<version_rolling> {
        version_mask Mask;
        byte MinBitCount;
        
        operator request () const;
        static maybe<configuration> read (const request &p);
    };
    
    template <> struct configured<version_rolling> {
        version_mask Mask;
        
        operator result_params () const;
        static maybe<configured> read (const result_params &p);
    };
    
    template <> struct configuration<minimum_difficulty> {
        difficulty Value;
        
        operator request () const;
        static maybe<configuration> read (const request &p);
    };
    
    template <> struct configuration<info> {
        string ConnectionURL;
        string HWVersion;
        string SWVersion;
        string HWID;
        
        operator request () const;
        static maybe<configuration> read (const request &p);
    };
    
    // requests for all extensions. 
    struct requests : public data::map<string, request> {
        using data::map<string, request>::map;
        requests (data::map<string, request> m) : data::map<string, request> {m} {}
        
        template <extension x>
        requests insert (const configuration<x> &n) const;
        
        template <extension x>
        maybe<configuration<x>> get () const;
    };
    
    struct result {
        accepted Accepted;
        result_params Parameters;
        
        result (const result_params &p);
        result ();
        result (accepted ac, const result_params &p = {});
        
        bool valid () const;
        
        bool operator == (const result &r) const;
        
    };
    
    using results = data::map<string, result>;
    
    struct options {
        // whether extension version_rolling is supported and 
        // parameter version mask. 
        optional<version_mask> VersionRollingMask {};
        
        bool SupportExtensionSubscribeExtranonce {false};
        bool SupportExtensionMinimumDifficulty {false};
        bool SupportExtensionInfo {false};
    };
    
    template <extension> struct parameters;
    
    template <> struct parameters<version_rolling> {
        version_mask LocalMask;
        configuration<version_rolling> RequestedMask;
        
        static optional<version_mask> make (version_mask local, const configuration<extensions::version_rolling> &r);
        
        parameters () : LocalMask {}, RequestedMask {} {}
        
        optional<version_mask> get () const;
        optional<version_mask> configure (const configuration<version_rolling> &requested);
        optional<version_mask> set (const version_mask &mask);
        
    };
    
    inline encoding::hex::fixed<4> write_version_mask (const version_mask &x) {
        return encoding::hex::write (x, hex_case::lower);
    }
    
    inline accepted::accepted () : std::variant<bool, string, std::monostate> {std::monostate {}} {}
        
    inline accepted::accepted (const JSON j) : accepted {} {
        if (j.is_boolean ()) *this = (bool) (j);
        else if (j.is_string ()) *this = (string) (j);
    }
        
    bool inline accepted::valid () const {
        return !std::holds_alternative<std::monostate> (*this);
    }
        
    inline accepted::operator bool () const {
        return std::holds_alternative<string> (*this) ? false : std::get<bool> (*this);
    }
        
    inline accepted::operator JSON () const {
        return std::holds_alternative<string> (*this) ? JSON (std::get<string> (*this)) : JSON (std::get<bool> (*this));
    }
        
    bool inline accepted::has_error () const {
        return std::holds_alternative<string> (*this);
    }
        
    string inline accepted::error () const {
        return has_error () ? std::get<string> (*this) : string {};
    }
    
    inline configuration<version_rolling>::operator request () const {
        return {{"mask", string (write_version_mask (Mask))}, {"min-bit-count", MinBitCount}};
    }
    
    inline configured<version_rolling>::operator result_params () const {
        return {{"mask", string (write_version_mask (Mask))}};
    }
    
    inline configuration<minimum_difficulty>::operator request () const {
        return {{"value", Value}};
    }
    
    inline configuration<info>::operator request () const {
        return {{"connection-url", ConnectionURL}, {"hw-version", HWVersion}, {"sw-version", SWVersion}, {"hw-id", HWID}};
    }
    
    template <extension x>
    requests inline requests::insert (const configuration<x> &n) const {
        return {data::map<string, request>::insert (extension_to_string (x), request (n))};
    }
    
    template <extension x>
    maybe<configuration<x>> requests::get () const {
        string ext = extension_to_string (x);
        auto z = this->contains (ext);
        if (z) return configuration<x>::read (*z);
        return {};
    }
    
    inline result::result (const result_params &p) : Accepted {true}, Parameters {} {}
    inline result::result () : Accepted {false}, Parameters {} {}
    inline result::result (accepted ac, const result_params &p): Accepted {ac}, Parameters {p} {}
    
    bool inline result::valid () const {
        return Accepted.valid () && (!bool (Accepted) || Parameters.size () == 0);
    }
    
    std::ostream inline &operator << (std::ostream &o, const accepted &a) {
        return bool (a) ? (o << "accepted") : a.has_error () ? (o << "rejected: " << a.error ()) : (o << "rejected");
    }
    
    std::ostream inline &operator << (std::ostream &o, const result &a) {
        o << "[" << a.Accepted;
        if (a.Parameters.size () > 0) return o << ", " << a.Parameters;
        return o << "]";
    }
        
    bool inline result::operator == (const result &r) const {
        return Accepted == r.Accepted && Parameters == r.Parameters;
    }
    
    optional<version_mask> inline parameters<version_rolling>::get () const {
        return make (LocalMask, RequestedMask);
    }
    
    optional<version_mask> inline parameters<version_rolling>::configure (const configuration<version_rolling> &requested) {
        RequestedMask = requested;
        return get ();
    }
    
    optional<version_mask> inline parameters<version_rolling>::set (const version_mask &mask) {
        LocalMask = mask;
        return get ();
    }
    
}

#endif
