// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMESTAMP
#define GIGAMONKEY_TIMESTAMP

#include <chrono>
#include <sstream>
#include <ctime>
#include <gigamonkey/types.hpp>

namespace Gigamonkey::Bitcoin {
    
    using duration = double;
    
    struct timestamp : nonzero<uint32_little> {
        
        static timestamp read (string_view);
        
        timestamp ();
        
        explicit timestamp (string_view s);
        explicit timestamp (uint32 t);
        explicit timestamp (uint32_little t);
        explicit timestamp (uint32_big x);
        explicit timestamp (int);
        explicit timestamp (time_t);
        explicit timestamp (nonzero<uint32_little> &&n);
        
        static timestamp now ();
        
        byte* data ();
        
        const byte* data () const;
        
        explicit operator bytes_view () const;
        explicit operator time_t () const;
        explicit operator uint32 () const;
        explicit operator string () const;
        
        bool operator == (const timestamp &d) const;

        std::strong_ordering operator <=> (const timestamp &d) const;
        
        duration operator - (const timestamp &t) const;

        explicit operator std::chrono::system_clock::time_point () const;

        explicit operator std::tm () const;

        uint16 year () const;
        byte month () const;
        byte day () const;
        byte weekday () const;
        byte hour () const;
        byte minute () const;
        byte second () const;
        
    };

    std::ostream &operator << (std::ostream &o, const timestamp &s);

    writer inline &operator << (writer &w, const timestamp &s) {
        return w << s.Value;
    }

    reader inline &operator >> (reader &r, timestamp &s) {
        return r >> s.Value;
    }

    inline timestamp::timestamp () : nonzero<uint32_little> {} {}
    
    inline timestamp::timestamp (string_view s) : timestamp {read (s)} {}
    inline timestamp::timestamp (uint32 t) : nonzero<uint32_little> {t} {}
    inline timestamp::timestamp (uint32_little t) : nonzero<uint32_little> {t} {}
    inline timestamp::timestamp (nonzero<uint32_little> &&n) : nonzero<uint32_little> {n} {}
    inline timestamp::timestamp (uint32_big x) : nonzero<uint32_little> {uint32_little {x}} {}
    inline timestamp::timestamp (time_t t) : timestamp (static_cast<uint32> (t)) {
        if (t < 0 || t > std::numeric_limits<uint32>::max ()) throw exception {} << "time_t out of range";
    }

    inline timestamp::timestamp (int t) : timestamp (static_cast<uint32> (t)) {
        if (t < 0 || t > std::numeric_limits<uint32>::max ()) throw exception {} << "int out of range";
    }

    inline timestamp::operator std::chrono::system_clock::time_point () const {
        return std::chrono::system_clock::from_time_t (static_cast<time_t> (uint32 (this->Value)));
    }
    
    timestamp inline timestamp::now () {
        return timestamp {uint32_little {static_cast<uint32> (duration_cast<std::chrono::seconds> (
            std::chrono::system_clock::now ().time_since_epoch ()).count ())}};
    };
    
    byte inline *timestamp::data () {
        return nonzero<uint32_little>::Value.data ();
    }
    
    const byte inline *timestamp::data () const {
        return nonzero<uint32_little>::Value.data ();
    }
    
    inline timestamp::operator uint32 () const {
        return nonzero<uint32_little>::Value.value ();
    }
    
    inline timestamp::operator time_t () const {
        time_t t = static_cast<time_t> (operator uint32 ());
        if (t < 0) throw ::std::logic_error {"unix epoch exceeded"};
        return t;
    }
    
    inline timestamp::operator string () const {
        std::stringstream s;
        s << *this;
        return s.str ();
    }
    
    inline timestamp::operator bytes_view () const {
        return bytes_view {data (), 4};
    }
        
    bool inline timestamp::operator == (const timestamp& d) const {
        return nonzero<uint32_little>::Value == d.Value;
    }
    
    std::strong_ordering inline timestamp::operator <=> (const timestamp& d) const {
        return uint32 (*this) <=> uint32 (d);
    }
    
    duration inline timestamp::operator - (const timestamp& t) const {
        return double (uint32 (nonzero<uint32_little>::Value)) - double (uint32 (t.Value));
    }

    uint16 inline timestamp::year () const {
        return static_cast<uint16> (1900 + std::tm (*this).tm_year);
    }

    byte inline timestamp::month () const {
        return static_cast<byte> (std::tm (*this).tm_mon);
    }

    byte inline timestamp::day () const {
        return static_cast<byte> (std::tm (*this).tm_mon);
    }

    byte inline timestamp::weekday () const {
        return static_cast<byte> (std::tm (*this).tm_wday);
    }

    byte inline timestamp::hour () const {
        return static_cast<byte> (std::tm (*this).tm_hour);
    }

    byte inline timestamp::minute () const {
        return static_cast<byte> (std::tm (*this).tm_min);
    }

    byte inline timestamp::second () const {
        return static_cast<byte> (std::tm (*this).tm_sec);
    }

}

#endif 
