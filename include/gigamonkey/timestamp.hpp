// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMESTAMP
#define GIGAMONKEY_TIMESTAMP

#include <sstream>
#include <gigamonkey/types.hpp>

namespace Gigamonkey::Bitcoin {
    
    using duration = double;
    
    struct timestamp : nonzero<uint32_little> {
        
        static timestamp read(string_view);
        
        timestamp();
        
        explicit timestamp(string_view s);
        explicit timestamp(const uint32 t);
        explicit timestamp(const uint32_little t);
        explicit timestamp(const nonzero<uint32_little> n);
        explicit timestamp(const uint32_big x);
        
        static timestamp convert(time_t);
        
        static timestamp now();
        
        byte* data();
        
        const byte* data() const;
        
        explicit operator bytes_view() const;
        explicit operator time_t() const;
        explicit operator uint32() const;
        explicit operator string() const;
        
        bytes_writer write(bytes_writer w) const;
        
        bool operator==(const timestamp& d) const;
        bool operator!=(const timestamp& d) const;
        
        bool operator>(const timestamp& t) const;
        bool operator<(const timestamp& t) const;
        bool operator>=(const timestamp& t) const;
        bool operator<=(const timestamp& t) const;
        
        duration operator-(const timestamp& t) const;
    };

    std::ostream& operator<<(std::ostream& o, const timestamp& s);

    inline bytes_writer operator<<(bytes_writer w, const timestamp& s) {
        return w << s.Value;
    }

    inline bytes_reader operator>>(bytes_reader r, timestamp& s) {
        return r >> s.Value;
    }

    inline timestamp::timestamp() : nonzero<uint32_little>{} {}
    
    inline timestamp::timestamp(string_view s) : timestamp{read(s)} {}
    inline timestamp::timestamp(const uint32 t) : nonzero<uint32_little>{t} {}
    inline timestamp::timestamp(const uint32_little t) : nonzero<uint32_little>{t} {}
    inline timestamp::timestamp(const nonzero<uint32_little> n) : nonzero<uint32_little>{n} {}
    inline timestamp::timestamp(const uint32_big x) : nonzero<uint32_little>{uint32_little{x}} {}
    
    inline timestamp timestamp::convert(const time_t t) {
        if (t < 0) throw std::invalid_argument{"negative time"};
        return timestamp{static_cast<uint32>(t)};
    }
    
    inline timestamp timestamp::now() {
        return timestamp{uint32_little{static_cast<uint32>(time(nullptr))}};
    };
    
    inline byte* timestamp::data() {
        return nonzero<uint32_little>::Value.data();
    }
    
    inline const byte* timestamp::data() const {
        return nonzero<uint32_little>::Value.data();
    }
    
    inline timestamp::operator uint32() const {
        return nonzero<uint32_little>::Value.value();
    }
    
    inline timestamp::operator time_t() const {
        time_t t = static_cast<time_t>(operator uint32());
        if (t < 0) throw ::std::logic_error{"unix epoch exceeded"};
        return t;
    }
    
    inline timestamp::operator string() const {
        std::stringstream s;
        s << *this;
        return s.str();
    }
    
    inline timestamp::operator bytes_view() const {
        return bytes_view{data(), 4};
    }
    
    inline bytes_writer timestamp::write(bytes_writer w) const {
        return w << nonzero<uint32_little>::Value;
    }
        
    inline bool timestamp::operator==(const timestamp& d) const {
        return nonzero<uint32_little>::Value == d.Value;
    }
    
    inline bool timestamp::operator!=(const timestamp& d) const {
        return nonzero<uint32_little>::Value != d.Value;
    }
    
    inline bool timestamp::operator>(const timestamp& t) const {
        return nonzero<uint32_little>::Value > t.Value;
    }
    
    inline bool timestamp::operator<(const timestamp& t) const {
        return nonzero<uint32_little>::Value < t.Value;
    }
    
    inline bool timestamp::operator>=(const timestamp& t) const {
        return nonzero<uint32_little>::Value >= t.Value;
    }
    
    inline bool timestamp::operator<=(const timestamp& t) const {
        return nonzero<uint32_little>::Value <= t.Value;
    }
    
    inline duration timestamp::operator-(const timestamp& t) const {
        return double(uint32(nonzero<uint32_little>::Value)) - double(uint32(t.Value));
    }
}

#endif 
