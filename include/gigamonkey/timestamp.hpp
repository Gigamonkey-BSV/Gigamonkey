// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TIMESTAMP
#define GIGAMONKEY_TIMESTAMP

#include <gigamonkey/types.hpp>

namespace Gigamonkey {
    
    struct timestamp : nonzero<uint32_little> {
        
        static timestamp read(string_view);
        
        timestamp() : nonzero<uint32_little>{} {}
        
        explicit timestamp(string_view s) : timestamp{read(s)} {}
        explicit timestamp(const uint32_little& t) : nonzero<uint32_little>{t} {}
        explicit timestamp(const nonzero<uint32_little>& n) : nonzero<uint32_little>{n} {}
        
        byte* data() {
            return nonzero<uint32_little>::Value.data();
        }
        
        const byte* data() const {
            return nonzero<uint32_little>::Value.data();
        }
        
        operator bytes_view() const {
            return bytes_view(data(), 4);
        }
        
        string_writer write(string_writer) const;
        string write() const;
        
        bytes_writer write(bytes_writer w) const {
            return w << nonzero<uint32_little>::Value;
        }
    };
}

inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::timestamp& s) {
    return o << s.write();
}

inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::timestamp& s) {
    return w << s.Value;
}

Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader w, Gigamonkey::timestamp& s);

#endif 
