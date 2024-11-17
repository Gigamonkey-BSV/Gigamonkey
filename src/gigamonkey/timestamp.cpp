// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/timestamp.hpp>
#include <chrono>

namespace Gigamonkey::Bitcoin {

    timestamp::operator std::tm () const {
        time_t t = static_cast<time_t> (uint32 (*this));
        std::tm tm = *gmtime (&t);
        return tm;
    }

    const char * format = "%Y-%m-%d %H:%M:%S";
    
    std::ostream &operator << (std::ostream &o, const timestamp &s) {
        auto t = std::tm (s);
        char buff[20];
        std::strftime (buff, 20, format, &t);
        return o << buff;
    }

    tm parse_tm (const char* datetimeString, const char *format) {
        struct tm tmStruct;
        strptime (datetimeString, format, &tmStruct);
        return tmStruct;
    }

    time_t to_time_t (std::tm const &tm) {
        int y = tm.tm_year + 1900;
        unsigned m = tm.tm_mon + 1;
        unsigned d = tm.tm_mday;
        y -= m <= 2;
        const int era = (y >= 0 ? y : y-399) / 400;
        const unsigned yoe = static_cast<unsigned>(y - era * 400);      // [0, 399]
        const unsigned doy = (153*(m + (m > 2 ? -3 : 9)) + 2)/5 + d-1;  // [0, 365]
        const unsigned doe = yoe * 365 + yoe/4 - yoe/100 + doy;         // [0, 146096]
        return (era * 146097 + static_cast<int> (doe) - 719468) * 86400 +
            tm.tm_hour * 3600 + tm.tm_min * 60 + tm.tm_sec;
    }

    timestamp timestamp::read (string_view x) {
        return timestamp (to_time_t (parse_tm (x.data (), format)));
    }

    
}
