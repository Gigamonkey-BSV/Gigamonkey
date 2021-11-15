// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_VAR_STRING_HPP
#define GIGAMONKEY_VAR_STRING_HPP

#include <string>
#include "var_int.hpp"

namespace Gigamonkey::Bitcoin {

    template<typename reader>
    std::string read_var_string(reader &r) {
        auto msgLength = read_var_int(r);
        std::string msg;
        if(msgLength>0) {
            for (int i = 0; i < msgLength; i++) {
                unsigned char tmp;
                r >> tmp;
                msg += tmp;
            }
        }
        return msg;
    }
    template<typename writer>
    writer & write_var_string(writer &w,const std::string& str) {
        write_var_int(w,str.length());
        if(!str.empty()) {
            for (char tmp: str)
                w << tmp;
        }
        return w;
    }
}
#endif //GIGAMONKEY_VAR_STRING_HPP
