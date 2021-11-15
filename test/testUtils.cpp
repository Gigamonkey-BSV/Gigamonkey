// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include "testUtils.h"

std::vector<unsigned char> strToTestVector(std::string input) {
    std::vector<unsigned char> ret;
    if (input.size() % 2 != 0) {
        return ret;
    }
    for (int i = 0; i < input.size(); i += 2) {
        ret.push_back(std::stoi(input.substr(i, 2), nullptr, 16));
    }
    return ret;
}

