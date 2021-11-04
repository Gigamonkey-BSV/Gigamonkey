// Copyright (c) 2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_SCRIPT_LIMITEDSTACK_H
#define BITCOIN_SCRIPT_LIMITEDSTACK_H

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <vector>
#include <gigamonkey/script/stack.hpp>

typedef Gigamonkey::Bitcoin::interpreter::element valtype;

typedef Gigamonkey::Bitcoin::interpreter::LimitedStack<valtype> LimitedStack;
typedef Gigamonkey::Bitcoin::interpreter::LimitedVector<valtype> LimitedVector;

#endif
