// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_BIG_NUM
#define GIGAMONKEY_BIG_NUM

#include <script/script_num.h>
#include <gigamonkey/types.hpp>

namespace Gigamonkey::Bitcoin {
    using Z = CScriptNum;
    
    using N = data::math::number::N<Z>;
    
    // rationals
    using Q = math::number::fraction<Z, N>;
    
    // Gaussian numbers (complex rationals)
    using G = math::complex<Q>;
        
    // rational quaternions
    using H = math::quaternion<Q>;
        
    // rational octonions
    using O = math::octonion<Q>;
}

#endif
