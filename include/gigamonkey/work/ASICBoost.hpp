// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_ASIC_BOOST
#define GIGAMONKEY_WORK_ASIC_BOOST

#include <data/encoding/halves.hpp>
#include <gigamonkey/types.hpp>

namespace Gigamonkey::work::ASICBoost {
    
    // This page implements general purpose nVersion bits, 
    // as described by https://en.bitcoin.it/wiki/BIP_0320. 
    
    const int32_little Mask{static_cast<int32>(0xe0001fff)};
    const int32_little Bits{static_cast<int32>(0x1fffe000)};
    
    inline int32_little version(int32_little version_field) {
        return Mask & version_field;
    }
    
    inline uint16_little bits(int32_little version_field) {
        return (Bits & version_field) >> 13;
    }
    
    inline uint16_little magic_number(int32_little version_field) {
        static const uint32_little MaskLeft{0xe0000000};
        static const uint32_little MaskRight{0x00001fff};
        return ((MaskLeft & version_field) >> 16) | (MaskRight & version_field);
    }
    
    inline int32_little category(uint16_little magic_number, uint16_little bits) {
        static const int32_little MaskLeft{0xe000};
        static const int32_little MaskRight{0x1fff};
        return int32_little{0} + (int32_little{bits} << 13) + (int32_little{magic_number & MaskRight}) + (int32_little{magic_number & MaskLeft} << 16);
    }
    
}

#endif

