// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_TARGET
#define GIGAMONKEY_WORK_TARGET

#include <gigamonkey/hash.hpp>
#include <gigamonkey/timestamp.hpp>
#include <vector>

namespace Gigamonkey::work {
    
    struct difficulty;
    
    // proportional to inverse difficulty.
    struct compact : uint32_little {
        
        static compact encode (byte e, uint24_little v);
        
        compact ();
        compact (byte e, uint24_little v);
        explicit compact (uint32_little i);
        explicit compact (uint32 i);
        explicit compact (work::difficulty);
        explicit compact (const uint256 &);
        
        byte exponent () const;
        
        uint24_little digits () const;
        
        bool valid () const;
        
        uint256 expand () const;
        
        work::difficulty difficulty () const;
        
        explicit operator work::difficulty () const;
        
        explicit operator bytes_view () const;
        
        static compact min () {
            return compact {3, 0x0001};
        }
        
        static compact max () {
            return compact {33, 0xffff};
        }
    };
    
    uint256 expand (const compact&);
    
    const compact SuccessHalf {33, 0x8000};
    const compact SuccessQuarter {32, 0x400000};
    const compact SuccessEighth {32, 0x200000};
    const compact SuccessSixteenth {32, 0x100000};
    
    // units of difficulty per second. 
    struct hashpower {
        float64 Value;
        
        hashpower operator + (const hashpower &x) const;
        hashpower& operator += (const hashpower &x);
        hashpower operator - (const hashpower &x) const;
        hashpower& operator -= (const hashpower &x);
        
        hashpower operator * (float64 x) const;
        
        bool operator == (const hashpower &x) const;
        bool operator != (const hashpower &x) const;
        
        bool operator >= (const hashpower &x) const;
        bool operator <= (const hashpower &x) const;
        bool operator > (const hashpower &x) const;
        bool operator < (const hashpower &x) const;
        
        explicit operator float64 () const;
    };
    
    
    // proportional to hash operations per second. 
    struct difficulty {
        float64 Value;
        
        bool valid () const;
        
        operator float64 () const;
        
        difficulty ();
        explicit difficulty (float64 x);
        
        explicit operator uint256 () const;
        
        static difficulty minimum ();
        
        difficulty operator + (const difficulty &x) const;
        difficulty operator += (const difficulty &x);
        difficulty operator - (const difficulty &x) const;
        difficulty operator -= (const difficulty &x);
        
        difficulty operator * (float64 x) const;
        
        bool operator == (const difficulty &x) const;
        bool operator != (const difficulty &x) const;
        
        bool operator >= (const difficulty &x) const;
        bool operator <= (const difficulty &x) const;
        bool operator > (const difficulty &x) const;
        bool operator < (const difficulty &x) const;
        
        float64 operator / (const hashpower &x) const;
        float64 operator / (const difficulty &x) const;
        
        static uint256 &unit () {
            static uint256 Unit {"0x00000000FFFF0000000000000000000000000000000000000000000000000000"};
            return Unit;
        }
        
    };
    
    std::ostream inline &operator << (std::ostream &o, const Gigamonkey::work::difficulty &h) {
        return o << h.Value << " difficulty ";
    }

    std::ostream inline &operator << (std::ostream &o, const Gigamonkey::work::hashpower &h) {
        return o << "(" << h.Value << " difficulty / second)";
    }

}

namespace Gigamonkey::Bitcoin {
    using target = work::compact;
}

namespace Gigamonkey::work {
    
    inline hashpower hashpower::operator + (const hashpower &x) const {
        return hashpower{Value + x.Value};
    }
    
    inline hashpower& hashpower::operator += (const hashpower &x) {
        Value += x.Value;
        return *this;
    }
    
    inline hashpower hashpower::operator - (const hashpower &x) const {
        return hashpower {Value - x.Value};
    }
    
    inline hashpower& hashpower::operator -= (const hashpower &x) {
        Value -= x.Value;
        return *this;
    }
    
    inline hashpower hashpower::operator * (float64 x) const {
        return hashpower {Value * x};
    }
    
    inline bool hashpower::operator == (const hashpower &x) const {
        return Value == x.Value;
    }
    
    inline bool hashpower::operator != (const hashpower &x) const {
        return Value != x.Value;
    }
    
    inline bool hashpower::operator >= (const hashpower &x) const {
        return Value >= x.Value;
    }
    
    inline bool hashpower::operator <= (const hashpower &x) const {
        return Value <= x.Value;
    }
    
    inline bool hashpower::operator > (const hashpower &x) const {
        return Value > x.Value;
    }
    
    inline bool hashpower::operator < (const hashpower &x) const {
        return Value < x.Value;
    }
    
    inline hashpower::operator double () const {
        return Value;
    }
    
    inline bool difficulty::valid () const {
        return *this >= minimum ();
    }
    
    inline difficulty::operator double () const {
        return Value;
    }
    
    inline difficulty::difficulty () : Value {0} {}
    inline difficulty::difficulty (double x) : Value {x} {}
    
    inline difficulty difficulty::minimum () {
        return difficulty (0);
    }
    
    inline difficulty difficulty::operator + (const difficulty &x) const {
        return difficulty {Value + x.Value};
    }
    
    inline difficulty difficulty::operator += (const difficulty &x) {
        Value += x.Value;
        return *this;
    }
    
    inline difficulty difficulty::operator - (const difficulty &x) const {
        return difficulty {Value - x.Value};
    }
    
    inline difficulty difficulty::operator -= (const difficulty &x) {
        Value -= x.Value;
        return *this;
    }
    
    inline difficulty difficulty::operator * (double x) const {
        return difficulty (Value * x);
    }
    
    inline bool difficulty::operator == (const difficulty &x) const {
        return Value == x.Value;
    }
    
    inline bool difficulty::operator != (const difficulty &x) const {
        return Value != x.Value;
    }
    
    inline bool difficulty::operator >= (const difficulty &x) const {
        return Value >= x.Value;
    }
    
    inline bool difficulty::operator <= (const difficulty &x) const {
        return Value <= x.Value;
    }
    
    inline bool difficulty::operator > (const difficulty &x) const {
        return Value > x.Value;
    }
    
    inline bool difficulty::operator < (const difficulty &x) const {
        return Value < x.Value;
    }
    
    inline double difficulty::operator / (const hashpower &x) const {
        return Value / x.Value;
    }
    
    inline double difficulty::operator / (const difficulty &x) const {
        return Value / x.Value;
    }
    
    inline compact::compact () : uint32_little {0} {}
    inline compact::compact (byte e, uint24_little v) : compact {encode (e, v)} {}
    inline compact::compact (uint32_little i) : uint32_little {i} {}
    inline compact::compact (uint32 i) : uint32_little {i} {}
    
    inline byte compact::exponent () const {
        return static_cast<byte> (static_cast<uint32_little> (*this) >> 24);
    }
    
    inline uint24_little compact::digits () const {
        return uint24_little {static_cast<uint32_little> (*this) & 0x00FFFFFF};
    }
    
    inline bool compact::valid () const {
        uint32 compact = *this;
        return expand () != 0;
    }
    
    inline uint256 compact::expand () const {
        return work::expand (*this);
    }
    
    inline work::difficulty compact::difficulty () const {
        return work::difficulty {
            double (work::difficulty::unit ()) / 
            double (N (expand ()))};
    };
    
    inline compact::operator work::difficulty () const {
        return difficulty ();
    }
    
    inline compact::operator bytes_view () const {
        return bytes_view {uint32_little::data (), 4};
    }

    inline compact compact::encode (byte e, uint24_little v) {
        compact t;
        data::iterator_writer<compact::iterator, byte> w (t.begin (), t.end ());
        w << v << e;
        return t;
    }
}

#endif 
