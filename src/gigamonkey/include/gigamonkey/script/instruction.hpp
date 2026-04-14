// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2026 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_INSTRUCTION
#define GIGAMONKEY_SCRIPT_INSTRUCTION

#include <gigamonkey/script/config.hpp>
#include <gigamonkey/script/error.h>

#include <gigamonkey/hash.hpp>
#include <gigamonkey/numbers.hpp>

namespace Gigamonkey::Bitcoin { 

    bool inline is_push (op o) {
        return o <= OP_16 && o != OP_RESERVED;
    }
    
    bool inline is_push_data (op o) {
        return o <= OP_PUSHDATA4;
    }
    
    bool is_minimal_script (slice<const byte>);
    
    // ASM is a standard human format for Bitcoin scripts that is unique only if the script is minimally encoded. 
    string ASM (slice<const byte>);
    
    // a single step in a program. 
    struct instruction; 
    
    bool operator == (const instruction &, const instruction &);
    bool operator != (const instruction &, const instruction &);
    
    size_t serialized_size (const instruction &o);
    
    std::ostream &operator << (std::ostream &, const instruction &);

    writer &operator << (writer &w, const instruction &i);
    
    instruction push_data (int);
    instruction push_data (const Z &z);
    instruction push_data (slice<const byte>);

    template <data::endian::order Order, class T, std::size_t n_bits, boost::endian::align Align>
    instruction push_data (const boost::endian::endian_arithmetic<Order, T, n_bits, Align> &x);
    
    bool is_minimal_instruction (const instruction &);
    
    // Representation of a Bitcoin script instruction, which is either an op code
    // by itself or an op code for pushing data to the stack along with data. 
    struct instruction {
        op Op;
        integer Data;
        
        instruction ();
        instruction (op p);
        instruction (slice<const byte> d) : instruction {push (d)} {}
        
        integer push_data () const;
        
        Error verify (const script_config &conf) const;
        
        bool valid () const {
            // TODO upgrade to chronicle
            return verify (genesis_profile ()) == Error::OK;
        };
        
        uint32 serialized_size () const;
        
        bool operator == (op o) const;
        bool operator != (op o) const;
        
        static instruction op_code (op o);
        static instruction read (slice<const byte> b);
        static instruction push (slice<const byte> d);
        
        static size_t min_push_size (slice<const byte> b) {
            auto x = b.size ();
            return x == 0 || (x == 1 && (b[0] == 0x81 || (b[0] >= 1 && b[0] <= 16))) ? 1 : 
                x < 75 ? x + 1 : x < 0xff ? x + 2 : x < 0xffff ? x + 3 : x + 5;
        }
        
        // use this if you want to make a non-minimal push. Otherwise use 
        // one of the other constructors. 
    private:
        instruction (op p, const integer &d);
    };
    
    size_t inline serialized_size (const instruction &o) {
        return o.serialized_size ();
    }

    bool inline provably_unspendable (slice<const byte> script, bool after_genesis) {
        if (after_genesis) return script.size () >= 2 && script[0] == OP_FALSE && script[1] == OP_RETURN;
        return script.size () >= 1 && script[0] == OP_RETURN;
    }
    
    bool inline operator == (const instruction &a, const instruction &b) {
        return a.Op == b.Op && static_cast<bytes> (a.Data) == static_cast<bytes> (b.Data);
    }
    
    bool inline operator != (const instruction &a, const instruction &b) {
        return !(a == b);
    }
    
    bool inline instruction::operator == (op o) const {
        return Op == o && Data.size () == 0;
    }
    
    bool inline instruction::operator != (op o) const {
        return !operator == (o);
    }
    
    inline instruction::instruction () : Op {OP_INVALIDOPCODE}, Data {} {}
    
    inline instruction::instruction (op p, const integer &d) : Op {p}, Data {d} {}
    
    inline instruction::instruction (op p) : Op {p}, Data {} {}
    
    instruction inline instruction::op_code (op o) {
        return instruction {o};
    }

    instruction inline push_data (int i) {
        return push_data (integer {i});
    }
    
    instruction inline push_data (slice<const byte> b) {
        return instruction::push (b);
    }

    instruction inline push_data (const Z &z) {
        return push_data (slice<const byte> (integer {z}));
    }

    template <data::endian::order Order, class T, std::size_t n_bits, boost::endian::align Align>
    instruction inline push_data (const boost::endian::endian_arithmetic<Order, T, n_bits, Align> &x) {
        return push_data (slice<const byte> (x));
    }
}

#endif
