// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_INSTRUCTION
#define GIGAMONKEY_SCRIPT_INSTRUCTION

#include <gigamonkey/script/config.hpp>
#include <gigamonkey/script/error.h>
//#include <sv/policy/policy.h>

#include <gigamonkey/hash.hpp>
#include <gigamonkey/numbers.hpp>

namespace Gigamonkey::Bitcoin { 

    bool inline is_push (op o) {
        return o <= OP_16 && o != OP_RESERVED;
    }
    
    bool inline is_push_data (op o) {
        return o <= OP_PUSHDATA4;
    }
    
    bool is_minimal_script (bytes_view);
    
    // ASM is a standard human format for Bitcoin scripts that is unique only if the script is minimally encoded. 
    string ASM (bytes_view);
    
    // a single step in a program. 
    struct instruction; 
    
    bool operator == (const instruction &, const instruction &);
    bool operator != (const instruction &, const instruction &);
    
    size_t serialized_size (const instruction &o);
    
    std::ostream &operator << (std::ostream &, const instruction &);

    writer &operator << (writer &w, const instruction &i);
    
    instruction push_data (int);
    instruction push_data (const Z &z);
    instruction push_data (bytes_view);
    
    template <bool is_signed, boost::endian::order o, std::size_t size>
    instruction push_data (const data::endian_integral<is_signed, o, size> &x);
    
    bool is_minimal_instruction (const instruction &);
    
    // Representation of a Bitcoin script instruction, which is either an op code
    // by itself or an op code for pushing data to the stack along with data. 
    struct instruction {
        op Op;
        integer Data;
        
        instruction ();
        instruction (op p);
        instruction (bytes_view d) : instruction {push (d)} {}
        
        integer push_data () const;
        
        ScriptError verify (flag flags) const;
        
        bool valid () const {
            return verify (genesis_profile ()) == SCRIPT_ERR_OK;
        };
        
        uint32 serialized_size () const;
        
        bool operator == (op o) const;
        bool operator != (op o) const;
        
        static instruction op_code (op o);
        static instruction read (bytes_view b);
        static instruction push (bytes_view d);
        
        static size_t min_push_size (bytes_view b) {
            auto x = b.size ();
            return x == 0 || (x == 1 && (b[0] == 0x81 || (b[0] >= 1 && b[0] <= 16))) ? 1 : 
                x < 75 ? x + 1 : x < 0xff ? x + 2 : x < 0xffff ? x + 3 : x + 5;
        }
        
        // use this if you want to make a non-minimal push. Otherwise use 
        // one of the other constructors. 
    private:
        instruction (op p, const integer &d);
    };

    using program = list<instruction>;

    bool is_push (program);

    // check flags that can be checked without running the program.
    ScriptError pre_verify (program, flag flags);

    // delete the script up to and including the last instance of OP_CODESEPARATOR.
    // if no OP_CODESEPARATOR is found, nothing is removed.
    // this function is needed for correctly checking and generating signatures.
    program remove_after_last_code_separator (bytes_view);

    // used in the original sighash algorithm to remove instances of the same
    // signature that might have been used previously in the script.
    program find_and_delete (program script_code, const instruction &sig);

    // make the full program from the two scripts.
    program full (const program unlock, const program lock, bool support_p2sh);

    // pay to script hash only applies to scripts that were created before genesis.
    bool is_P2SH (const program p);

    bool inline valid (program p) {
        return pre_verify (p, genesis_profile ()) == SCRIPT_ERR_OK;
    };

    bytes compile (program p);

    bytes compile (instruction i);

    program decompile (bytes_view);

    // thrown if you try to decompile an invalid program.
    struct invalid_program : exception {
        ScriptError Error;
        invalid_program (ScriptError err): Error {err} {
            *this << "program is invalid: " << err;
        }
    };

    size_t serialized_size (program p);

    bool inline is_P2SH (bytes_view script) {
        return script.size () == 23 && script[0] == OP_HASH160 &&
            script[1] == 0x14 && script[22] == OP_EQUAL;
    }

    bool inline is_P2SH (const program p) {
        return is_P2SH (compile (p));
    }

    size_t inline serialized_size (program p) {
        if (data::empty (p)) return 0;
        return serialized_size (p.first ()) + serialized_size (p.rest ());
    }

    bool inline is_push (program p) {
        if (data::empty (p)) return true;
        return is_push (p.first ().Op) && is_push (p.rest ());
    }
    
    size_t inline serialized_size (const instruction &o) {
        return o.serialized_size ();
    }

    bool inline provably_unspendable (bytes_view script, bool after_genesis) {
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
    
    instruction inline push_data (bytes_view b) {
        return instruction::push (b);
    }

    instruction inline push_data (const Z &z) {
        return push_data (integer {z});
    }
    
    template <bool is_signed, boost::endian::order o, std::size_t size>
    instruction inline push_data (const data::endian_integral<is_signed, o, size> &x) {
        return push_data (bytes_view (x));
    }

    bool inline is_minimal_script (bytes_view b) {
        for (const instruction &i : decompile (b)) if (!is_minimal_instruction (i)) return false;
        return true;
    }
}

#endif
