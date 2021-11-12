// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_INSTRUCTION
#define GIGAMONKEY_SCRIPT_INSTRUCTION

#include <gigamonkey/script/opcodes.h>
#include <gigamonkey/script/flags.h>
#include <gigamonkey/script/error.h>
#include <sv/policy/policy.h>

#include <gigamonkey/number.hpp>

namespace Gigamonkey::Bitcoin { 
    
    using op = opcodetype;
    
    // instructions which can appear in script programs but which 
    // do not have names in the original Satoshi client. 
    const op OP_PUSHSIZE1 = op(0x01);
    const op OP_PUSHSIZE2 = op(0x02);
    const op OP_PUSHSIZE3 = op(0x03);
    const op OP_PUSHSIZE4 = op(0x04);
    const op OP_PUSHSIZE5 = op(0x05);
    const op OP_PUSHSIZE6 = op(0x06);
    const op OP_PUSHSIZE7 = op(0x07);
    const op OP_PUSHSIZE8 = op(0x08);
    const op OP_PUSHSIZE9 = op(0x09);
    
    const op OP_PUSHSIZE10 = op(0x0a); 
    const op OP_PUSHSIZE11 = op(0x0b);
    const op OP_PUSHSIZE12 = op(0x0c);
    const op OP_PUSHSIZE13 = op(0x0d);
    const op OP_PUSHSIZE14 = op(0x0e);
    const op OP_PUSHSIZE15 = op(0x0f);
    const op OP_PUSHSIZE16 = op(0x10);
    const op OP_PUSHSIZE17 = op(0x11);
    const op OP_PUSHSIZE18 = op(0x12);
    const op OP_PUSHSIZE19 = op(0x13);
    
    const op OP_PUSHSIZE20 = op(0x14);
    const op OP_PUSHSIZE21 = op(0x15);
    const op OP_PUSHSIZE22 = op(0x16);
    const op OP_PUSHSIZE23 = op(0x17);
    const op OP_PUSHSIZE24 = op(0x18);
    const op OP_PUSHSIZE25 = op(0x19);
    const op OP_PUSHSIZE26 = op(0x1a);
    const op OP_PUSHSIZE27 = op(0x1b);
    const op OP_PUSHSIZE28 = op(0x1c);
    const op OP_PUSHSIZE29 = op(0x1d);

    const op OP_PUSHSIZE30 = op(0x1e);
    const op OP_PUSHSIZE31 = op(0x1f);
    const op OP_PUSHSIZE32 = op(0x20);
    const op OP_PUSHSIZE33 = op(0x21);
    const op OP_PUSHSIZE34 = op(0x22);
    const op OP_PUSHSIZE35 = op(0x23);
    const op OP_PUSHSIZE36 = op(0x24);
    const op OP_PUSHSIZE37 = op(0x25);
    const op OP_PUSHSIZE38 = op(0x26);
    const op OP_PUSHSIZE39 = op(0x27);
    
    const op OP_PUSHSIZE40 = op(0x28);
    const op OP_PUSHSIZE41 = op(0x29);
    const op OP_PUSHSIZE42 = op(0x2a);
    const op OP_PUSHSIZE43 = op(0x2b);
    const op OP_PUSHSIZE44 = op(0x2c);
    const op OP_PUSHSIZE45 = op(0x2d);
    const op OP_PUSHSIZE46 = op(0x2e);
    const op OP_PUSHSIZE47 = op(0x2f);
    const op OP_PUSHSIZE48 = op(0x30);
    const op OP_PUSHSIZE49 = op(0x31);
    
    const op OP_PUSHSIZE50 = op(0x32);
    const op OP_PUSHSIZE51 = op(0x33);
    const op OP_PUSHSIZE52 = op(0x34);
    const op OP_PUSHSIZE53 = op(0x35);
    const op OP_PUSHSIZE54 = op(0x36);
    const op OP_PUSHSIZE55 = op(0x37);
    const op OP_PUSHSIZE56 = op(0x38);
    const op OP_PUSHSIZE57 = op(0x39);
    const op OP_PUSHSIZE58 = op(0x3a);
    const op OP_PUSHSIZE59 = op(0x3b);
    
    const op OP_PUSHSIZE60 = op(0x3c);
    const op OP_PUSHSIZE61 = op(0x3d);
    const op OP_PUSHSIZE62 = op(0x3e);
    const op OP_PUSHSIZE63 = op(0x3f);
    const op OP_PUSHSIZE64 = op(0x40);
    const op OP_PUSHSIZE65 = op(0x41);
    const op OP_PUSHSIZE66 = op(0x42);
    const op OP_PUSHSIZE67 = op(0x43);
    const op OP_PUSHSIZE68 = op(0x44);
    const op OP_PUSHSIZE69 = op(0x45);
    
    const op OP_PUSHSIZE70 = op(0x46);
    const op OP_PUSHSIZE71 = op(0x47);
    const op OP_PUSHSIZE72 = op(0x48);
    const op OP_PUSHSIZE73 = op(0x49);
    const op OP_PUSHSIZE74 = op(0x4a);
    const op OP_PUSHSIZE75 = op(0x4b);

    bool inline is_push(op o) {
        return o <= OP_16 && o != OP_RESERVED;
    }
    
    bool inline is_push_data(op o) {
        return o <= OP_PUSHDATA4;
    }
    
    bool is_minimal(bytes_view);
    
    // ASM is a standard human format for Bitcoin scripts that is unique only if the script is minimally encoded. 
    string ASM(bytes_view);
    
    // a single step in a program. 
    struct instruction; 
    
    bool operator==(const instruction &, const instruction &);
    bool operator!=(const instruction &, const instruction &);
    
    size_t size(const instruction &o);
    
    std::ostream& operator<<(std::ostream&, const instruction &);
    
    instruction push_data(int z);
    instruction push_data(bytes_view);
    
    template <boost::endian::order o, bool is_signed, std::size_t size>
    instruction push_data(const data::endian::arithmetic<o, is_signed, size>& x);
    
    using program = list<instruction>;
    
    ScriptError verify(program, uint32 flags = 0);
    
    bool inline valid(program p) {
        return verify(p) == SCRIPT_ERR_OK;
    };
    
    bytes compile(program p); 
    
    bytes compile(instruction i); 
    
    program decompile(bytes_view); 
    
    size_t serialized_size(program p);

    bool is_push(program);
    
    // Representation of a Bitcoin script instruction, which is either an op code
    // by itself or an op code for pushing data to the stack along with data. 
    struct instruction {
        op Op;
        bytes Data;
        
        instruction();
        instruction(op p);
        instruction(bytes_view d) : instruction{push(d)} {}
        
        bytes data() const;
        
        ScriptError verify(uint32 flags = 0) const;
        
        bool valid() const {
            return verify() == SCRIPT_ERR_OK;
        };
        
        uint32 serialized_size() const;
        
        bool operator==(op o) const;
        bool operator!=(op o) const;
        
        template <typename writer>
        static writer &write(writer &w, const instruction&);
        
        static instruction op_code(op o);
        static instruction read(bytes_view b);
        static instruction push(bytes_view d);
        static instruction op_return_data(const bytes& data) {
            return instruction(OP_RETURN, data);
        }
        
        static size_t min_push_size(bytes_view b) {
            auto x = b.size();
            return x == 0 || (x == 1 && (b[0] == 0x81 || (b[0] >= 1 && b[0] <= 16))) ? 1 : 
                x < 75 ? x + 1 : x < 0xff ? x + 2 : x < 0xffff ? x + 3 : x + 5;
        }
        
        // use this if you want to make a non-minimal push. Otherwise use 
        // one of the other constructors. 
    private:
        instruction(op p, bytes d);
    };
    
    bool is_minimal(const instruction&);
    
    size_t inline serialized_size(const instruction &o) {
        return o.serialized_size();
    }
    
    size_t inline serialized_size(program p) {
        if (data::empty(p)) return 0;
        return serialized_size(p.first()) + serialized_size(p.rest());
    }
    
    bool inline is_push(program p) {
        if (data::empty(p)) return true;
        return is_push(p.first().Op) && is_push(p.rest());
    }
    
    bool inline operator==(const instruction &a, const instruction &b) {
        return a.Op == b.Op && a.Data == b.Data;
    }
    
    bool inline operator!=(const instruction &a, const instruction &b) {
        return !(a == b);
    }
    
    bool inline instruction::operator==(op o) const {
        return Op == o && Data.size() == 0;
    }
    
    bool inline instruction::operator!=(op o) const {
        return !operator==(o);
    }
    
    inline instruction::instruction() : Op{OP_INVALIDOPCODE}, Data{} {}
    
    inline instruction::instruction(op p, bytes d) : Op{p}, Data{d} {}
    
    inline instruction::instruction(op p) : Op{p}, Data{} {}
    
    template <typename writer>
    writer &instruction::write(writer &w, const instruction& i) {
        if (is_push_data(i.Op)) {
            if (i.Op <= OP_PUSHSIZE75) w << static_cast<byte>(i.Op);
            else if (i.Op == OP_PUSHDATA1) w << static_cast<byte>(OP_PUSHDATA1) << static_cast<byte>(i.Data.size()); 
            else if (i.Op == OP_PUSHDATA2) w << static_cast<byte>(OP_PUSHDATA2) << static_cast<uint16_little>(i.Data.size()); 
            else w << static_cast<byte>(OP_PUSHDATA2) << static_cast<uint32_little>(i.Data.size());
            return w << i.Data;
        }
        
        return w << static_cast<byte>(i.Op);
    }
    
    instruction inline instruction::op_code(op o) {
        return instruction{o};
    }

    writer inline &operator<<(writer &w, const instruction i) {
        return i.write(w, i);
    }
    
    instruction inline push_data(bytes_view b) {
        return instruction::push(b);
    }
    
    instruction inline push_data(int z) {
        return push_data(Z{z});
    }
    
    template <boost::endian::order o, bool is_signed, std::size_t size>
    instruction inline push_data(const data::endian::arithmetic<o, is_signed, size>& x) {
        return push_data(bytes_view(x));
    }
}

#endif
