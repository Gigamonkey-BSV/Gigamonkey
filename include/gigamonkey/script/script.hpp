// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_SCRIPT
#define GIGAMONKEY_SCRIPT_SCRIPT

#include <sv/script/opcodes.h>
#include <sv/script/script_error.h>

#include <boost/endian/conversion.hpp>

#include <gigamonkey/signature.hpp>
#include <gigamonkey/wif.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 
    
    // the result returned from a script evaluatuon. 
    // There is a success or failure and a possible error. 
    struct result; 
    
    // Test validity of a script. All signature operations succeed. 
    result evaluate(const script& unlock, const script& lock);
    
    // Evaluate script with real signature operations. 
    result evaluate(const script& unlock, const signature::document &lock);
    
    bool operator==(const result &, const result &);
    bool operator!=(const result &, const result &);
    
    using op = opcodetype;

    bool inline is_push(op o) {
        return o <= OP_16 && o != OP_RESERVED;
    }
    
    bool inline is_push_data(op o) {
        return o <= OP_PUSHDATA4;
    }
    
    // a single step in a program. 
    struct instruction; 
    
    bool operator==(const instruction &, const instruction &);
    bool operator!=(const instruction &, const instruction &);
    
    size_t size(const instruction &o);
    
    std::ostream& operator<<(std::ostream&, const instruction &);
    
    instruction push_value(int);
    
    instruction push_hex(std::string);
    
    using program = list<instruction>;
    
    bool valid(program);
    
    bytes compile(program p); 
    
    bytes compile(instruction i); 
    
    program decompile(bytes_view); 
    
    size_t inline size(program p) {
        if (p.empty()) return 0;
        return size(p.first()) + size(p.rest());
    }
    
    struct result {
        ScriptError Error;
        bool Return;
        
        result() : Error{SCRIPT_ERR_OK}, Return{false} {}
        result(ScriptError err) : Error{err}, Return{false} {}
        
        bool valid() const {
            return !Error;
        }
        
        bool verify() const {
            return !Error && Return;
        }
        
        operator bool() const {
            return verify();
        }
    };
    
    // Representation of a Bitcoin script instruction, which is either an op code
    // by itself or an op code for pushing data to the stack along with data. 
    struct instruction {
        op Op;
        bytes Data;
        
        instruction();
        instruction(op p, bytes d);
        instruction(op p);
        instruction(bytes_view);
        
        bytes data() const;
        
        bool valid() const;
        
        uint32 size() const;
        
        bool operator==(op o) const;
        bool operator!=(op o) const;
        
        bytes_writer write(bytes_writer w) const;
        
        static instruction op_code(op o);
        static instruction op_return(bytes_view b);
        static instruction read(bytes_view b);
        
    private:
        static bytes_writer write_push_data(bytes_writer w, op Push, size_t size);
    };
    
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
    
    size_t inline size(const instruction &o) {
        return o.size();
    }
    
    instruction inline push_data(int32_little x) {
        return instruction{bytes_view{x.data(), 4}};
    }
    
    instruction inline push_data(uint32_little x) {
        return instruction{bytes_view{x.data(), 4}};
    }
    
    instruction inline push_data(uint64_little x) {
        return instruction{bytes_view{x.data(), 8}};
    }
    
    instruction inline push_data(bytes_view x) {
        return instruction{x};
    }
    
    instruction inline push_data(const pubkey &p) {
        return instruction{write(p.size(), p)};
    }
    
    program inline safe_op_return(bytes_view b) {
        return {OP_FALSE, instruction::op_return(b)};
    }
    
    bool inline is_op_return(const script& p) {
        return (p.size() > 1 && p[0] == 0x6a) || (p.size() > 2 && p[0] == 0x00 && p[1] == 0x6a);
    }
    
    bool inline operator==(const result &a, const result &b) {
        return a.Return == b.Return && a.Error == b.Error;
    }
    
    bool inline operator!=(const result &a, const result &b) {
        return !(a == b);
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
    
    bytes_writer inline instruction::write(bytes_writer w) const {
        return is_push_data(Op) ? 
            write_push_data(w, Op, Data.size()) << Data : 
            w << static_cast<byte>(Op);
    }
    
    instruction inline instruction::op_code(op o) {
        return instruction{o};
    }
    
    instruction inline instruction::op_return(bytes_view b) {
        return instruction{OP_RETURN, b};
    }

    bytes_writer inline operator<<(bytes_writer w, const instruction i) {
        return i.write(w);
    }
    
}

#endif 


