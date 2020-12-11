// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_SCRIPT
#define GIGAMONKEY_SCRIPT_SCRIPT

#include <sv/script/script.h>
#include <sv/script/script_error.h>

#include <boost/endian/conversion.hpp>

#include <gigamonkey/signature.hpp>
#include <gigamonkey/address.hpp>

namespace Gigamonkey::Bitcoin { 
    
    struct evaluated {
        bsv::ScriptError Error;
        bool Return;
        
        evaluated() : Error{bsv::SCRIPT_ERR_OK}, Return{false} {}
        evaluated(bsv::ScriptError err) : Error{err}, Return{false} {}
        
        bool valid() const {
            return Error == bsv::SCRIPT_ERR_OK;
        }
        
        bool operator==(const evaluated e) const {
            return Error == e.Error && Return == e.Return;
        }
        
        bool operator!=(const evaluated e) const {
            return !operator==(e);
        }
    };
    
    // Test validity of a script. All signature operations succeed. 
    evaluated evaluate_script(const script& unlock, const script& lock);
    
    // Evaluate script with real signature operations. 
    evaluated evaluate_script(const script& unlock, const script& lock, const input_index& tx);
    
    using op = opcodetype;
    
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
    
    // Representation of a Bitcoin script instruction, which is either an op code
    // by itself or an op code for pushing data to the stack along with data. 
    struct instruction {
        op Op;
        bytes Data;
        
        instruction() : Op{OP_INVALIDOPCODE}, Data{} {}
        
        instruction(op p, bytes d) : Op{p}, Data{d} {}
        
        instruction(op p) : Op{p}, Data{} {}
        
        instruction(bytes_view data) : Op{[](size_t size)->op{
            if (size <= OP_PUSHSIZE75) return static_cast<op>(size);
            if (size <= 0xffff) return OP_PUSHDATA1;
            if (size <= 0xffffffff) return OP_PUSHDATA2;
            return OP_PUSHDATA4;
        }(data.size())}, Data{data} {} 
        
        bytes data() const {
            if (is_push_data(Op) || Op == OP_RETURN) return Data;
            if (!is_push(Op)) return {};
            if (Op == OP_1NEGATE) return {OP_1NEGATE};
            return bytes{static_cast<byte>(Op - 0x50)};
        }
        
        bool valid() const {
            if (Op == OP_INVALIDOPCODE) return false;
            if (Op == OP_RETURN) return true;
            size_t size = Data.size();
            return (!is_push_data(Op) && size == 0) || (Op <= OP_PUSHSIZE75 && Op == size) 
                || (Op == OP_PUSHDATA1 && size <= 0xffff) 
                || (Op == OP_PUSHDATA2 && size <= 0xffffffff) 
                || (Op == OP_PUSHDATA4 && size <= 0xffffffffffffffff);
        }
        
        uint32 length() const {
            if (Op == OP_RETURN) return Data.size() + 1;
            if (!is_push_data(Op)) return 1;
            uint32 size = Data.size();
            if (Op <= OP_PUSHSIZE75) return size + 1;
            if (Op == OP_PUSHDATA1) return size + 2;
            if (Op == OP_PUSHDATA2) return size + 3;
            if (Op == OP_PUSHDATA4) return size + 5;
            return 0; // invalid 
        }
        
        bool operator==(instruction x) const {
            return Op == x.Op && Data == x.Data;
        }
        
        bool operator!=(instruction x) const {
            return !operator==(x);
        }
        
        bool operator==(op o) const {
            return Op == o && Data.size() == 0;
        }
        
        bool operator!=(op o) const {
            return !operator==(o);
        }
        
        bytes_writer write(bytes_writer w) const {
            return is_push_data(Op) ? 
                write_push_data(w, Op, Data.size()) << Data : 
                w << static_cast<byte>(Op);
        }
        
        static instruction op_code(op o) {
            return instruction{o};
        }
        
        static instruction op_return(bytes_view b) {
            return {OP_RETURN, b};
        }
        
        static instruction read(bytes_view b);
        
    private:
        static bytes_writer write_push_data(bytes_writer w, op Push, size_t size) {
            if (Push <= OP_PUSHSIZE75) return w << static_cast<byte>(Push);
            if (Push == OP_PUSHDATA1) return w << static_cast<byte>(OP_PUSHDATA1) << static_cast<byte>(size); 
            if (Push == OP_PUSHDATA2) return w << static_cast<byte>(OP_PUSHDATA2) << static_cast<uint16_little>(size); 
            return w << static_cast<byte>(OP_PUSHDATA2) << static_cast<uint32_little>(size);
        }
    };
    
    instruction push_value(int);
    
    instruction push_hex(std::string);
    
    using program = list<instruction>;
    
    bool valid(program);
    
    bytes compile(program p); 
    
    bytes compile(instruction i); 
    
    program decompile(bytes_view); 
    
    size_t inline length(instruction o) {
        return o.length();
    }
    
    size_t inline length(program p) {
        if (p.empty()) return 0;
        return length(p.first()) + length(p.rest());
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
    
    instruction inline push_data(pubkey p) {
        return instruction{write(p.size(), p)};
    }
    
    program inline safe_op_return(bytes_view b) {
        return {OP_FALSE, instruction::op_return(b)};
    }
    
    bool provably_prunable(program p);
    
}

#endif 


