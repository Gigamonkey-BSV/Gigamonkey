// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT
#define GIGAMONKEY_SCRIPT

#include <boost/endian/conversion.hpp>
#include "signature.hpp"

namespace gigamonkey::bitcoin::script {
    enum op : byte {
        // push value
        OP_0 = 0x00,
        OP_FALSE = OP_0,
            
        OP_PUSHSIZE1 = 0x01,
        OP_PUSHSIZE2 = 0x02,
        OP_PUSHSIZE3 = 0x03,
        OP_PUSHSIZE4 = 0x04,
        OP_PUSHSIZE5 = 0x05,
        OP_PUSHSIZE6 = 0x06,
        OP_PUSHSIZE7 = 0x07,
        OP_PUSHSIZE8 = 0x08,
        OP_PUSHSIZE9 = 0x09,
        
        OP_PUSHSIZE10 = 0x0a, 
        OP_PUSHSIZE11 = 0x0b,
        OP_PUSHSIZE12 = 0x0c,
        OP_PUSHSIZE13 = 0x0d,
        OP_PUSHSIZE14 = 0x0e,
        OP_PUSHSIZE15 = 0x0f,
        OP_PUSHSIZE16 = 0x10,
        OP_PUSHSIZE17 = 0x11,
        OP_PUSHSIZE18 = 0x12,
        OP_PUSHSIZE19 = 0x13,
        
        OP_PUSHSIZE20 = 0x14,
        OP_PUSHSIZE21 = 0x15,
        OP_PUSHSIZE22 = 0x16,
        OP_PUSHSIZE23 = 0x17,
        OP_PUSHSIZE24 = 0x18,
        OP_PUSHSIZE25 = 0x19,
        OP_PUSHSIZE26 = 0x1a,
        OP_PUSHSIZE27 = 0x1b,
        OP_PUSHSIZE28 = 0x1c,
        OP_PUSHSIZE29 = 0x1d,
        
        OP_PUSHSIZE30 = 0x1e,
        OP_PUSHSIZE31 = 0x1f,
        OP_PUSHSIZE32 = 0x20,
        OP_PUSHSIZE33 = 0x21,
        OP_PUSHSIZE34 = 0x22,
        OP_PUSHSIZE35 = 0x23,
        OP_PUSHSIZE36 = 0x24,
        OP_PUSHSIZE37 = 0x25,
        OP_PUSHSIZE38 = 0x26,
        OP_PUSHSIZE39 = 0x27,
        
        OP_PUSHSIZE40 = 0x28,
        OP_PUSHSIZE41 = 0x29,
        OP_PUSHSIZE42 = 0x2a,
        OP_PUSHSIZE43 = 0x2b,
        OP_PUSHSIZE44 = 0x2c,
        OP_PUSHSIZE45 = 0x2d,
        OP_PUSHSIZE46 = 0x2e,
        OP_PUSHSIZE47 = 0x2f,
        OP_PUSHSIZE48 = 0x30,
        OP_PUSHSIZE49 = 0x31,
        
        OP_PUSHSIZE50 = 0x32,
        OP_PUSHSIZE51 = 0x33,
        OP_PUSHSIZE52 = 0x34,
        OP_PUSHSIZE53 = 0x35,
        OP_PUSHSIZE54 = 0x36,
        OP_PUSHSIZE55 = 0x37,
        OP_PUSHSIZE56 = 0x38,
        OP_PUSHSIZE57 = 0x39,
        OP_PUSHSIZE58 = 0x3a,
        OP_PUSHSIZE59 = 0x3b,
        
        OP_PUSHSIZE60 = 0x3c,
        OP_PUSHSIZE61 = 0x3d,
        OP_PUSHSIZE62 = 0x3e,
        OP_PUSHSIZE63 = 0x3f,
        OP_PUSHSIZE64 = 0x40,
        OP_PUSHSIZE65 = 0x41,
        OP_PUSHSIZE66 = 0x42,
        OP_PUSHSIZE67 = 0x43,
        OP_PUSHSIZE68 = 0x44,
        OP_PUSHSIZE69 = 0x45,
        
        OP_PUSHSIZE70 = 0x46,
        OP_PUSHSIZE71 = 0x47,
        OP_PUSHSIZE72 = 0x48,
        OP_PUSHSIZE73 = 0x49,
        OP_PUSHSIZE74 = 0x4a,
        OP_PUSHSIZE75 = 0x4b,
        
        OP_PUSHDATA1 = 0x4c,
        OP_PUSHDATA2 = 0x4d,
        OP_PUSHDATA4 = 0x4e,
        OP_1NEGATE = 0x4f,
        OP_RESERVED = 0x50,
        OP_1 = 0x51,
        OP_TRUE = OP_1,
        OP_2 = 0x52,
        OP_3 = 0x53,
        OP_4 = 0x54,
        OP_5 = 0x55,
        OP_6 = 0x56,
        OP_7 = 0x57,
        OP_8 = 0x58,
        OP_9 = 0x59,
        OP_10 = 0x5a,
        OP_11 = 0x5b,
        OP_12 = 0x5c,
        OP_13 = 0x5d,
        OP_14 = 0x5e,
        OP_15 = 0x5f,
        OP_16 = 0x60,

        // control
        OP_NOP = 0x61,
        OP_VER = 0x62,
        OP_IF = 0x63,
        OP_NOTIF = 0x64,
        OP_VERIF = 0x65,
        OP_VERNOTIF = 0x66,
        OP_ELSE = 0x67,
        OP_ENDIF = 0x68,
        OP_VERIFY = 0x69,
        OP_RETURN = 0x6a,

        // stack ops
        OP_TOALTSTACK = 0x6b,
        OP_FROMALTSTACK = 0x6c,
        OP_2DROP = 0x6d,
        OP_2DUP = 0x6e,
        OP_3DUP = 0x6f,
        OP_2OVER = 0x70,
        OP_2ROT = 0x71,
        OP_2SWAP = 0x72,
        OP_IFDUP = 0x73,
        OP_DEPTH = 0x74,
        OP_DROP = 0x75,
        OP_DUP = 0x76,
        OP_NIP = 0x77,
        OP_OVER = 0x78,
        OP_PICK = 0x79,
        OP_ROLL = 0x7a,
        OP_ROT = 0x7b,
        OP_SWAP = 0x7c,
        OP_TUCK = 0x7d,

        // splice ops
        OP_CAT = 0x7e,
        OP_SPLIT = 0x7f,   // after monolith upgrade (May 2018)
        OP_NUM2BIN = 0x80, // after monolith upgrade (May 2018)
        OP_BIN2NUM = 0x81, // after monolith upgrade (May 2018)
        OP_SIZE = 0x82,
            
        // bit logic
        OP_INVERT = 0x83,
        OP_AND = 0x84,
        OP_OR = 0x85,
        OP_XOR = 0x86,
        OP_EQUAL = 0x87,
        OP_EQUALVERIFY = 0x88,
        OP_RESERVED1 = 0x89,
        OP_RESERVED2 = 0x8a,

        // numeric
        OP_1ADD = 0x8b,
        OP_1SUB = 0x8c,
        OP_2MUL = 0x8d,
        OP_2DIV = 0x8e,
        OP_NEGATE = 0x8f,
        OP_ABS = 0x90,
        OP_NOT = 0x91,
        OP_0NOTEQUAL = 0x92,

        OP_ADD = 0x93,
        OP_SUB = 0x94,
        OP_MUL = 0x95,
        OP_DIV = 0x96,
        OP_MOD = 0x97,
        OP_LSHIFT = 0x98,
        OP_RSHIFT = 0x99,

        OP_BOOLAND = 0x9a,
        OP_BOOLOR = 0x9b,
        OP_NUMEQUAL = 0x9c,
        OP_NUMEQUALVERIFY = 0x9d,
        OP_NUMNOTEQUAL = 0x9e,
        OP_LESSTHAN = 0x9f,
        OP_GREATERTHAN = 0xa0,
        OP_LESSTHANOREQUAL = 0xa1,
        OP_GREATERTHANOREQUAL = 0xa2,
        OP_MIN = 0xa3,
        OP_MAX = 0xa4,

        OP_WITHIN = 0xa5,

        // crypto
        OP_RIPEMD160 = 0xa6,
        OP_SHA1 = 0xa7,
        OP_SHA256 = 0xa8,
        OP_HASH160 = 0xa9,
        OP_HASH256 = 0xaa,
        OP_CODESEPARATOR = 0xab,
        OP_CHECKSIG = 0xac,
        OP_CHECKSIGVERIFY = 0xad,
        OP_CHECKMULTISIG = 0xae,
        OP_CHECKMULTISIGVERIFY = 0xaf,

        // expansion
        OP_NOP1 = 0xb0,
        OP_CHECKLOCKTIMEVERIFY = 0xb1,
        OP_NOP2 = OP_CHECKLOCKTIMEVERIFY,
        OP_CHECKSEQUENCEVERIFY = 0xb2,
        OP_NOP3 = OP_CHECKSEQUENCEVERIFY,
        OP_NOP4 = 0xb3,
        OP_NOP5 = 0xb4,
        OP_NOP6 = 0xb5,
        OP_NOP7 = 0xb6,
        OP_NOP8 = 0xb7,
        OP_NOP9 = 0xb8,
        OP_NOP10 = 0xb9,

        // The first op_code value after all defined opcodes
        FIRST_UNDEFINED_OP_VALUE,

        // template matching params
        OP_SMALLINTEGER = 0xfa,
        OP_PUBKEYS = 0xfb,
        OP_PUBKEYHASH = 0xfd,
        OP_PUBKEY = 0xfe,

        OP_INVALIDOPCODE = 0xff,
    };
    
    inline bool is_push(op o) {
        return o <= OP_16 && o != OP_RESERVED;
    }
    
    inline bool is_push_data(op o) {
        return o <= OP_PUSHDATA4;
    }
    
    inline uint32 next_instruction_size(bytes_view o) {
        return o[0] <= OP_PUSHSIZE75 ? o[0] + 1 : 
            o[0] == OP_PUSHDATA1 ? o[1] + 2 : 
            o[0] == OP_PUSHDATA2 ? boost::endian::load_little_u16(&o[1]) + 3 : 
            o[0] == OP_PUSHDATA4 ? boost::endian::load_little_u32(&o[1]) + 5 : 1;
    }
    
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
            if (!is_push(Op)) return {};
            if (is_push_data(Op)) return Data;
            if (Op == OP_1NEGATE) return {OP_1NEGATE};
            return {{static_cast<byte>(byte{Op} - byte{0x50})}};
        }
        
        bool valid() {
            if (Op == OP_INVALIDOPCODE) return false;
            size_t size = Data.size();
            return (!is_push_data(Op) && size == 0) || (Op <= OP_PUSHSIZE75 && Op == size) 
                || (Op == OP_PUSHDATA1 && size <= 0xffff) 
                || (Op == OP_PUSHDATA2 && size <= 0xffffffff) 
                || (Op == OP_PUSHDATA4 && size <= 0xffffffffffffffff);
        }
        
        uint32 length() const {
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
        
        static bytes_writer write_push_data(bytes_writer w, op Push, size_t size) {
            if (Push <= OP_PUSHSIZE75) return w << static_cast<byte>(Push);
            if (Push == OP_PUSHDATA1) return w << static_cast<byte>(OP_PUSHDATA1) << static_cast<byte>(size); 
            if (Push == OP_PUSHDATA2) return w << static_cast<byte>(OP_PUSHDATA2) << static_cast<uint32_little>(size); 
            return w << static_cast<byte>(OP_PUSHDATA4) << uint64_little{size};
        }
        
        bytes_writer write(bytes_writer w) const {
            if (is_push_data(Op))return write_push_data(w, Op, Data.size());
            return w << static_cast<byte>(Op);
        }
    
        static instruction op_code(op o) {
            return instruction{o};
        }
        
        static instruction push_data(bytes_view b) {
            return instruction{b};
        }
        
        static instruction read(bytes_view b);
        
    };
    
    using program = queue<instruction>;
    
    bytes compile(program p);
    
    bytes compile(instruction i);
    
    program decompile(bytes_view);
    
    inline size_t length(instruction o) {
        return o.length();
    }
    
    inline size_t length(program p) {
        if (p.empty()) return 0;
        return length(p.first()) + length(p.rest());
    }
    
}

std::ostream& operator<<(std::ostream& o, gigamonkey::bitcoin::script::op);

inline std::ostream& operator<<(std::ostream& o, gigamonkey::bitcoin::script::instruction i) {
    if (!gigamonkey::bitcoin::script::is_push_data(i.Op)) return o << i.Op;
    return o << i.Op << "{" << data::encoding::hex::write(i.Data) << "}";
}

namespace gigamonkey::bitcoin::script {
    
    inline bytes_writer write(bytes_writer w, instruction o) {
        return o.write(w);
    }
    
    inline bytes_writer write(bytes_writer w, program p) {
        if (p.empty()) return w;
        return write(write(w, p.first()), p.rest());
    }
    
}

#endif

