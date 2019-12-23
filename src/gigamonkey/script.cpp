// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script.hpp>

namespace gigamonkey::bitcoin::script {
    
    struct writer {
        timechain::writer Writer;
        writer operator<<(instruction o) const {
            return writer{write(Writer, o)};
        }
        
        writer operator<<(program p) const {
            return writer{write(Writer, p)};
        }
        
        writer(timechain::writer w) : Writer{w.Writer} {}
        writer(bytes& b) : Writer{timechain::writer{data::slice<byte>{b}}} {}
    };
    
    timechain::reader read_push(timechain::reader r, instruction& rest) {
        uint32 size;
        if (rest.Op <= OP_PUSHSIZE75) size = rest.Op;
        if (rest.Op == OP_PUSHDATA1) {
            byte x;
            r = r >> x;
            size = x;
        }
        if (rest.Op == OP_PUSHDATA2) {
            uint16_little x;
            r = r >> x;
            size = x;
        }
        if (rest.Op == OP_PUSHDATA4) {
            uint32_little x;
            r = r >> x;
            size = x;
        }
        rest.Data.resize(size);
        return r >> rest.Data;
    }
    
    struct reader {
        timechain::reader Reader;
        reader operator>>(instruction& i) const {
            byte next;
            timechain::reader r = Reader >> next;
            i.Op = op{next};
            if (is_push_data(i.Op)) return read_push(r, i);
            return r;
        }
        
        bool empty() const {
            return Reader.empty();
        }
        
        reader(timechain::reader r) : Reader{r} {}
        reader(bytes_view b) : Reader{timechain::reader{b}} {}
    };
    
    // TODO there is an exception thrown here. 
    // I am not initializing the string correctly. 
    // I don't know how to do it right. 
    bytes compile(program p) {
        bytes compiled{};
        compiled.resize(length(p));
        writer{compiled} << p;
        return compiled;
    }
    
    program decompile(bytes_view b) {
        program p{};
        reader r{b};
        while(!r.empty()) {
            instruction i{};
            r = r >> i;
            p = p + i;
        }
        return p;
    }
    
}

std::ostream& operator<<(std::ostream& o, gigamonkey::bitcoin::script::op x) {
    using namespace gigamonkey::bitcoin::script;
    if (x == OP_FALSE) return o << "push_empty";
    if (is_push(x)) {
        switch(x) {
            case OP_PUSHDATA1 : return o << "push_data_1";
            case OP_PUSHDATA2 : return o << "push_data_2";
            case OP_PUSHDATA4 : return o << "push_data_4";
            default : return o << "push_size_" << int{x};
        }
    }
    
    switch (x) {
        default : return o << "***unknown op code***";
        case OP_CHECKSIG: return o << "checksig";
        case OP_CHECKSIGVERIFY: return o << "checksig_verify";
        case OP_EQUALVERIFY: return o << "equal_verify";
        
        case OP_1NEGATE: return o << "push_-1";
        
        case OP_RESERVED: return o << "reserved";
        
        case OP_1: return o << "push_true";
        case OP_2: return o << "push_2";
        case OP_3: return o << "push_3";
        case OP_4: return o << "push_4";
        case OP_5: return o << "push_5";
        case OP_6: return o << "push_6";
        case OP_7: return o << "push_7";
        case OP_8: return o << "push_8";
        case OP_9: return o << "push_9";
        case OP_10: return o << "push_10";
        case OP_11: return o << "push_11";
        case OP_12: return o << "push_12";
        case OP_13: return o << "push_13";
        case OP_14: return o << "push_14";
        case OP_15: return o << "push_15";
        case OP_16: return o << "push_16";
        
        case OP_NOP: return o << "nop";
        case OP_VER: return o << "ver";
        case OP_IF: return o << "if";
        case OP_NOTIF: return o << "not_if";
        case OP_VERIF: return o << "ver_if";
        case OP_VERNOTIF: return o << "ver_not_if";
        case OP_ELSE: return o << "else";
        case OP_ENDIF: return o << "end_if";
        case OP_VERIFY: return o << "verify";
        case OP_RETURN: return o << "return";

        case OP_TOALTSTACK: return o << "to_alt_stack";
        case OP_FROMALTSTACK: return o << "from_alt_stack";
        case OP_2DROP: return o << "2_drop";
        case OP_2DUP: return o << "2_dup";
        case OP_3DUP: return o << "3_dup";
        case OP_2OVER: return o << "2_over";
        case OP_2ROT: return o << "2_rot";
        case OP_2SWAP: return o << "2_swap";
        case OP_IFDUP: return o << "if_dup";
        case OP_DEPTH: return o << "depth";
        case OP_DROP: return o << "drop";
        case OP_DUP: return o << "dup";
        case OP_NIP: return o << "nip";
        case OP_OVER: return o << "over";
        case OP_PICK: return o << "pick";
        case OP_ROLL: return o << "roll";
        case OP_ROT: return o << "rot";
        case OP_SWAP: return o << "swap";
        case OP_TUCK: return o << "tuck";
        
    }
}

