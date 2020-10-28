// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include <data/math/number/bytes/N.hpp>

namespace Gigamonkey::Bitcoin {
    
    bool valid_program(program p, stack<op> x) {
        if (p.empty()) return false;
        if (!p.first().valid()) return false;
        op o = p.first().Op;
        if (o == OP_ENDIF) {
            if (x.empty()) return false;
            op prev = x.first();
            x = x.rest();
            if (prev == OP_ELSE) {
                if (x.empty()) return false;
                prev = x.first();
                x = x.rest();
            }
            if (prev != OP_IF && prev != OP_NOTIF) return false;
        } else if (o == OP_ELSE || o == OP_IF || o == OP_NOTIF) x = x << o;
        if (p.size() == 1) return x.empty();
        if (o == OP_RETURN && p.first().Data.size() != 0) return false;
        return valid_program(p.rest(), x);
    }
    
    bool valid(program p) {
        return valid_program(p, {});
    }
    
    bool provably_prunable_recurse(program p) {
        if (p.size() < 2) return false;
        if (p.size() == 2) return p.first().Op == OP_FALSE && p.rest().first() == OP_RETURN;
        return provably_prunable_recurse(p);
    }
    
    bool provably_prunable(program p) {
        if (!p.valid()) return false;
        return provably_prunable_recurse(p);
    }
    
    // We already know that o has size at least 1 
    // when we call this function. 
    uint32 next_instruction_size(bytes_view o) {
        op p = op(o[0]);
        if (p == OP_INVALIDOPCODE) return 0;
        if (!is_push_data(p)) return 1;
        if (p <= OP_PUSHSIZE75) return (p + 1);
        if (p == OP_PUSHDATA1) {
            if (o.size() < 2) return 0;
            return o[1] + 2;
        }
        if (p == OP_PUSHDATA2) {
            if (o.size() < 3) return 0;
            return boost::endian::load_little_u16(&o[1]) + 3;
        }
        // otherwise it's OP_PUSHDATA4
        if (o.size() < 5) return 0;
        return boost::endian::load_little_u32(&o[1]) + 5;
    }
    
    // Inefficient: extra copying. 
    instruction push_value(int z) {
        if (z == 0) return OP_FALSE;
        if (z == -1) return OP_1NEGATE;
        if (z > 0 && z <= 16) return op(0x50 + z);
        if (z < 0 || z > 127) throw method::unimplemented{"push_value"};
        data::math::number::N_bytes<data::endian::little> zz{static_cast<uint64>(z)};
        bytes b(1);
        std::copy(zz.begin(), zz.begin() + 1, b.begin());
        return instruction{b};
    }
    
    // inefficient: copying. 
    instruction push_hex(std::string str) {
        data::encoding::hex::view hex{str};
        if (!hex.valid()) return instruction{};
        data::bytes b = data::bytes_view(hex);
        bytes x(b.size());
        std::copy(b.begin(), b.end(), x.begin());
        return instruction{x};
    }
    
    struct script_writer {
        bytes_writer Writer;
        script_writer operator<<(instruction o) const {
            return script_writer{write(Writer, o)};
        }
        
        script_writer operator<<(program p) const {
            return p.size() == 0 ? script_writer{Writer} : (script_writer{Writer} << p.first() << p.rest());
        }
        
        script_writer(bytes_writer w) : Writer{w} {}
    };
    
    bytes_reader read_push(bytes_reader r, instruction& rest) {
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
        
        // TODO inefficient because I copy data here for
        // no reason other than not wanting to re-write
        // some old types. 
        rest.Data = bytes(size);
        data::bytes bx(size);
        r = r >> bx;
        std::copy(bx.begin(), bx.end(), rest.Data.begin());
        return r;
    }
    
    struct script_reader {
        bytes_reader Reader;
        script_reader operator>>(instruction& i) const {
            byte next;
            bytes_reader r = Reader >> next;
            i.Op = static_cast<op>(next);
            if (is_push_data(i.Op)) return read_push(r, i);
            return r;
        }
        
        bool empty() const {
            return Reader.empty();
        }
        
        script_reader(bytes_reader r) : Reader{r} {}
        script_reader(bytes_view b) : Reader{b.data(), b.data() + b.size()} {}
    };
    
    instruction instruction::read(bytes_view b) {
        instruction i;
        script_reader{b} >> i;
        return i;
    }
    
    bytes compile(program p) {
        bytes compiled(length(p));
        script_writer{bytes_writer{compiled.begin(), compiled.end()}} << p;
        return compiled;
    }
    
    bytes compile(instruction i) {
        bytes compiled(length(i));
        script_writer{bytes_writer{compiled.begin(), compiled.end()}} << i;
        return compiled;
    }
    
    program decompile(bytes_view b) {
        program p{};
        script_reader r{bytes_reader{b.data(), b.data() + b.size()}};
        while(!r.empty()) {
            instruction i{};
            r = r >> i;
            p = p << i;
        }
        return p;
    }
    
    bytes_view pattern::atom::scan(bytes_view p) const {
        if (p.size() == 0) throw fail{};
        if (p[0] != Instruction.Op) throw fail{};
        uint32 size = next_instruction_size(p);
        if (p.size() < size || Instruction != instruction::read(p.substr(0, size))) throw fail{};
        return p.substr(size);
    }
    
    bytes_view pattern::string::scan(bytes_view p) const {
        if (p.size() < Program.size()) throw fail{};
        for (int i = 0; i < Program.size(); i++) if (p[i] != Program[i]) throw fail{};
        return p.substr(Program.size());
    }
    
    bytes_view any::scan(bytes_view p) const {
        if (p.size() == 0) throw fail{};
        uint32 size = next_instruction_size(p);
        if (p.size() < size) throw fail{};
        return p.substr(size);
    }
    
    bool push::match(const instruction& i) const {
        switch (Type) {
            case any : 
                return is_push(i.Op);
            case value : 
                return is_push(i.Op) && Value == Z{data::math::number::Z_bytes<data::endian::little>{i.data()}};
            case data : 
                return is_push(i.Op) && Data == i.data();
            case read : 
                if (!is_push(i.Op)) return false;
                Read = i.data();
                return true;
            default: 
                return false;
        }
    }
    
    bytes_view push::scan(bytes_view p) const {
        if (p.size() == 0) throw fail{};
        uint32 size = next_instruction_size(p);
        if (size == 0) throw fail{};
        if (!match(instruction::read(p.substr(0, size)))) throw fail{};
        return p.substr(size);
    }
    
    bool push_size::match(const instruction& i) const {
        bytes Data = i.data();
        if (Data.size() != Size) return false;
        if (Reader) Read = Data;
        return true;
    }
    
    bytes_view push_size::scan(bytes_view p) const {
        if (p.size() == 0) throw fail{};
        uint32 size = next_instruction_size(p);
        if (!match(instruction::read(p.substr(0, size)))) throw fail{};
        return p.substr(size);
    }
    
    bytes_view pattern::sequence::scan(bytes_view p) const {
        list<ptr<pattern>> patt = Patterns;
        while (!data::empty(patt)) {
            p = patt.first()->scan(p);
            patt = patt.rest();
        }
        return p;
    }
        
    bytes_view optional::scan(bytes_view p) const {
        try {
            return pattern::Pattern->scan(p);
        } catch (fail) {
            return p;
        }
    }
    
    bytes_view repeated::scan(bytes_view p) const {
        ptr<pattern> patt = pattern::Pattern;
        uint32 min = Second == -1 && Directive == or_less ? 0 : First;
        int64 max = Second != -1 ? Second : Directive == or_more ? -1 : First;
        uint32 matches = 0;
        while (true) {
            try {
                p = patt->scan(p);
                matches++;
                if (matches == max) return p;
            } catch (fail) {
                if (matches < min) throw fail{};
                return p;
            }
        }
    }
    
    bytes_view alternatives::scan(bytes_view b) const {
        list<ptr<pattern>> patt = Patterns;
        while (!data::empty(patt)) {
            try {
                return patt.first()->scan(b);
            } catch (fail) {
                patt = patt.rest();
            }
        }
        throw fail{};
    };

    std::ostream& write_op_code(std::ostream& o, op x) {
        if (x == OP_FALSE) return o << "push_empty";
        if (is_push(x)) {
            switch(x) {
                case OP_PUSHDATA1 : return o << "push_data_1";
                case OP_PUSHDATA2 : return o << "push_data_2";
                case OP_PUSHDATA4 : return o << "push_data_4";
                case OP_FALSE : return o << "(0)";
                case OP_1NEGATE: return o << "(-1)";
                case OP_1: return o << "(1)";
                case OP_2: return o << "(2)";
                case OP_3: return o << "(3)";
                case OP_4: return o << "(4)";
                case OP_5: return o << "(5)";
                case OP_6: return o << "(6)";
                case OP_7: return o << "(7)";
                case OP_8: return o << "(8)";
                case OP_9: return o << "(9)";
                case OP_10: return o << "(10)";
                case OP_11: return o << "(11)";
                case OP_12: return o << "(12)";
                case OP_13: return o << "(13)";
                case OP_14: return o << "(14)";
                case OP_15: return o << "(15)";
                case OP_16: return o << "(16)";
                default : return o << "push_size_" << int{x};
            }
        }
        
        switch (x) {
            default : return o << "***unknown op code***";
            case OP_CHECKSIG: return o << "checksig";
            case OP_CHECKSIGVERIFY: return o << "checksig_verify";
            case OP_EQUALVERIFY: return o << "equal_verify";
            
            case OP_HASH256: return o << "hash256";
            
            case OP_RESERVED: return o << "reserved";
            
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
            
            case OP_SIZE: return o << "size";
            case OP_CAT: return o << "cat";
            case OP_SPLIT: return o << "split";
            
            case OP_LESSTHAN : return o << "less";
            case OP_GREATERTHAN : return o << "greater";
            case OP_LESSTHANOREQUAL : return o << "less_equal";
            case OP_GREATERTHANOREQUAL : return o << "greater_equal";
            case OP_WITHIN : return o << "within";
            
            case OP_SUB : return o << "subtract";
            case OP_ADD : return o << "add";
            case OP_MUL : return o << "mul";
            
            case OP_RSHIFT : return o << "rshift";
            case OP_LSHIFT : return o << "lshift";
            
        }
    }

    std::ostream& operator<<(std::ostream& o, instruction i) {
        if (!is_push_data(i.Op)) return write_op_code(o, i.Op);
        return write_op_code(o, i.Op) << "{" << data::encoding::hex::write(i.Data) << "}";
    }

}
