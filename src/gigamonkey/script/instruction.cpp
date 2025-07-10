// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include <data/math/number/bytes/Z.hpp>

namespace Gigamonkey::Bitcoin {

    writer &operator << (writer &w, const instruction &i) {
        if (is_push_data (i.Op)) {
            if (i.Op <= OP_PUSHSIZE75) w << static_cast<byte> (i.Op);
            else if (i.Op == OP_PUSHDATA1) w << static_cast<byte> (OP_PUSHDATA1) << static_cast<byte> (i.Data.size ());
            else if (i.Op == OP_PUSHDATA2) w << static_cast<byte> (OP_PUSHDATA2) << static_cast<uint16_little> (i.Data.size ());
            else w << static_cast<byte> (OP_PUSHDATA4) << static_cast<uint32_little> (i.Data.size ());
            return w << i.Data;
        }

        return w << static_cast<byte> (i.Op);
    }
    
    namespace {
    
        ScriptError verify_instruction (const instruction &i) {
            if (i.Op == OP_INVALIDOPCODE ||
                i.Op == OP_RESERVED ||
                i.Op == OP_RESERVED1 ||
                i.Op == OP_RESERVED2 ||
                i.Op >= FIRST_UNDEFINED_OP_VALUE) return SCRIPT_ERR_BAD_OPCODE;
            
            size_t size = i.Data.size ();
            if (!is_push_data (i.Op)) {
                if (size > 0) return SCRIPT_ERR_PUSH_SIZE;
                return SCRIPT_ERR_OK;
            }
            
            if ((i.Op <= OP_PUSHSIZE75 && i.Op != size) 
                || (i.Op == OP_PUSHDATA1 && size > 0xffff) 
                || (i.Op == OP_PUSHDATA2 && size > 0xffffffff) 
                || (i.Op == OP_PUSHDATA4 && size > 0xffffffffffffffff)) return SCRIPT_ERR_PUSH_SIZE;
            
            return SCRIPT_ERR_OK;
        }
        
        bool is_minimal_push (const op o, const bytes &data) {
            if (!is_push_data (o)) return data.size () == 0;
            if (data.size () == 1 && (data[0] == 0x81 || (data[0] >= 1 && data[0] <= 16))) return false;
            if (o == OP_PUSHDATA1) return data.size () > 75;
            if (o == OP_PUSHDATA2) return data.size () > 256;
            if (o == OP_PUSHDATA4) return data.size () > 65536;
            return true;
        }
        
        template <typename W>
        struct script_writer {
            W &Writer;
            script_writer &operator << (instruction o) {
                Writer << o;
                return *this;
            }
            
            script_writer &operator << (program p) {
                return p.size () == 0 ? *this : (*this << p.first () << p.rest ());
            }
            
            script_writer (W &w) : Writer {w} {}
        };

        template <typename W>
        script_writer (W &w) -> script_writer<W>;
    
        template <typename R> R read_push (R read, instruction &rest) {
            
            uint32 size;
            R r = read;
            if (rest.Op <= OP_PUSHSIZE75) size = rest.Op;
            if (rest.Op == OP_PUSHDATA1) {
                byte x;
                r >> x;
                size = x;
            }

            if (rest.Op == OP_PUSHDATA2) {
                uint16_little x;
                r >> x;
                size = x;
            }

            if (rest.Op == OP_PUSHDATA4) {
                uint32_little x;
                r >> x;
                size = x;
            }
            
            if ((r.End - r.Begin) < size)
                throw invalid_program {SCRIPT_ERR_PUSH_SIZE};
            
            rest.Data = bytes (size);
            r >> rest.Data;
            return r;
        }
    
        template <typename R>
        struct script_reader {
            R Reader;

            script_reader operator >> (instruction &i) {
                if ((Reader.End - Reader.Begin) == 0)
                    throw invalid_program {SCRIPT_ERR_UNKNOWN_ERROR};
                
                byte next;
                Reader >> next;
                i.Op = static_cast<op> (next);
                if (is_push_data (i.Op)) return read_push (Reader, i);
                return Reader;
            }
            
            bool empty () const {
                return Reader.empty ();
            }
            
            bytes read_all () {
                bytes b (Reader.End - Reader.Begin);
                std::copy (Reader.Begin, Reader.End, b.begin ());
                Reader.Begin = Reader.End;
                return b;
            }
            
            script_reader (it_rdr<const byte *> r) : Reader {r} {}
        };

        template <typename R>
        script_reader (R w) -> script_reader<R>;
    
    }

    ScriptError instruction::verify (flag flags) const {
        auto script_error = verify_instruction (*this);
        if (script_error != SCRIPT_ERR_OK) return script_error;
        
        if (verify_minimal_push (flags) && !is_minimal_push (Op, Data)) return SCRIPT_ERR_MINIMALDATA;
        
        return SCRIPT_ERR_OK;
    }

    bool is_minimal_instruction (const instruction &i) {
        return verify_instruction (i) == SCRIPT_ERR_OK && is_minimal_push (i.Op, i.Data);
    }
    
    instruction instruction::read (slice<const byte> b) {
        instruction i;
        script_reader {it_rdr {b.data (), b.data () + b.size ()}} >> i;
        return i;
    }
    
    instruction instruction::push (slice<const byte> data) {
        int size = data.size ();
        if (size == 0) return instruction {OP_0};
        
        if (size == 1) {
            if (data[0] == 0x81) return instruction {OP_1NEGATE};
            if (data[0] >= 0x01 && data[0] <= 0x10) return instruction {static_cast<op> (data[0] + 0x50)};
        }
        
        if (size <= 0x4b) return instruction {static_cast<op> (size), integer (data)};
        if (size <= 0xff) return instruction {OP_PUSHDATA1, integer (data)};
        if (size <= 0xffff) return instruction {OP_PUSHDATA2, integer (data)};
        return instruction {OP_PUSHDATA4, integer (data)};
    }
    
    integer instruction::push_data () const {
        if (is_push_data (Op) || Op == OP_RETURN) return Data;
        if (!is_push (Op)) return {};
        if (Op == OP_1NEGATE) return {0x81};
        return integer {int64 (Op - 0x50)};
    }
    
    uint32 instruction::serialized_size () const {
        if (Op == OP_RETURN) return Data.size () + 1;
        if (!is_push_data (Op)) return 1;
        uint32 size = Data.size ();
        if (Op <= OP_PUSHSIZE75) return size + 1;
        if (Op == OP_PUSHDATA1) return size + 2;
        if (Op == OP_PUSHDATA2) return size + 3;
        if (Op == OP_PUSHDATA4) return size + 5;
        return 0; // invalid 
    }
    
    std::ostream &write_asm (std::ostream &o, instruction i) {
        if (i.Op == OP_0) return o << "0";
        if (is_push_data (i.Op)) return o << encoding::hex::write (i.Data);
        return o << i.Op;
    }
    
    string ASM (slice<const byte> b) {
        std::stringstream ss;
        program p = decompile (b);

        if (p.size () != 0) {
            auto i = p.begin ();
            write_asm (ss, *i);
            while (++i != p.end ()) write_asm (ss << " ", *i);
        }

        return ss.str ();
    }

    std::ostream &write_op_code (std::ostream &o, op x) {
        if (x == OP_FALSE) return o << "push_empty";
        if (is_push (x)) {
            switch (x) {
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
                default : return o << "push_size_" << int {x};
            }
        }
        
        switch (x) {
            default : return o << x;
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

    std::ostream &operator << (std::ostream &o, const instruction &i) {
        if (!is_push_data (i.Op)) return write_op_code (o, i.Op);
        return write_op_code (o, i.Op) << "{" << encoding::hex::write (i.Data) << "}";
    }
    
    bytes compile (program p) {
        bytes compiled (serialized_size (p));
        it_wtr b {compiled.begin (), compiled.end ()};
        script_writer {b} << p;
        return compiled;
    }
    
    bytes compile (instruction i) {
        bytes compiled (serialized_size (i));
        it_wtr b {compiled.begin (), compiled.end ()};
        script_writer {b} << i;
        return compiled;
    }
    
    program decompile (slice<const byte> b) {
        
        program p {};
        script_reader r {it_rdr {b.data (), b.data () + b.size ()}};
        
        stack<op> Control;
        
        while (!r.empty ()) {
            instruction i {};
            r = r >> i;
            
            if (auto err = i.verify (flag {}); err != SCRIPT_ERR_OK) throw invalid_program {err};
            
            if (i.Op == OP_ENDIF) {
                if (Control.empty ()) throw invalid_program {SCRIPT_ERR_UNBALANCED_CONDITIONAL};
                op prev = Control.first ();
                Control = Control.rest ();

                if (prev == OP_ELSE) {
                    if (Control.empty ()) throw invalid_program {SCRIPT_ERR_UNBALANCED_CONDITIONAL};
                    prev = Control.first ();
                    Control = Control.rest ();
                }

                if (prev != OP_IF && prev != OP_NOTIF) invalid_program {SCRIPT_ERR_UNBALANCED_CONDITIONAL};
            } else if (i.Op == OP_ELSE || i.Op == OP_IF || i.Op == OP_NOTIF) Control = Control >> i.Op;
            
            p = p << i;
        }
        
        return p;
    }
    
    // TODO need to take into account OP_VER etc
    ScriptError valid_program (program p, stack<op> x, flag flags) {
        
        if (data::empty (p)) {
            if (x.empty ()) return SCRIPT_ERR_OK;
            return SCRIPT_ERR_UNBALANCED_CONDITIONAL;
        }
        
        const instruction &i = p.first ();
        
        auto script_error = i.verify (flags);
        if (script_error != SCRIPT_ERR_OK) return script_error;
        
        if ((verify_minimal_push (flags)) && !is_minimal_instruction (i)) return SCRIPT_ERR_MINIMALDATA;
        
        op o = i.Op;
        
        // prior to genesis, OP_RETURN is not allowed to appear in a
        // normal script. It must be in a script consisting only of
        // itself.
        if (o == OP_RETURN) {
            if (!safe_return_data (flags)) return SCRIPT_ERR_OP_RETURN;
            if (data::empty (x) && p.size () == 1) return SCRIPT_ERR_OK;
            if (i.Data.size () != 0) return SCRIPT_ERR_OP_RETURN;
        }
        
        if (o == OP_ENDIF) {
            if (x.empty ()) return SCRIPT_ERR_UNBALANCED_CONDITIONAL;
            op prev = x.first ();
            x = x.rest ();

            if (prev == OP_ELSE) {
                if (x.empty ()) return SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                prev = x.first ();
                x = x.rest ();
            }

            if (prev != OP_IF && prev != OP_NOTIF) return SCRIPT_ERR_UNBALANCED_CONDITIONAL;
        } else if (o == OP_ELSE || o == OP_IF || o == OP_NOTIF) x = x >> o;
        
        return valid_program (p.rest (), x, flags);
    }

    ScriptError pre_verify (program p, flag flags) {
        if (data::empty (p)) return SCRIPT_ERR_OK;

        // first we check for OP_RETURN data.
        if (safe_return_data (flags)) {
            if (p.size () == 2 && p.first ().Op == OP_FALSE && p.first ().valid () && p.rest ().first ().Op == OP_RETURN)
                return SCRIPT_ERR_OK;
        } else if (p.size () == 1 && p.first ().Op == OP_RETURN) return SCRIPT_ERR_OK;

        return valid_program (p, {}, flags);
    }

    // note: pay to script hash only applies to scripts that were created before genesis.
    program full (const program unlock, const program lock, bool support_p2sh) {
        if (!support_p2sh || !is_P2SH (lock) || data::empty (unlock))
            // TODO the code separator should only go here if
            // there is no code separator in the unlocking script.
            return (unlock << OP_CODESEPARATOR) + lock;

        auto reversed = data::reverse (unlock);
        const instruction &push_redeem = data::first (reversed);

        // For P2SH scripts. This is a depricated special case that is supported for backwards compatability.
        return (data::reverse (data::rest (reversed)) << OP_CODESEPARATOR) +
            (decompile (push_redeem.push_data ()) << OP_VERIFY << push_redeem) + lock;
    }

    program find_and_delete (program p, const instruction &sig) {
        program q;
        for (const instruction &i : p) if (i != sig) q <<= i;
        return q;
    }
    
}
