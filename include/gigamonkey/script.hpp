// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT
#define GIGAMONKEY_SCRIPT

#include <sv/script/script.h>
#include <sv/script/script_error.h>

#include <boost/endian/conversion.hpp>

#include <gigamonkey/signature.hpp>
#include <gigamonkey/address.hpp>

namespace Gigamonkey::Bitcoin { 
    
    using script_error = bsv::ScriptError;
    
    struct evaluated {
        script_error Error;
        bool Return;
        
        evaluated() : Error{bsv::SCRIPT_ERR_OK}, Return{false} {}
        evaluated(script_error err) : Error{err}, Return{false} {}
        
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
    
    using op = bsv::opcodetype;
    
    const op OP_0 = op(0x00);
    
    // push value
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
    
    const op OP_FALSE = OP_0;
    const op OP_PUSHDATA1 = op(0x4c);
    const op OP_PUSHDATA2 = op(0x4d);
    const op OP_PUSHDATA4 = op(0x4e);
    const op OP_1NEGATE = op(0x4f);
    const op OP_RESERVED = op(0x50);
    const op OP_1 = op(0x51);
    const op OP_TRUE = OP_1;
    const op OP_2 = op(0x52);
    const op OP_3 = op(0x53);
    const op OP_4 = op(0x54);
    const op OP_5 = op(0x55);
    const op OP_6 = op(0x56);
    const op OP_7 = op(0x57);
    const op OP_8 = op(0x58);
    const op OP_9 = op(0x59);
    const op OP_10 = op(0x5a);
    const op OP_11 = op(0x5b);
    const op OP_12 = op(0x5c);
    const op OP_13 = op(0x5d);
    const op OP_14 = op(0x5e);
    const op OP_15 = op(0x5f);
    const op OP_16 = op(0x60);

    // control
    const op OP_NOP = op(0x61);
    const op OP_VER = op(0x62);
    const op OP_IF = op(0x63);
    const op OP_NOTIF = op(0x64);
    const op OP_VERIF = op(0x65);
    const op OP_VERNOTIF = op(0x66);
    const op OP_ELSE = op(0x67);
    const op OP_ENDIF = op(0x68);
    const op OP_VERIFY = op(0x69);
    const op OP_RETURN = op(0x6a);

    // stack ops
    const op OP_TOALTSTACK = op(0x6b);
    const op OP_FROMALTSTACK = op(0x6c);
    const op OP_2DROP = op(0x6d);
    const op OP_2DUP = op(0x6e);
    const op OP_3DUP = op(0x6f);
    const op OP_2OVER = op(0x70);
    const op OP_2ROT = op(0x71);
    const op OP_2SWAP = op(0x72);
    const op OP_IFDUP = op(0x73);
    const op OP_DEPTH = op(0x74);
    const op OP_DROP = op(0x75);
    const op OP_DUP = op(0x76);
    const op OP_NIP = op(0x77);
    const op OP_OVER = op(0x78);
    const op OP_PICK = op(0x79);
    const op OP_ROLL = op(0x7a);
    const op OP_ROT = op(0x7b);
    const op OP_SWAP = op(0x7c);
    const op OP_TUCK = op(0x7d);

    // splice ops
    const op OP_CAT = op(0x7e);
    const op OP_SPLIT = op(0x7f);   // after monolith upgrade (May 2018)
    const op OP_NUM2BIN = op(0x80); // after monolith upgrade (May 2018)
    const op OP_BIN2NUM = op(0x81); // after monolith upgrade (May 2018)
    const op OP_SIZE = op(0x82);

    // bit logic
    const op OP_INVERT = op(0x83);
    const op OP_AND = op(0x84);
    const op OP_OR = op(0x85);
    const op OP_XOR = op(0x86);
    const op OP_EQUAL = op(0x87);
    const op OP_EQUALVERIFY = op(0x88);
    const op OP_RESERVED1 = op(0x89);
    const op OP_RESERVED2 = op(0x8a);

    // numeric
    const op OP_1ADD = op(0x8b);
    const op OP_1SUB = op(0x8c);
    const op OP_2MUL = op(0x8d);
    const op OP_2DIV = op(0x8e);
    const op OP_NEGATE = op(0x8f);
    const op OP_ABS = op(0x90);
    const op OP_NOT = op(0x91);
    const op OP_0NOTEQUAL = op(0x92);

    const op OP_ADD = op(0x93);
    const op OP_SUB = op(0x94);
    const op OP_MUL = op(0x95);
    const op OP_DIV = op(0x96);
    const op OP_MOD = op(0x97);
    const op OP_LSHIFT = op(0x98);
    const op OP_RSHIFT = op(0x99);

    const op OP_BOOLAND = op(0x9a);
    const op OP_BOOLOR = op(0x9b);
    const op OP_NUMEQUAL = op(0x9c);
    const op OP_NUMEQUALVERIFY = op(0x9d);
    const op OP_NUMNOTEQUAL = op(0x9e);
    const op OP_LESSTHAN = op(0x9f);
    const op OP_GREATERTHAN = op(0xa0);
    const op OP_LESSTHANOREQUAL = op(0xa1);
    const op OP_GREATERTHANOREQUAL = op(0xa2);
    const op OP_MIN = op(0xa3);
    const op OP_MAX = op(0xa4);

    const op OP_WITHIN = op(0xa5);

    // crypto
    const op OP_RIPEMD160 = op(0xa6);
    const op OP_SHA1 = op(0xa7);
    const op OP_SHA256 = op(0xa8);
    const op OP_HASH160 = op(0xa9);
    const op OP_HASH256 = op(0xaa);
    const op OP_CODESEPARATOR = op(0xab);
    const op OP_CHECKSIG = op(0xac);
    const op OP_CHECKSIGVERIFY = op(0xad);
    const op OP_CHECKMULTISIG = op(0xae);
    const op OP_CHECKMULTISIGVERIFY = op(0xaf);

    // expansion
    const op OP_NOP1 = op(0xb0);
    const op OP_CHECKLOCKTIMEVERIFY = op(0xb1);
    const op OP_NOP2 = OP_CHECKLOCKTIMEVERIFY;
    const op OP_CHECKSEQUENCEVERIFY = op(0xb2);
    const op OP_NOP3 = OP_CHECKSEQUENCEVERIFY;
    const op OP_NOP4 = op(0xb3);
    const op OP_NOP5 = op(0xb4);
    const op OP_NOP6 = op(0xb5);
    const op OP_NOP7 = op(0xb6);
    const op OP_NOP8 = op(0xb7);
    const op OP_NOP9 = op(0xb8);
    const op OP_NOP10 = op(0xb9);

    // template matching params
    const op OP_SMALLINTEGER = op(0xfa);
    const op OP_PUBKEYS = op(0xfb);
    const op OP_PUBKEYHASH = op(0xfd);
    const op OP_PUBKEY = op(0xfe);

    const op OP_INVALIDOPCODE = op(0xff);

    inline bool is_push(op o) {
        return o <= OP_16 && o != OP_RESERVED;
    }
    
    inline bool is_push_data(op o) {
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
            if (!is_push(Op)) return {};
            if (is_push_data(Op)) return Data;
            if (Op == OP_1NEGATE) return {OP_1NEGATE};
            return bytes{static_cast<byte>(Op - 0x50)};
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
        
        bytes_writer write(bytes_writer w) const {
            return is_push_data(Op) ? 
                write_push_data(w, Op, Data.size()) << Data : 
                w << static_cast<byte>(Op);
        }
        
        static instruction op_code(op o) {
            return instruction{o};
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
    
    inline instruction push_data(int32_little x) {
        return instruction{bytes_view{x.data(), 4}};
    }
    
    inline instruction push_data(uint32_little x) {
        return instruction{bytes_view{x.data(), 4}};
    }
    
    inline instruction push_data(uint64_little x) {
        return instruction{bytes_view{x.data(), 8}};
    }
    
    inline instruction push_data(bytes_view x) {
        return instruction{x};
    }
    
    inline instruction push_data(pubkey p) {
        return instruction{write(p.size(), p)};
    }
    
    instruction push_value(int);
    
    instruction push_hex(std::string);
    
    using program = list<instruction>;
    
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
    
    class push;
    struct optional;
    struct alternatives;
    struct repeated;
    
    // for matching and scraping values.
    struct pattern {
        bool match(bytes_view b) const {
            try {
                bytes_view rest = scan(b); 
                return rest.size() == 0;
            } catch (fail) {
                return false;
            }
        }
        
        // A pattern which matches a single op code or instruction. 
        explicit pattern(op);
        explicit pattern(instruction);
        
        // A pattern which matches a given program. 
        explicit pattern(program);
        
        // A pattern which matches an empty string.
        pattern() : Pattern{nullptr} {}
        
        // A pattern denoted as a sequence of other patterns. 
        template <typename X, typename... P>
        pattern(X, P...);
        
        struct fail {}; // Used to end out of a scan operation immediately. 
        
        virtual bytes_view scan(bytes_view p) const {
            if (Pattern == nullptr) return p;
            return Pattern->scan(p);
        }
        
        virtual ~pattern() {}
        
        struct sequence;
    protected:
        struct atom;
        struct string;
        ptr<pattern> Pattern;
        explicit pattern(ptr<pattern> p) : Pattern{p} {};
    };
    
    // A pattern that matches anything. 
    struct any final : pattern {
        any() {}
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    // A pattern that represents a single instruction. 
    struct pattern::atom final : pattern {
        instruction Instruction;
        atom(instruction i) : Instruction{i} {}
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    // A pattern that represents a single instruction. 
    struct pattern::string final : pattern {
        bytes Program;
        string(program p) : Program{compile(p)} {}
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    // A pattern that represents a push instruction 
    // and which has the ability to scrape values of
    // push instructions as a pattern is being read. 
    class push final : public pattern {
        enum type : byte {any, value, data, read};
        type Type;
        Z Value;
        bytes Data;
        bytes& Read;
        
    public:
        // match any push data.
        push() : Type{any}, Value{0}, Data{}, Read{Data} {}
        // match any push data of the given value
        push(int64 v) : Type{value}, Value{v}, Data{}, Read{Data} {}
        // match a push of the given data. 
        push(bytes_view b) : Type{data}, Value{0}, Data{b}, Read{Data} {}
        // match any push data and save the result.
        push(bytes& r) : Type{read}, Value{0}, Data{}, Read{r} {}
        
        bool match(const instruction& i) const;
        
        virtual bytes_view scan(bytes_view p) const final override;
        
        operator instruction() const;
    };
    
    class push_size final : public pattern {
        bool Reader;
        size_t Size;
        bytes Data;
        bytes& Read;
        
    public:
        // match any push data of the given value
        push_size(size_t s) : Reader{false}, Size{s}, Data{}, Read{Data} {}
        // match any push data and save the result.
        push_size(size_t s, bytes& r) : Reader(true), Size(s), Data(), Read(r) {}
        
        bool match(const instruction& i) const;
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    enum repeated_directive : byte {
        exactly, or_more, or_less
    };
    
    struct repeated final : public pattern {
        int64 First;
        int Second;
        repeated_directive Directive;
        
        repeated(op, uint32 = 1, repeated_directive = or_more);
        repeated(instruction, uint32 = 1, repeated_directive = or_more);
        repeated(push, uint32 = 1, repeated_directive = or_more);
        repeated(optional, uint32 = 1, repeated_directive = or_more);
        repeated(pattern, uint32 = 1, repeated_directive = or_more);
        repeated(repeated, uint32, repeated_directive = or_more);
        repeated(alternatives, uint32 = 1, repeated_directive = or_more);
        
        repeated(op, uint32, uint32);
        repeated(instruction, uint32, uint32);
        repeated(push, uint32, uint32);
        repeated(optional, uint32, uint32);
        repeated(pattern, uint32, uint32);
        repeated(repeated, uint32, uint32);
        repeated(alternatives, uint32, uint32);
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    struct optional final : pattern {
        
        optional(op o) : pattern{o} {}
        optional(instruction i) : pattern{i} {}
        optional(push p) : pattern{ptr<pattern>(std::make_shared<push>(p))} {}
        optional(repeated p) : pattern{ptr<pattern>(std::make_shared<repeated>(p))} {}
        optional(push_size p) : pattern{ptr<pattern>(std::make_shared<push_size>(p))} {}
        optional(pattern p);
        optional(alternatives);
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
        
    inline pattern::pattern(op o) : pattern{instruction{o}} {}
    
    inline pattern::pattern(instruction i) : Pattern{ptr<pattern>(std::make_shared<atom>(i))} {}
    
    inline pattern::pattern(program p) : Pattern{ptr<pattern>(std::make_shared<string>(p))} {}
    
    struct pattern::sequence : public pattern {
        list<ptr<pattern>> Patterns;
        
        template <typename... P>
        sequence(P... p) : Patterns(make(p...)) {}
        
        virtual bytes_view scan(bytes_view p) const override;
        
    private:
        
        static ptr<pattern> construct(op p);
        static ptr<pattern> construct(instruction p);
        static ptr<pattern> construct(program p);
        static ptr<pattern> construct(push p);
        static ptr<pattern> construct(push_size p);
        static ptr<pattern> construct(alternatives p);
        static ptr<pattern> construct(optional p);
        static ptr<pattern> construct(pattern p);
        
        template <typename X> 
        static list<ptr<pattern>> make(X x);
        
        template <typename X, typename... P>
        static list<ptr<pattern>> make(X x, P... p);
    };
    
    struct alternatives final : pattern::sequence {
    public:
        template <typename... P>
        alternatives(P... p) : sequence{p...} {}
        
        virtual bytes_view scan(bytes_view) const final override;
    };
    
    // A pattern that matches a pubkey and grabs the value of that pubkey.
    inline pattern pubkey_pattern(bytes& pubkey) {
        return pattern{alternatives{push_size{33, pubkey}, push_size{65, pubkey}}};
    }
    
    struct op_return_data {
        static Bitcoin::pattern pattern() {
            static Bitcoin::pattern Pattern{optional{OP_FALSE}, OP_RETURN, repeated{push{}, 0}};
            return Pattern;
        }
        
        static Gigamonkey::script script(list<bytes> push);
        
        list<bytes> Push;
        bool Safe; // whether op_false is pushed before op_return
        bool Valid;
        
        bytes script() const {
            return script(Push);
        };
        
        op_return_data(bytes_view);
        op_return_data(list<bytes> p) : Push{p}, Safe{true}, Valid{true} {}
    };
    
    struct pay_to_pubkey {
        static Bitcoin::pattern pattern(bytes& pubkey) {
            return {pubkey_pattern(pubkey), OP_CHECKSIG};
        }
        
        static bytes script(pubkey p) {
            return compile(program{push_data(p), OP_CHECKSIG});
        }
        
        pubkey Pubkey;
        
        bool valid() const {
            return Pubkey.valid();
        }
        
        bytes script() const {
            return script(Pubkey);
        }
        
        pay_to_pubkey(bytes_view script) : Pubkey{} {
            pubkey p;
            if (!pattern(p.Value).match(script)) return;
            Pubkey = p;
        }
        
        static bytes redeem(const signature& s) {
            return compile(push_data(s));
        }
    };
    
    struct pay_to_address {
        static Bitcoin::pattern pattern(bytes& address) {
            return {OP_DUP, OP_HASH160, push_size{20, address}, OP_EQUALVERIFY, OP_CHECKSIG};
        }
        
        static bytes script(const digest160& a) {
            return compile(program{OP_DUP, OP_HASH160, bytes_view(a), OP_EQUALVERIFY, OP_CHECKSIG});
        }
        
        digest160 Address;
        
        bool valid() const {
            return Address.valid();
        }
        
        bytes script() const {
            return script(Address);
        }
        
        pay_to_address(bytes_view script) : Address{} {
            bytes addr{20};
            pattern(addr).match(script);
            std::copy(addr.begin(), addr.end(), Address.Value.begin());
        }
        
        static bytes redeem(const signature& s, const pubkey& p) {
            return compile(program{} << push_data(s) << push_data(p));
        }
    };

    std::ostream& operator<<(std::ostream& o, const instruction i);

    inline bytes_writer operator<<(bytes_writer w, const instruction i) {
        return i.write(w);
    }
    
    template <typename X, typename... P>
    pattern::pattern(X x, P... p) : Pattern(std::make_shared<sequence>(x, p...)) {}
    
    inline repeated::repeated(op x, uint32 first, repeated_directive d) 
        : pattern{x}, First{first}, Second{-1}, Directive{d} {}
    inline repeated::repeated(instruction x, uint32 first, repeated_directive d) 
        : pattern{x}, First{first}, Second{-1}, Directive{d} {}
    inline repeated::repeated(push x, uint32 first, repeated_directive d) 
        : pattern{x}, First{first}, Second{-1}, Directive{d} {}
    inline repeated::repeated(optional x, uint32 first, repeated_directive d) 
        : pattern{x}, First{first}, Second{-1}, Directive{d} {}
    inline repeated::repeated(pattern x, uint32 first, repeated_directive d) 
        : pattern{x}, First{first}, Second{-1}, Directive{d} {}
    inline repeated::repeated(repeated x, uint32 first, repeated_directive d) 
        : pattern{x}, First{first}, Second{-1}, Directive{d} {}
    inline repeated::repeated(alternatives x, uint32 first, repeated_directive d) 
        : pattern{x}, First{first}, Second{-1}, Directive{d} {}
    
    inline repeated::repeated(op x, uint32 first, uint32 second) 
        : pattern{x}, First{first}, Second{static_cast<int>(second)}, Directive{exactly} {}
    inline repeated::repeated(instruction x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{static_cast<int>(second)}, Directive{exactly} {}
    inline repeated::repeated(push x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{static_cast<int>(second)}, Directive{exactly} {}
    inline repeated::repeated(optional x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{static_cast<int>(second)}, Directive{exactly} {}
    inline repeated::repeated(pattern x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{static_cast<int>(second)}, Directive{exactly} {}
    inline repeated::repeated(repeated x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{static_cast<int>(second)}, Directive{exactly} {}
    inline repeated::repeated(alternatives x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{static_cast<int>(second)}, Directive{exactly} {}
    
    inline ptr<pattern> pattern::sequence::construct(op p) {
        return std::make_shared<atom>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(instruction p) {
        return std::make_shared<atom>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(program p) {
        return std::make_shared<string>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(push p) {
        return std::make_shared<push>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(push_size p) {
        return std::make_shared<push_size>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(alternatives p) {
        return std::make_shared<alternatives>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(optional p) {
        return std::make_shared<optional>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(pattern p) {
        return std::make_shared<pattern>(p);
    }
    
    template <typename X> 
    inline list<ptr<pattern>> pattern::sequence::make(X x) {
        return list<ptr<pattern>>{}.prepend(construct(x));
    }
    
    template <typename X, typename... P>
    inline list<ptr<pattern>> pattern::sequence::make(X x, P... p) {
        return make(p...).prepend(construct(x));
    }
    
}

#endif 

