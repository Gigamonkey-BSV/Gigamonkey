// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PATTERN
#define GIGAMONKEY_SCRIPT_PATTERN

#include <gigamonkey/script/instruction.hpp>
#include <gigamonkey/address.hpp>
#include <data/data.hpp>

namespace Gigamonkey { 
    
    // script patterns that can be used to recognize transaction formats and scrape data from them. 
    
    class push;
    class push_size;
    struct optional;
    struct alternatives;
    struct repeated;
    
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
        explicit pattern(Bitcoin::op);
        explicit pattern(Bitcoin::instruction);
        
        // A pattern which matches a given program. 
        explicit pattern(Bitcoin::program);
        
        // A pattern which matches an empty string.
        pattern() : Pattern{nullptr} {}
        
        // A pattern denoted as a sequence of other patterns. 
        template <typename X, typename... P>
        pattern(X, P...);
        
        virtual bytes_view scan(bytes_view p) const {
            if (Pattern == nullptr) return p;
            return Pattern->scan(p);
        }
        
        virtual ~pattern() {}
        
        struct sequence;
        
    protected:
        
        struct fail {}; // Used to end out of a scan operation immediately. 
        
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
        Bitcoin::instruction Instruction;
        atom(Bitcoin::instruction i) : Instruction{i} {}
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    // A pattern that represents any string that is part of a program. 
    struct pattern::string final : pattern {
        bytes Program;
        string(Bitcoin::program p) : Program{compile(p)} {}
        string(const bytes& p) : Program{p} {}
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    // A pattern that represents a push instruction 
    // and which has the ability to scrape values of
    // push instructions as a pattern is being read. 
    class push final : public pattern {
        enum type : byte {any, value, data, read};
        type Type;
        Bitcoin::Z Value;
        bytes Data;
        bytes& Read;
        
    public:
        // match any push data.
        push() : Type{any}, Value{0}, Data{}, Read{Data} {}
        // match any push data of the given value
        push(const Bitcoin::Z& v) : Type{value}, Value{v}, Data{}, Read{Data} {}
        // match a push of the given data. 
        push(bytes_view b) : Type{data}, Value{0}, Data{b}, Read{Data} {}
        // match any push data and save the result.
        push(bytes& r) : Type{read}, Value{0}, Data{}, Read{r} {}
        
        bool match(const Bitcoin::instruction& i) const;
        
        virtual bytes_view scan(bytes_view p) const final override;
        
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
        
        bool match(const Bitcoin::instruction& i) const;
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    enum repeated_directive : byte {
        exactly, or_more, or_less
    };
    
    struct repeated final : public pattern {
        int64 First;
        int Second;
        repeated_directive Directive;
        
        repeated(Bitcoin::op, uint32 = 1, repeated_directive = or_more);
        repeated(Bitcoin::instruction, uint32 = 1, repeated_directive = or_more);
        repeated(push, uint32 = 1, repeated_directive = or_more);
        repeated(optional, uint32 = 1, repeated_directive = or_more);
        repeated(pattern, uint32 = 1, repeated_directive = or_more);
        repeated(repeated, uint32, repeated_directive = or_more);
        repeated(alternatives, uint32 = 1, repeated_directive = or_more);
        
        repeated(Bitcoin::op, uint32, uint32);
        repeated(Bitcoin::instruction, uint32, uint32);
        repeated(push, uint32, uint32);
        repeated(optional, uint32, uint32);
        repeated(pattern, uint32, uint32);
        repeated(repeated, uint32, uint32);
        repeated(alternatives, uint32, uint32);
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    struct optional final : pattern {
        
        optional(Bitcoin::op o) : pattern{o} {}
        optional(Bitcoin::instruction i) : pattern{i} {}
        optional(push p) : pattern{ptr<pattern>(std::make_shared<push>(p))} {}
        optional(repeated p) : pattern{ptr<pattern>(std::make_shared<repeated>(p))} {}
        optional(push_size p) : pattern{ptr<pattern>(std::make_shared<push_size>(p))} {}
        optional(pattern p);
        optional(alternatives);
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    inline pattern::pattern(Bitcoin::op o) : pattern{Bitcoin::instruction{o}} {}
    
    inline pattern::pattern(Bitcoin::instruction i) : Pattern{ptr<pattern>(std::make_shared<atom>(i))} {}
    
    inline pattern::pattern(Bitcoin::program p) : Pattern{ptr<pattern>(std::make_shared<string>(p))} {}
    
    struct pattern::sequence : public pattern {
        list<ptr<pattern>> Patterns;
        
        template <typename... P>
        sequence(P... p) : Patterns(make(p...)) {}
        
        virtual bytes_view scan(bytes_view p) const override;
        
    private:
        
        static ptr<pattern> construct(Bitcoin::op p);
        static ptr<pattern> construct(Bitcoin::instruction p);
        static ptr<pattern> construct(Bitcoin::program p);
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
    
    // OP_RETURN followed by arbitrary data. 
    struct op_return_data final : public pattern {
        // match OP_RETURN followed by any data. 
        op_return_data() : pattern{} {}
        
        op_return_data(const bytes& d) : pattern{string{d}} {}
        
        template <typename... P>
        op_return_data(P... p) : pattern{p...} {}
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    // A pattern that matches a pubkey and grabs the value of that pubkey.
    pattern inline pubkey_pattern(bytes& pubkey) {
        return pattern{alternatives{push_size{33, pubkey}, push_size{65, pubkey}}};
    }
    
    // create and read an OP_RETURN script. 
    struct op_return {
        enum type {
            unsafe, 
            safe, 
            either
        };
        
        static Gigamonkey::pattern pattern(type t = either) {
            static Gigamonkey::pattern Either{optional{OP_FALSE}, op_return_data{}};
            static Gigamonkey::pattern Unsafe{op_return_data{}};
            static Gigamonkey::pattern Safe{OP_FALSE, op_return_data{}};
            switch (t) {
                case unsafe: return Unsafe;
                case safe: return Safe;
                case either: return Either;
            }
        }
        
        static Gigamonkey::script script(const bytes_view data, bool safe_script = true) {
            using namespace Bitcoin;
            return compile(safe_script ? 
                program{OP_FALSE, instruction::op_return_data(data)} : 
                program{instruction::op_return_data(data)});
        }
    
        static bool match(const bytes_view p) {
            return (p.size() > 1 && p[0] == 0x6a) || (p.size() > 2 && p[0] == 0x00 && p[1] == 0x6a);
        }
        
        bytes Data;
        bool Safe; // whether op_false is pushed before op_return
        
        bytes script() const {
            return script(Data, Safe);
        };
        
        Bitcoin::output output() const {
            return Bitcoin::output{0, script(Data, Safe)};
        }
        
        op_return(bytes_view b, bool safe_script = true) : Data{b}, Safe{safe} {}
    };
    
    struct pay_to_pubkey {
        static Gigamonkey::pattern pattern(bytes& pubkey) {
            return {pubkey_pattern(pubkey), OP_CHECKSIG};
        }
        
        static bytes script(Bitcoin::pubkey p) {
            using namespace Bitcoin;
            return compile(program{push_data(p), OP_CHECKSIG});
        }
        
        Bitcoin::pubkey Pubkey;
        
        bool valid() const {
            return Pubkey.valid();
        }
        
        bytes script() const {
            return script(Pubkey);
        }
        
        pay_to_pubkey(bytes_view script) : Pubkey{} {
            using namespace Bitcoin;
            pubkey p;
            if (!pattern(p).match(script)) return;
            Pubkey = p;
        }
        
        static bytes redeem(const Bitcoin::signature& s) {
            using namespace Bitcoin;
            return compile(push_data(s));
        }
    };
    
    struct pay_to_address {
        static Gigamonkey::pattern pattern(bytes& address) {
            using namespace Bitcoin;
            return {OP_DUP, OP_HASH160, push_size{20, address}, OP_EQUALVERIFY, OP_CHECKSIG};
        }
        
        static bytes script(const digest160& a) {
            using namespace Bitcoin;
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
            using namespace Bitcoin;
            bytes addr{20};
            if (!pattern(addr).match(script)) return;
            std::copy(addr.begin(), addr.end(), Address.begin());
        }
        
        static bytes redeem(const Bitcoin::signature& s, const Bitcoin::pubkey& p) {
            using namespace Bitcoin;
            return compile(program{} << push_data(s) << push_data(p));
        }
    };
    
    struct pay_to_hash {
        static Gigamonkey::pattern pattern(bytes& hash) {
            return {OP_HASH160, push_size{20, hash}, OP_EQUALVERIFY};
        }
        
        static bytes script(const digest160& a) {
            using namespace Bitcoin;
            return compile(program{OP_HASH160, bytes_view(a), OP_EQUALVERIFY});
        }
        
        digest160 Hash;
        
        bool valid() const {
            return Hash.valid();
        }
        
        bytes script() const {
            return script(Hash);
        }
        
        pay_to_hash(bytes_view script) : Hash{} {
            bytes hash{20};
            if (!pattern(hash).match(script)) return;
            std::copy(hash.begin(), hash.end(), Hash.begin());
        }
        
        static bytes redeem(const bytes_view s) {
            using namespace Bitcoin;
            return compile(program{} << push_data(s));
        }
    };
    
    // an obsolete pattern that was introduced by Gavin. 
    struct pay_to_script_hash {
        static Gigamonkey::pattern pattern(bytes& hash) {
            return {OP_HASH160, push_size{20, hash}, OP_EQUAL};
        }
        
        static bytes script(const digest160& a) {
            using namespace Bitcoin;
            return compile(program{OP_HASH160, bytes_view(a), OP_EQUAL});
        }
        
        digest160 Hash;
        
        bool valid() const {
            return Hash.valid();
        }
        
        bytes script() const {
            return script(Hash);
        }
        
        pay_to_script_hash(bytes_view script) : Hash{} {
            using namespace Bitcoin;
            bytes hash{20};
            if (!pattern(hash).match(script)) return;
            std::copy(hash.begin(), hash.end(), Hash.begin());
        }
        
        static bytes redeem(const bytes_view s) {
            using namespace Bitcoin;
            return compile(program{} << push_data(s));
        }
    };
}

namespace Gigamonkey { 
    
    template <typename X, typename... P>
    pattern::pattern(X x, P... p) : Pattern(std::make_shared<sequence>(x, p...)) {}
    
    inline repeated::repeated(Bitcoin::op x, uint32 first, repeated_directive d) 
        : pattern{x}, First{first}, Second{-1}, Directive{d} {}
    inline repeated::repeated(Bitcoin::instruction x, uint32 first, repeated_directive d) 
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
    
    inline repeated::repeated(Bitcoin::op x, uint32 first, uint32 second) 
        : pattern{x}, First{first}, Second{static_cast<int>(second)}, Directive{exactly} {}
    inline repeated::repeated(Bitcoin::instruction x, uint32 first, uint32 second)
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
    
    inline ptr<pattern> pattern::sequence::construct(Bitcoin::op p) {
        return std::make_shared<atom>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(Bitcoin::instruction p) {
        return std::make_shared<atom>(p);
    }
    
    inline ptr<pattern> pattern::sequence::construct(Bitcoin::program p) {
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
