// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PATTERN
#define GIGAMONKEY_SCRIPT_PATTERN

#include <gigamonkey/script.hpp>

namespace gigamonkey::bitcoin::script {
    
    struct pattern {
        
        bool match(bytes_view b) const {
            try {
                bytes_view rest = scan(b); 
                return rest.size() == 0;
            } catch (fail) {
                return false;
            }
        }
        
        pattern(op);
        pattern(instruction);
        
        template <typename... P>
        pattern(P...);
        
        virtual ~pattern() {
            delete Pattern;
        }
        
        struct fail {};
        
        virtual bytes_view scan(bytes_view p) const {
            return Pattern->scan(p);
        }
        
        struct sequence;
    protected:
        struct atom;
        pattern* Pattern;
        pattern() {}
    };
    
    struct push final : pattern {
        push(); 
        push(size_t size); 
        push(const bytes&);
        push(bytes&);
        
        bool match(instruction) const;
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    struct optional;
    struct alternatives;
    
    enum repeated_directive : byte {
        exactly, or_more, or_less
    };
    
    struct repeated final : pattern {
        int64 First;
        int64 Second;
        repeated_directive Directive;
        
        repeated(op, uint32 = 1, repeated_directive = or_more);
        repeated(instruction, uint32 = 1, repeated_directive = or_more);
        repeated(push, uint32 = 1, repeated_directive = or_more);
        repeated(optional, uint32 = 1, repeated_directive = or_more);
        repeated(pattern, uint32 = 1, repeated_directive = or_more);
        repeated(repeated, uint32 = 1, repeated_directive = or_more);
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
        optional(op);
        optional(instruction);
        optional(push);
        optional(repeated);
        optional(pattern);
        optional(alternatives);
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
    
    struct pattern::atom final : pattern {
        instruction Instruction;
        atom(instruction i) : Instruction{i} {}
        
        virtual bytes_view scan(bytes_view p) const final override;
    };
        
    inline pattern::pattern(op o) : pattern{instruction{o}} {}
    
    inline pattern::pattern(instruction i) : Pattern{new atom{i}} {}
    
    struct pattern::sequence : pattern {
        queue<pattern*> Patterns;
        virtual ~sequence();
        
        template <typename... P>
        sequence(P... p) : Patterns{make(p...)} {}
        
        virtual bytes_view scan(bytes_view p) const override;
        
    private:
        
        static pattern* construct(op);
        
        static pattern* construct(instruction);
        
        static pattern* construct(push);
        
        static pattern* construct(pattern);
        
        static pattern* construct(optional);
        
        template <typename X> 
        queue<pattern*> make(X x) {
            return queue<pattern*>{}.prepend(construct(x));
        }
        
        template <typename X, typename... P>
        static queue<pattern*> make(X x, P... p) {
            return make(p...).prepend(construct(x));
        }
    };
    
    struct alternatives final : pattern::sequence {        
        template <typename... P>
        alternatives(P... p) : sequence{p...} {}
        
        virtual bytes_view scan(bytes_view) const final override;
    };
    
    template <typename... P>
    pattern::pattern(P... p) : Pattern{new sequence{p...}} {}
    
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
        : pattern{x}, First{first}, Second{second}, Directive{exactly} {}
    inline repeated::repeated(instruction x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{second}, Directive{exactly} {}
    inline repeated::repeated(push x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{second}, Directive{exactly} {}
    inline repeated::repeated(optional x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{second}, Directive{exactly} {}
    inline repeated::repeated(pattern x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{second}, Directive{exactly} {}
    inline repeated::repeated(repeated x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{second}, Directive{exactly} {}
    inline repeated::repeated(alternatives x, uint32 first, uint32 second)
        : pattern{x}, First{first}, Second{second}, Directive{exactly} {}
    
}

#endif

