// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>

namespace gigamonkey::bitcoin::script {
    pattern::sequence::~sequence() {
        queue<pattern*> patt = Patterns;
        while (!data::empty(patt)) {
            delete patt.first();
            patt = patt.rest();
        }
    }
        
    bytes_view pattern::atom::scan(bytes_view p) const {
        if (p.size() == 0) throw fail{};
        if (p[0] != Instruction.Op) throw fail{};
        uint32 size = next_instruction_size(p);
        if (p.size() < size || p.substr(1, size) != Instruction.Data) throw fail{};
        return p.substr(size);
    }
        
    bytes_view pattern::sequence::scan(bytes_view p) const {
        queue<pattern*> patt = Patterns;
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
        pattern* patt = pattern::Pattern;
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
        queue<pattern*> patt = Patterns;
        while (!data::empty(patt)) {
            try {
                return patt.first()->scan(b);
            } catch (fail) {
                patt = patt.rest();
            }
        }
        throw fail{};
    };
}
