// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include <data/math/number/bytes/N.hpp>

namespace Gigamonkey::Bitcoin::interpreter {
    
    bool provably_prunable_recurse(program p) {
        if (p.size() < 2) return false;
        if (p.size() == 2) return p.first().Op == OP_FALSE && p.rest().first() == OP_RETURN;
        return provably_prunable_recurse(p);
    }
    
    bool provably_prunable(program p) {
        if (!p.valid()) return false;
        return provably_prunable_recurse(p);
    }
    
    bool push::match(const instruction& i) const {
        switch (Type) {
            case any : 
                return is_push(i.Op);
            case value : 
                return is_push(i.Op) && Value == Z{bytes_view(i.data())};
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
    
    bool push_size::match(const instruction& i) const {
        bytes Data = i.data();
        if (Data.size() != Size) return false;
        if (Reader) Read = Data;
        return true;
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

}
