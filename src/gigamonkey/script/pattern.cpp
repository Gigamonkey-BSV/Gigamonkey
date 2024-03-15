// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include <gigamonkey/script/counter.hpp>
#include <data/math/number/bytes/Z.hpp>

namespace Gigamonkey {
    
    // We already know that o has size at least 1 
    // when we call this function. 
    uint32 next_instruction_size (bytes_view o) {
        opcodetype op = opcodetype (o[0]);
        if (op == OP_INVALIDOPCODE) return 0;
        if (!Bitcoin::is_push_data (opcodetype (op))) return 1;
        if (op <= Bitcoin::OP_PUSHSIZE75) return (op + 1);

        if (op == OP_PUSHDATA1) {
            if (o.size () < 2) return 0;
            return o[1] + 2;
        }

        if (op == OP_PUSHDATA2) {
            if (o.size () < 3) return 0;
            return boost::endian::load_little_u16 (&o[1]) + 3;
        }

        // otherwise it's OP_PUSHDATA4
        if (o.size () < 5) return 0;
        return boost::endian::load_little_u32 (&o[1]) + 5;
    }
    
    bytes_view pattern::atom::scan (bytes_view p) const {
        if (p.size () == 0) throw fail {};
        if (p[0] != Instruction.Op) throw fail {};
        uint32 size = next_instruction_size (p);
        if (p.size () < size || Instruction != Bitcoin::instruction::read (p.substr (0, size))) throw fail {};
        return p.substr (size);
    }
    
    bytes_view pattern::string::scan (bytes_view p) const {
        if (p.size () < Program.size ()) throw fail {};
        for (int i = 0; i < Program.size (); i++) if (p[i] != Program[i]) throw fail {};
        return p.substr (Program.size ());
    }
    
    bytes_view any::scan (bytes_view p) const {
        if (p.size () == 0) throw fail {};
        uint32 size = next_instruction_size(p);
        if (p.size () < size) throw fail {};
        return p.substr (size);
    }
    
    bytes_view push::scan(bytes_view p) const {
        if (p.size () == 0) throw fail {};
        uint32 size = next_instruction_size (p);
        if (size == 0) throw fail {};

        if (!match (Bitcoin::instruction::read (p.substr (0, size))))
            throw fail {};

        return p.substr (size);
    }
    
    bytes_view push_size::scan(bytes_view p) const {
        if (p.size () == 0) throw fail {};
        uint32 size = next_instruction_size (p);

        if (!match (Bitcoin::instruction::read (p.substr (0, size))))
            throw fail {};

        return p.substr (size);
    }
    
    bytes_view op_return_data::scan(bytes_view p) const {
        if (p.size() == 0) throw fail {};
        if (p[0] != OP_RETURN) throw fail {};
        return pattern::scan (p.substr (1));
    }
    
    bool push::match (const Bitcoin::instruction& i) const {
        switch (Type) {
            case any : 
                return Bitcoin::is_push (i.Op);
            case value : 
                return Bitcoin::is_push (i.Op) && Value == Z (i.data ());
            case data : 
                return Bitcoin::is_push (i.Op) && Data == static_cast<bytes> (i.data ());
            case read : 
                if (!Bitcoin::is_push (i.Op)) return false;
                Read = i.data ();
                return true;
            default: 
                return false;
        }
    }
    
    bool push_size::match (const Bitcoin::instruction& i) const {
        bytes Data = i.data ();
        if (Data.size () != Size) return false;
        if (Reader) Read = Data;
        return true;
    }
    
    bytes_view pattern::sequence::scan (bytes_view p) const {
        list<ptr<pattern>> patt = Patterns; 
        while (!data::empty (patt)) {
            p = patt.first ()->scan (p);
            patt = patt.rest ();
        }
        return p;
    }
        
    bytes_view optional::scan (bytes_view p) const {
        try {
            return pattern::Pattern->scan (p);
        } catch (fail) {
            return p;
        }
    }
    
    bytes_view repeated::scan (bytes_view p) const {
        ptr<pattern> patt = pattern::Pattern;
        uint32 min = Second == -1 && Directive == or_less ? 0 : First;
        int64 max = Second != -1 ? Second : Directive == or_more ? -1 : First;
        uint32 matches = 0;

        while (true) {
            try {
                p = patt->scan (p);
                matches++;
                if (matches == max) return p;
            } catch (fail) {
                if (matches < min) throw fail {};
                return p;
            }
        }
    }
    
    bytes_view alternatives::scan (bytes_view b) const {
        list<ptr<pattern>> patt = Patterns;

        while (!data::empty (patt)) {
            try {
                return patt.first ()->scan (b);
            } catch (fail) {
                patt = patt.rest ();
            }
        }

        throw fail {};
    };

}
