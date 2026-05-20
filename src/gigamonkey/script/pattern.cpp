// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include <gigamonkey/script/counter.hpp>

namespace Gigamonkey {
    
    // We already know that o has size at least 1 
    // when we call this function. 
    uint32 next_instruction_size (byte_slice o) {
        using namespace Bitcoin;

        op O = op (o[0]);

        if (O == OP_INVALIDOPCODE) return 0;
        if (!is_push_data (op (O))) return 1;
        if (O <= OP_PUSHSIZE75) return (O + 1);

        if (O == OP_PUSHDATA1) {
            if (o.size () < 2) return 0;
            return o[1] + 2;
        }

        if (O == OP_PUSHDATA2) {
            if (o.size () < 3) return 0;
            return boost::endian::load_little_u16 (&o[1]) + 3;
        }

        // otherwise it's OP_PUSHDATA4
        if (o.size () < 5) return 0;
        return boost::endian::load_little_u32 (&o[1]) + 5;
    }
    
    byte_slice pattern::atom::scan (byte_slice p) const {
        using namespace Bitcoin;

        if (p.size () == 0) throw fail {};
        if (p[0] != Instruction.Op) throw fail {};

        uint32 size = next_instruction_size (p);
        if (p.size () < size || Instruction != instruction::read (p.range (0, size))) throw fail {};
        return p.drop (size);
    }
    
    byte_slice pattern::string::scan (byte_slice p) const {
        if (p.size () < Program.size ()) throw fail {};
        for (int i = 0; i < Program.size (); i++) if (p[i] != Program[i]) throw fail {};
        return p.drop (Program.size ());
    }
    
    byte_slice any::scan (byte_slice p) const {
        if (p.size () == 0) throw fail {};
        uint32 size = next_instruction_size(p);
        if (p.size () < size) throw fail {};
        return p.drop (size);
    }
    
    byte_slice push::scan (byte_slice p) const {
        if (p.size () == 0) throw fail {};
        uint32 size = next_instruction_size (p);
        if (size == 0) throw fail {};

        if (!match (Bitcoin::instruction::read (p.range (0, size))))
            throw fail {};

        return p.drop (size);
    }
    
    byte_slice push_size::scan (byte_slice p) const {
        if (p.size () == 0) throw fail {};
        uint32 size = next_instruction_size (p);

        if (!match (Bitcoin::instruction::read (p.range (0, size))))
            throw fail {};

        return p.drop (size);
    }
    
    byte_slice op_return_data::scan (byte_slice p) const {
        using namespace Bitcoin;
        if (p.size () == 0) throw fail {};
        if (p[0] != OP_RETURN) throw fail {};
        return pattern::scan (p.drop (1));
    }
    
    bool push::match (const Bitcoin::instruction &i) const {
        switch (Type) {
            case any :
                return Bitcoin::is_push (i.Op);
            case value :
                return Bitcoin::is_push (i.Op) && Value == Bitcoin::integer (i.push_data ());
            case data : 
                return Bitcoin::is_push (i.Op) && Data == static_cast<bytes> (i.push_data ());
            case read : 
                if (!Bitcoin::is_push (i.Op)) return false;
                Read = i.push_data ();
                return true;
            default: 
                return false;
        }
    }
    
    bool push_size::match (const Bitcoin::instruction& i) const {
        bytes Data = i.push_data ();
        if (Data.size () != Size) return false;
        if (Reader) Read = Data;
        return true;
    }
    
    byte_slice pattern::sequence::scan (byte_slice p) const {
        list<ptr<pattern>> patt = Patterns; 
        while (!empty (patt)) {
            p = first (patt)->scan (p);
            patt = rest (patt);
        }
        return p;
    }
        
    byte_slice optional::scan (byte_slice p) const {
        try {
            return pattern::Pattern->scan (p);
        } catch (fail) {
            return p;
        }
    }
    
    byte_slice repeated::scan (byte_slice p) const {
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
    
    byte_slice alternatives::scan (byte_slice b) const {
        list<ptr<pattern>> patt = Patterns;

        while (!empty (patt)) {
            try {
                return first (patt)->scan (b);
            } catch (fail) {
                patt = rest (patt);
            }
        }

        throw fail {};
    };

}
