// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include <gigamonkey/script/counter.hpp>
#include <data/math/number/bytes/N.hpp>

namespace Gigamonkey::Bitcoin::interpreter {
    
    // We already know that o has size at least 1 
    // when we call this function. 
    uint32 next_instruction_size(bytes_view o) {
        opcodetype op = opcodetype(o[0]);
        if (op == OP_INVALIDOPCODE) return 0;
        if (!is_push_data(opcodetype(op))) return 1;
        if (op <= OP_PUSHSIZE75) return (op + 1);
        if (op == OP_PUSHDATA1) {
            if (o.size() < 2) return 0;
            return o[1] + 2;
        }
        if (op == OP_PUSHDATA2) {
            if (o.size() < 3) return 0;
            return boost::endian::load_little_u16(&o[1]) + 3;
        }
        // otherwise it's OP_PUSHDATA4
        if (o.size() < 5) return 0;
        return boost::endian::load_little_u32(&o[1]) + 5;
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
    
    bytes_view push::scan(bytes_view p) const {
        if (p.size() == 0) throw fail{};
        uint32 size = next_instruction_size(p);
        if (size == 0) throw fail{};
        if (!match(instruction::read(p.substr(0, size)))) throw fail{};
        return p.substr(size);
    }
    
    bytes_view push_size::scan(bytes_view p) const {
        if (p.size() == 0) throw fail{};
        uint32 size = next_instruction_size(p);
        if (!match(instruction::read(p.substr(0, size)))) throw fail{};
        return p.substr(size);
    }
    
    bytes_view op_return_data::scan(bytes_view p) const {
        if (p.size() == 0) throw fail{};
        if (p[0] != OP_RETURN) throw fail{};
        return pattern::scan(p.substr(1));
    }
    
}
