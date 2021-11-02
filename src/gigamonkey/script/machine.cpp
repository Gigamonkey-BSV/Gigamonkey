// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/machine.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 
    
    std::ostream& operator<<(std::ostream& o, const machine& i) {
        return o << "machine{\n\tProgram: " << i.Program << ",\n\tState: {Halt: " << (i.State.Halt ? "true" : "false") 
            << ", Success: " << (i.State.Success ? "true" : "false") << ", Error: " 
            << i.State.Error << ", Flags: " << i.State.Flags << ",\n\t\tStack: " << i.State.Stack << ",\n\t\tAltStack: " 
            << i.State.AltStack << ", Exec: " << i.State.Exec << ", Else: " << i.State.Else << "}}";
    }
    
    void step_through(machine& m) {
        std::cout << "begin program" << std::endl;
        while(true) {
            std::cout << m << std::endl;
            if (m.State.Halt) break;
            wait_for_enter();
            m.step();
        }
        
        if (m.State.Success) std::cout << "Program executed successfully" << std::endl;
        else if (m.State.Error) std::cout << "Program failed with error" << m.State.Error << std::endl;
        else std::cout << "Program failed" << std::endl;
    }
    
}
