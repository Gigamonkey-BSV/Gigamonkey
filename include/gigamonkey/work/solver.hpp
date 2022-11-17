// Copyright (c) 2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WORK_SOLVER
#define GIGAMONKEY_WORK_SOLVER

#include <gigamonkey/work/proof.hpp>

namespace Gigamonkey::work {
    
    struct evaluator {
        virtual void solved(const solution &) = 0;
        virtual ~evaluator() {};
    };
    
    struct solver : virtual evaluator {
        virtual void pose(const puzzle &) = 0;
        virtual ~solver() {}
    };
    
    struct selector : virtual evaluator {
        // get latest job. If there is no job yet, block.  
        virtual puzzle select() = 0;
        virtual ~selector() {}
    };
}

#endif
