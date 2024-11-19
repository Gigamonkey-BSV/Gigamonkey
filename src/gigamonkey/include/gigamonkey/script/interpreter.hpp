// Copyright (c) 2021-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_INTERPRETER
#define GIGAMONKEY_SCRIPT_INTERPRETER

#include <gigamonkey/script/machine.hpp>

namespace Gigamonkey::Bitcoin {

    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct interpreter {

        machine Machine;
        bytes Script;
        program_counter Counter;

        // If the redemption document is not provided, all signature operations will succeed.
        interpreter (const script &unlock, const script &lock, const redemption_document &doc, const script_config & = {});

        interpreter (const script &unlock, const script &lock, const script_config & = {});

        void step ();
        result run ();

        program unread () const;

    };

    std::ostream &operator << (std::ostream &, const interpreter &);

    result step_through (interpreter &m);

    result inline evaluate (const script &unlock, const script &lock, const redemption_document &doc, const script_config &conf) {
        return interpreter (unlock, lock, doc, conf).run ();
    }

    // if the redemption document is not provided, all signature operations will succeed.
    result inline evaluate (const script &unlock, const script &lock, const script_config &conf) {
        return interpreter (unlock, lock, conf).run ();
    }

    program inline interpreter::unread () const {
        return decompile (bytes_view {Counter.Script}.substr (Counter.Counter));
    }

}

#endif

