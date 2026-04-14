// Copyright (c) 2021-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_INTERPRETER
#define GIGAMONKEY_SCRIPT_INTERPRETER

#include <gigamonkey/script/machine.hpp>
#include <gigamonkey/script/program.hpp>

namespace Gigamonkey::Bitcoin {

    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct interpreter {

        ::Error Error {::Error::OK};

        program_counter Program;
        machine Machine;

        // If the redemption document is not provided, all signature operations will succeed.
        interpreter (const list<script> scripts, const redemption_document &doc, const script_config & = {});

        interpreter (const list<script> scripts, const script_config & = {});

        void step ();
        ::Error run ();

        segment unread () const;

    };

    std::ostream &operator << (std::ostream &, const interpreter &);

    // evaluate with real signatures.
    Error inline evaluate (const script &unlock, const script &lock, const redemption_document &doc, const script_config &conf) {
        return interpreter (list<script> {unlock, lock}, doc, conf).run ();
    }

    // if the redemption document is not provided, all signature operations will succeed automatically.
    Error inline evaluate (const script &unlock, const script &lock, const script_config &conf) {
        return interpreter (list<script> {unlock, lock}, conf).run ();
    }

    // evaluate with real signatures.
    Error inline evaluate (const list<script> scripts, const redemption_document &doc, const script_config &conf) {
        return interpreter (scripts, doc, conf).run ();
    }

    // if the redemption document is not provided, all signature operations will succeed automatically.
    Error inline evaluate (const list<script> scripts, const script_config &conf) {
        return interpreter (scripts, conf).run ();
    }

    segment inline interpreter::unread () const {
        return decompile (byte_slice {Program.Script}.drop (Program.Index));
    }

}

#endif

