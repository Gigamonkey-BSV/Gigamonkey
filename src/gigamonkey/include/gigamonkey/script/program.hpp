// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018 The Bitcoin SV developers
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_PROGRAM
#define GIGAMONKEY_SCRIPT_PROGRAM

#include <gigamonkey/script/instruction.hpp>
#include <data/lift.hpp>
#include <data/flatten.hpp>

namespace Gigamonkey::Bitcoin {

    using segment = list<instruction>;

    // decompile throws if a push operation would include bytes past the end of the script.
    segment decompile (slice<const byte>);

    bool is_push (segment);

    bytes compile (segment);

    // used in the original sighash algorithm to remove instances of the same
    // signature that might have been used previously in the script.
    segment find_and_delete (segment script_code, const instruction &sig);

    using program = list<segment>;

    // check flags that can be checked without running the program.
    ScriptError pre_verify (program, const script_config &flags);

    // make the full program from the two scripts.
    program full (const segment unlock, const segment lock, bool support_p2sh);

    // pay to script hash only applies to scripts that were created before genesis.
    bool is_P2SH (const segment p);

    bool inline valid (program p) {
        return pre_verify (p, genesis_profile ()) == SCRIPT_ERR_OK;
    };

    struct execution_image {
        bytes Script;
        cross<size_t> Jump;
    };

    execution_image compile (program p);
    program decompile (const execution_image &p);

    // thrown if you try to decompile an invalid program.
    struct invalid_program : exception {
        ScriptError Error;
        invalid_program (ScriptError err): Error {err} {
            *this << "program is invalid: " << err;
        }
    };

    size_t serialized_size (segment p);

    bool inline is_P2SH (slice<const byte> script) {
        return script.size () == 23 && script[0] == OP_HASH160 &&
        script[1] == 0x14 && script[22] == OP_EQUAL;
    }

    bool inline is_P2SH (const segment p) {
        return is_P2SH (compile (p));
    }

    size_t inline serialized_size (segment p) {
        if (empty (p)) return 0;
        return serialized_size (first (p)) + serialized_size (rest (p));
    }

    bool inline is_push (segment p) {
        if (empty (p)) return true;
        return is_push (first (p).Op) && is_push (rest (p));
    }

    bool inline is_minimal_script (slice<const byte> b) {
        for (const instruction &i : decompile (b)) if (!is_minimal_instruction (i)) return false;
        return true;
    }

    execution_image inline compile (program p) {
        return execution_image {
            compile (data::flatten (p)),
            cross<size_t> {data::accumulate (data::lift ([](const segment z){
                size_t size {0};
                for (const instruction &in : z) size += serialized_size (in);
                return size;
            }, p))}};
    }
}

#endif
