// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <sv/policy/policy.h>

namespace Gigamonkey::Bitcoin {

    std::expected<program, Error> read_program (const program scripts, const script_config &conf) {
        if (size (scripts) == 0) return scripts;

        segment unlock = first (scripts);
        if (conf.verify_unlock_push_only () && !is_push (unlock)) return std::unexpected (Error::SIG_PUSHONLY);

        if (size (scripts) == 1) return scripts;

        program p;
        if (size (scripts) == 2) {
            segment lock = scripts[1];

            if (conf.verify_P2SH () && is_P2SH (lock)) {
                if (empty (unlock)) return std::unexpected (Error::INVALID_STACK_OPERATION);
                else if (!is_push (unlock)) return std::unexpected (Error::SIG_PUSHONLY);
            }

            // the full program is the two scripts merged
            // together, unless this is P2SH, which is
            // a special case no longer supported.
            p = full (unlock, lock, conf.verify_P2SH ());
        } else p = scripts;

        ::Error v = pre_verify (p, conf.Flags);

        if (bool (v)) return std::unexpected (v);
        return p;

    }

    void setup_interpreter (interpreter &I, const list<script> scripts, const script_config &conf) {

        // this try block should not be necessary. We should
        // remove all error throwing that could occurr within
        // this block.
        try {
            auto e = read_program (lift ([&conf] (const auto &script) {
                segment x = decompile (script);
                for (const instruction &i : x) if (auto err = i.verify (conf); err != Error::OK)
                    throw invalid_program {err};

                return x;
            }, scripts), conf);

            if (e) I.Program = compile (*e);
            else I.Error = e.error ();

        } catch (const invalid_program &x) {
            I.Error = x.Error;
        }
    }

    interpreter::interpreter (const list<script> scripts, const redemption_document &doc, const script_config &conf) :
        Machine {{doc}, conf} {
        setup_interpreter (*this, scripts, conf);
    }

    interpreter::interpreter (const list<script> scripts, const script_config &conf) :
        Machine {{}, conf} {
        setup_interpreter (*this, scripts, conf);
    }

    list<bool> make_list (const std::vector<bool> &v) {
        list<bool> l;
        for (const bool &b : v) l << b;
        return l;
    }

    std::ostream &operator << (std::ostream &o, const interpreter &i) {
        return o << "interpreter {\n\tProgram: " << i.unread ()
            << ", Error: " << i.Error << ", Flags: " << i.Machine.Config.Flags
            << ",\n\t" << *i.Machine.Stack << ", Exec: " << make_list (i.Machine.Exec)
            << ", Else: " << make_list (i.Machine.Else) << "}";
    }

    Error machine_step (machine &x, program_counter &p) {
        auto r = x.step (p);
        if (bool (r)) return r;

        if (p.Next[0] == OP_RETURN) {
            // if the instruction was an OP_RETURN, we have to jump
            // instead of increment.
            p.jump ();

            // if this is not the end of the program, we
            // have to check the top of the stack for true.
            // if not, we err. Otherwise we pop the top
            // and erase the if/else stacks.
            if (p.valid ()) {
                if (x.Stack->size () < 1)
                    return Error::INVALID_STACK_OPERATION;

                if (Bitcoin::is_zero (x.Stack->top ()))
                    return Error::OP_RETURN;

                x.Exec = {};
                x.Else = {};

                x.Stack->pop_back ();
            }
        }

        // increment op counter.
        else ++p;

        return Error::OK;
    }

    Error machine_run (machine &x, program_counter &p) {
        while (true) {
            auto r = machine_step (x, p);

            // if an error was generated, return it.
            if (bool (r)) return r;

            // if there are no more instructions, return the result.
            if (!p.valid ()) {
                if (x.Config.verify_clean_stack () && (x.Stack->size () != 1))
                    return Error::CLEANSTACK;

                return x.top ();
            }
        }
    }

    Error catch_all_errors (Error (*fn) (machine &, program_counter &), machine &x, program_counter &p) {
        try {
            return fn (x, p);
        } catch (const invalid_program &err) {
            return err.Error;
        } catch (const std::out_of_range &err) {
            return Error::INVALID_STACK_OPERATION;
        } catch (...) {
            return Error::UNKNOWN_ERROR;
        }
    }

    void interpreter::step () {
        if (bool (Error)) return;
        Error = catch_all_errors (machine_step, Machine, Program);
    }

    Error interpreter::run () {
        if (bool (Error)) return Error;
        return catch_all_errors (machine_run, Machine, Program);
    }
}
