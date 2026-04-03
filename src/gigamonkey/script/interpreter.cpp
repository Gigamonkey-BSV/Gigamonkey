// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <sv/policy/policy.h>

namespace Gigamonkey::Bitcoin {

    std::expected<program, ScriptError> read_program (const program scripts, const script_config &conf) {
        if (size (scripts) == 0) return scripts;

        segment unlock = first (scripts);
        if (conf.verify_unlock_push_only () && !is_push (unlock)) return std::unexpected (SCRIPT_ERR_SIG_PUSHONLY);

        if (size (scripts) == 1) return scripts;

        program p;
        if (size (scripts) == 2) {
            segment lock = scripts[1];

            if (conf.verify_P2SH () && is_P2SH (lock)) {
                if (empty (unlock)) return std::unexpected (SCRIPT_ERR_INVALID_STACK_OPERATION);
                else if (!is_push (unlock)) return std::unexpected (SCRIPT_ERR_SIG_PUSHONLY);
            }

            // the full program is the two scripts merged
            // together, unless this is P2SH, which is
            // a special case no longer supported.
            p = full (unlock, lock, conf.verify_P2SH ());
        } else p = scripts;

        ScriptError v = pre_verify (p, conf.Flags);

        if (v) return std::unexpected (v);
        return p;

    }

    void setup_interpreter (interpreter &I, const list<script> scripts, const script_config &conf) {

        // this try block should not be necessary. We should
        // remove all error throwing that could occurr within
        // this block.
        try {
            auto e = read_program (lift ([&conf] (const auto &script) {
                segment x = decompile (script);
                for (const instruction &i : x) if (auto err = i.verify (conf); err != SCRIPT_ERR_OK) throw invalid_program {err};
                return x;
            }, scripts), conf);

            if (e) I.Program = compile (*e);
            else I.Machine.Result.Error = e.error ();

        } catch (const invalid_program &x) {
            I.Machine.Result.Error = x.Error;
        }

        if (I.Machine.Result.Error != SCRIPT_ERR_OK) I.Machine.Halt = true;

        I.Counter = program_counter {I.Program.Script};
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
            << ",\n\tHalt: " << (i.Machine.Halt ? "true" : "false")
            << ", Result: " << i.Machine.Result << ", Flags: " << i.Machine.Config.Flags
            << ",\n\t" << *i.Machine.Stack << ", Exec: " << make_list (i.Machine.Exec)
            << ", Else: " << make_list (i.Machine.Else) << "}";
    }

    maybe<result> machine_step (machine &x, program_counter &p) {
        auto r = x.step (p);
        if (!bool (r)) ++p;
        return r;
    }

    result machine_run (machine &x, program_counter &p) {
        while (true) {
            auto r = x.step (p);
            if (bool (r)) return *r;
            else ++p;
        }
    }

    template <typename R>
    R catch_all_errors (R (*fn) (machine &, program_counter &), machine &x, program_counter &p) {
        try {
            return fn (x, p);
        } catch (script_exception &err) {
            return err.Error;
        } /*catch (scriptnum_overflow_error &err) {
            return SCRIPT_ERR_SCRIPTNUM_OVERFLOW;
        } catch (scriptnum_minencode_error &err) {
            return SCRIPT_ERR_SCRIPTNUM_MINENCODE;
        } catch (const bsv::big_int_error &) {
            return SCRIPT_ERR_BIG_INT;
        } */catch (std::out_of_range &err) {
            return SCRIPT_ERR_INVALID_STACK_OPERATION;
        } catch (...) {
            return SCRIPT_ERR_UNKNOWN_ERROR;
        }
    }

    void interpreter::step () {
        if (Machine.Halt) return;
        auto r = catch_all_errors<maybe<result>> (machine_step, Machine, Counter);
        if (bool (r)) {
            Machine.Halt = true;
            Machine.Result = *r;
        }
    }

    result interpreter::run () {
        if (!Machine.Halt) {
            Machine.Result = catch_all_errors<result> (machine_run, Machine, Counter);
            Machine.Halt = true;
        }

        return Machine.Result;
    }
}
