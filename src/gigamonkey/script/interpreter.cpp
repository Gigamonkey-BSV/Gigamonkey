// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <sv/policy/policy.h>

namespace Gigamonkey::Bitcoin {

    void setup_interpreter (interpreter &I, const script &ux, const script &lx, const script_config &conf) {
        program p;

        try {
            program unlock = decompile (ux);
            program lock = decompile (lx);

            p = full (unlock, lock, conf.support_P2SH ());

            if (conf.verify_sig_push_only () && !is_push (unlock)) I.Machine.Result = SCRIPT_ERR_SIG_PUSHONLY;
            else if (conf.support_P2SH () && is_P2SH (lock)) {
                if (data::empty (unlock)) I.Machine.Result =  SCRIPT_ERR_INVALID_STACK_OPERATION;
                else if (!is_push (unlock)) I.Machine.Result = SCRIPT_ERR_SIG_PUSHONLY;
            } else I.Machine.Result = pre_verify (p, conf.Flags);

        } catch (const invalid_program &x) {
            I.Machine.Result.Error = x.Error;
        }

        if (I.Machine.Result.Error != SCRIPT_ERR_OK) I.Machine.Halt = true;

        I.Script = compile (p);
        I.Counter = program_counter {I.Script};
    }

    interpreter::interpreter (const script &unlock, const script &lock, const redemption_document &doc, const script_config &conf) :
        Machine {{doc}, conf} {
        setup_interpreter (*this, unlock, lock, conf);
    }

    interpreter::interpreter (const script &unlock, const script &lock, const script_config &conf) :
        Machine {{}, conf} {
        setup_interpreter (*this, unlock, lock, conf);
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

    result step_through (interpreter &m) {
        while (true) {
            std::cout << m << std::endl;
            if (m.Machine.Halt) break;
            wait_for_enter ();
            m.step ();
        }

        std::cout << "Result " << m.Machine.Result << std::endl;
        return m.Machine.Result;
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
