// Copyright (c) 2019-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <sv/policy/policy.h>

namespace Gigamonkey::Bitcoin {

    interpreter::interpreter (maybe<redemption_document> doc, const program unlock, const program lock, const script_config &conf) :
        Machine {doc, conf} {

        program p = full (unlock, lock, conf.support_P2SH ());

        if (conf.verify_sig_push_only () && !is_push (unlock)) Machine.Result = SCRIPT_ERR_SIG_PUSHONLY;
        else if (conf.support_P2SH () && isP2SH (lock)) {
            if (data::empty (unlock)) Machine.Result =  SCRIPT_ERR_INVALID_STACK_OPERATION;
            else if (!is_push (unlock)) Machine.Result = SCRIPT_ERR_SIG_PUSHONLY;
        } else Machine.Result = pre_verify (p, conf.Flags);

        if (Machine.Result.Error != SCRIPT_ERR_OK) Machine.Halt = true;

        Script = compile (p);
        Counter = program_counter {Script};
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
        std::cout << "begin program" << std::endl;
        while (true) {
            std::cout << m << std::endl;
            if (m.Machine.Halt) break;
            wait_for_enter ();
            m.step ();
        }

        std::cout << "Result " << m.Machine.Result << std::endl;
        return m.Machine.Result;
    }

    result machine_step (machine &x, program_counter &p) {
        auto r = x.step (p);
        if (!r.Error && !r.Success) ++p;
        return r;
    }

    result machine_run (machine &x, program_counter &p) {
        while (true) {
            auto r = x.step (p);
            if (r.Error || r.Success) return r;
            else ++p;
        }
    }

    result catch_all_errors (result (*fn) (machine &, program_counter &), machine &x, program_counter &p) {
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
        auto err = catch_all_errors (machine_step, Machine, Counter);
        if (err.Error || err.Success) {
            Machine.Halt = true;
            Machine.Result = err;
        }
    }

    result interpreter::run () {
        Machine.Result = catch_all_errors (machine_run, Machine, Counter);
        Machine.Halt = true;
        return Machine.Result;
    }
}
