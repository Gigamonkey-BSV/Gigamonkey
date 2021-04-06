// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/machine.hpp>
#include "script/interpreter.h"
#include "taskcancellation.h"
#include "streams.h"
#include "config.h"
#include "policy/policy.h"

// not in use but required by config.h dependency
bool fRequireStandard = true;

namespace Gigamonkey::Bitcoin {
    
    class DummySignatureChecker : public BaseSignatureChecker {
    public:
        DummySignatureChecker() {}

        bool CheckSig(const std::vector<uint8_t> &scriptSig,
                    const std::vector<uint8_t> &vchPubKey,
                    const CScript &scriptCode, bool enabledSighashForkid) const override {
            return true;
        }
    };
    
    evaluated evaluate_script(const script& unlock, const script& lock, const BaseSignatureChecker& checker) {
        evaluated Response;
        std::optional<bool> response = VerifyScript(
            GlobalConfig::GetConfig(), // Config. 
            false, // true for consensus rules, false for policy rules.  
            task::CCancellationSource::Make()->GetToken(), 
            CScript(unlock.begin(), unlock.end()), 
            CScript(lock.begin(), lock.end()), 
            StandardScriptVerifyFlags(true, true), // Flags. I don't know what these should be. 
            checker, 
            &Response.Error);
        if (response.has_value()) {
            Response.Return = *response;
        } 
        return Response;
    }
    
    evaluated evaluate_script(const script& unlock, const script& lock) {
        return evaluate_script(unlock, lock, DummySignatureChecker{});
    }
    
    evaluated evaluate_script(const script& unlock, const script& lock, const bytes_view tx, const index i) {
        CDataStream stream{(const char*)(tx.data()), 
            (const char*)(tx.data() + tx.size()), SER_NETWORK, PROTOCOL_VERSION};
        CTransaction ctx{deserialize, stream}; 
        
        return evaluate_script(lock, unlock, TransactionSignatureChecker(&ctx, i, Amount(int64(output::value(transaction::output(tx, i))))));
    }
    
    std::ostream& operator<<(std::ostream& o, const machine& i) {
        return o << "machine{\n\tProgram: " << i.Program << ",\n\tState: {Halt: " << (i.State.Halt ? "true" : "false") 
            << ", Success: " << (i.State.Success ? "true" : "false") << ", Error: " 
            << i.State.Error << ", Flags: " << i.State.Flags << ",\n\t\tStack: " << i.State.Stack << ",\n\t\tAltStack: " 
            << i.State.AltStack << ", Exec: " << i.State.Exec << ", Else: " << i.State.Else << "}}";
    }
    
    machine::machine(program p, uint32 flags, uint32 index, satoshi value, transaction tx) : 
        Program{p}, State{flags}, Transaction{tx}, Index{index}, SignatureChecker{nullptr}, Tx{nullptr} {
        
        if (!tx.valid()) {
            SignatureChecker = new DummySignatureChecker{};
            return; 
        }
        
        bytes tx_bytes = tx.write();
        
        CDataStream stream{(const char*)(tx_bytes.data()), 
        (const char*)(tx_bytes.data() + tx_bytes.size()), SER_NETWORK, PROTOCOL_VERSION};
        Tx = new CTransaction{deserialize, stream};
        SignatureChecker = new TransactionSignatureChecker(Tx, index, Amount(int64(value)));
        
    }
    
    machine::state machine::state::step(const BaseSignatureChecker& x, instruction i) const {
                
        if (Error || Halt) return *this;
        
        const GlobalConfig& config = GlobalConfig::GetConfig();
        bool consensus = false;
        
        bytes compiled = compile(i);
        CScript z(compiled.begin(), compiled.end());
        
        LimitedStack stack(config.GetMaxStackMemoryUsage(Flags & SCRIPT_UTXO_AFTER_GENESIS, consensus));
        LimitedStack altstack {stack.makeChildStack()};
        
        // TODO copy from stacks onto limited stack
        for (const bytes& b : Stack.reverse()) stack.push_back(b);
        for (const bytes& b : AltStack.reverse()) altstack.push_back(b);
        
        std::vector<bool> v_exec(Exec.size());
        std::vector<bool> v_else(Else.size());
        
        auto f_exec = Exec;
        for (int i = 0; i < v_exec.size(); i++) {
            v_exec[i] = f_exec.first();
            f_exec = f_exec.rest();
        }
        
        auto f_else = Else;
        for (int i = 0; i < v_else.size(); i++) {
            v_else[i] = f_else.first();
            f_else = f_else.rest();
        }
        
        state m{Flags};
        m.Counter = Counter;
        
        std::optional<bool> result = EvalScript(
            config, consensus, 
            task::CCancellationSource::Make()->GetToken(), 
            stack, z, Flags, x, 
            altstack, m.Counter,
            v_exec, v_else, &m.Error);
        
        // copy stacks back 
        while(!stack.empty()) {
            auto elem = stack.back().GetElement();
            m.Stack = m.Stack << bytes_view{elem.data(), elem.size()};
            stack.pop_back();
        }
        
        while(!altstack.empty()) {
            auto elem = altstack.back().GetElement();
            m.AltStack = m.AltStack << bytes_view{elem.data(), elem.size()};
            altstack.pop_back();
        }
        
        for (int i = 0; i < v_exec.size(); i++) m.Exec = m.Exec << v_exec[i];
        for (int i = 0; i < v_else.size(); i++) m.Else = m.Else << v_else[i];
        
        if ((i.Op == OP_RETURN || 
            i.Op == OP_VERIFY || 
            i.Op == OP_EQUALVERIFY || 
            i.Op == OP_NUMEQUALVERIFY || 
            i.Op == OP_CHECKSIGVERIFY || 
            i.Op == OP_CHECKMULTISIGVERIFY) && (!result.has_value() || !result.value())) {
            m.Halt = true;
            m.Success = false;
        }
        
        return m;
    }

}
