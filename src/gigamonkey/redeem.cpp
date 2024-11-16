#include <gigamonkey/redeem.hpp>
#include <gigamonkey/script/pattern/pay_to_pubkey.hpp>
#include <gigamonkey/script/pattern/pay_to_address.hpp>

namespace Gigamonkey {
    Bitcoin::script redeem_p2pkh_and_p2pk
        (const Bitcoin::output &out, const Bitcoin::sighash::document &doc, list<sigop> sigs, const bytes &script_code) {

        // the only types of scripts we know how to redeem fit this pattern.
        if (size (sigs) != 1) return {};

        const Bitcoin::secret &x = first (sigs).Key;
        if (!x.valid ()) return {};

        // the pubkey
        const Bitcoin::pubkey p = x.to_public ();

        const bytes &output_script = out.Script;

        // is this pay-to-address?
        pay_to_address p2pkh {output_script};

        if (p2pkh.valid ()) {
            if (p2pkh.Address != p.address_hash ()) return {};

            return pay_to_address::redeem (x.sign (doc, first (sigs).Directive), p);
        }

        // is this pay-to-pubkey?
        pay_to_pubkey p2pk {output_script};

        if (!p2pk.valid ()) return {};
        if (p2pk.Pubkey != p) return {};

        return pay_to_pubkey::redeem (x.sign (doc, first (sigs).Directive));
    }

    extended::transaction redeemable_transaction::redeem (const Gigamonkey::redeem &r) const {
        Bitcoin::incomplete::transaction incomplete (*this);

        uint32 index = 0;
        list<Bitcoin::sighash::document> docs;
        for (const input &in : this->Inputs)
            docs <<= Bitcoin::sighash::document {
                incomplete, index++, in.Prevout.Value,
                Bitcoin::remove_after_last_code_separator (in.script_so_far ())};

        auto inputs = this->Inputs;
        auto sigs = Signatures;
        list<bytes> input_scripts {};

        while (size (docs) > 0) {
            auto &in = first (inputs);
            input_scripts <<= r (in.Prevout, first (docs), first (sigs), in.InputScriptSoFar);
            inputs = rest (inputs);
            docs = rest (docs);
            sigs = rest (sigs);
        }

        return this->complete (input_scripts);
    }
}
