// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/pay/ARC.hpp>

namespace Gigamonkey::ARC {
    bool response::valid (const net::HTTP::response &r) {
        if (r.Status == net::HTTP::status::unauthorized && r.Body == "") return true;
        const auto *v = r.Headers.contains (net::HTTP::header::field::content_type);
        return bool (v) && *v == "appliction/json" && bool (body (r));
    }

    maybe<JSON> response::body (const net::HTTP::response &r) {
        try {
            JSON j = JSON::parse (r.Body);
            if (success::valid (j)) return j;
        } catch (JSON::exception) {}
        return {};
    }

    bool health_response::valid (const net::HTTP::response &r) {
        if (!response::valid (r)) return false;
        auto b = response::body (r);
        return bool (b) ? health::valid (*b) : true;
    }

    bool policy_response::valid (const net::HTTP::response &r) {
        if (!response::valid (r)) return false;
        auto b = response::body (r);
        if (!bool (b)) return true;
        if (!success::valid (*b)) return false;
        return b->contains ("policy") && policy::valid ((*b)["policy"]);
    }

    bool status::valid (const JSON &j) {
        if (!j.contains ("blockHash") && !j.contains ("blockHeight") && !j.contains ("txid") &&
            !j.contains ("merklePath") && !j.contains ("txStatus") && !j.contains ("extraInfo") &&
            !j.contains ("competingTxs")) return false;

        // we could look at these fields in a little more detail but we don't.
        return true;
    }

    bool status_response::valid (const net::HTTP::response &r) {
        if (!response::valid (r)) return false;
        auto b = response::body (r);
        if (!bool (b)) return true;
        if (response::error (r)) return error::valid (*b) && r.Status == net::HTTP::status::not_found || r.Status == net::HTTP::status::conflict;
        if (!success::valid (*b)) return false;
        return status::valid (*b);
    }

    submit_request::submit_request (const extended::transaction &tx, submit x) :
        net::HTTP::REST::request {net::HTTP::method::post, "/v1/tx", {}, {}, x.headers ()} {
        switch (x.ContentType) {
            case (octet): {
                this->Body = string (bytes (tx));
            } return;
            case (json): {
                JSON::object_t j;
                j["rawTx"] = encoding::hex::write (bytes (tx));
                this->Body = JSON (j).dump ();
            } return;
            case (text): {
                this->Body = encoding::hex::write (bytes (tx));
            } return;
            default: throw exception {} << "Invalid ARC content type";
        }
    }

    submit_txs_request::submit_txs_request (list<extended::transaction> txs, submit x) :
        net::HTTP::REST::request {net::HTTP::method::post, "/v1/txs", {}, {}, x.headers ()} {
        switch (x.ContentType) {
            case (octet): {
                bytes b (fold ([] (size_t so_far, const extended::transaction &G) {
                    return so_far + G.serialized_size ();
                }, size_t {0}, txs));
                bytes_writer bb {b.begin (), b.end ()};
                for (const extended::transaction &tx : txs) bb << tx;
                this->Body = string (b);
            } return;
            case (json): {
                JSON::array_t a (txs.size ());
                int index = 0;
                for (const extended::transaction &tx : txs) {
                    JSON::object_t j;
                    j["rawTx"] = encoding::hex::write (bytes (tx));
                    a[index++] = j;
                }
                this->Body = JSON (a).dump ();
            } return;
            case (text): {
                this->Body = string_join (for_each ([] (const extended::transaction &tx) -> string {
                    return encoding::hex::write (bytes (tx));
                }, txs), "\n");
            } return;
            default: throw exception {} << "Invalid ARC content type";
        }
    }

    namespace {
        ASCII write (content_type_option);
        ASCII write (status_value);
        ASCII write (const net::URL &);
        ASCII write (bool);
        ASCII write (int);
    }

    map<net::HTTP::header, ASCII> submit::headers () const {
        map<net::HTTP::header, ASCII> m {};
        m = m.insert (net::HTTP::header::field::content_type, write (ContentType));
        if (bool (CallbackURL)) m = m.insert ("X-CallbackURL", write (*CallbackURL));
        if (bool (FullStatusUpdates)) m = m.insert ("X-FullStatusUpdates", write (*FullStatusUpdates));
        if (bool (MaxTimeout)) m = m.insert ("X-MaxTimeout", write (*MaxTimeout));
        if (bool (SkipFeeValidation)) m = m.insert ("X-SkipFeeValidation", write (*SkipFeeValidation));
        if (bool (SkipScriptValidation)) m = m.insert ("X-SkipScriptValidation", write (*SkipScriptValidation));
        if (bool (SkipTxValidation)) m = m.insert ("X-SkipTxValidation", write (*SkipTxValidation));
        if (bool (CumulativeFeeValidation)) m = m.insert ("X-CumulativeFeeValidation", write (*CumulativeFeeValidation));
        if (bool (CallbackToken)) m = m.insert ("X-CallbackToken", *CallbackToken);
        if (bool (WaitFor)) m = m.insert ("X-WaitFor", write (*WaitFor));
        return m;
    }

}
