// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/pay/ARC.hpp>

namespace Gigamonkey::ARC {

    HTTP::request::make inline policy_request (const std::string &base_path) {
        return HTTP::request::make {}.method (HTTP::method::get).path (base_path + "/v1/policy");
    }

    HTTP::request::make inline health_request (const std::string &base_path) {
        return HTTP::request::make {}.method (HTTP::method::get).path (base_path + "/v1/health");
    }

    HTTP::request::make inline status_request (const std::string &base_path, const Bitcoin::TXID &txid) {
        return HTTP::request::make {}.method (HTTP::method::get).path (base_path + std::string {"/v1/tx/"} + Gigamonkey::write_reverse_hex (txid));
    }

    awaitable<policy_response> client::policy () {
        co_return co_await this->operator () (this->REST (policy_request (REST.Path)));
    }

    awaitable<health_response> client::health () {
        co_return co_await this->operator () (this->REST (health_request (REST.Path)));
    }

    awaitable<status_response> client::status (const Bitcoin::TXID &txid) {
        co_return co_await this->operator () (this->REST (status_request (REST.Path, txid)));
    }

    bool response::valid (const HTTP::response &r) {
        if (r.Status == HTTP::status::unauthorized && r.Body == bytes {}) return true;
        auto v = r.content_type ();
        return bool (v) && *v == "application/json" || bool (body (r));
    }

    error response::error (const HTTP::response &r) {
        if (!error (r) || r.Status == HTTP::status::unauthorized) return JSON (nullptr);
        return *body (r);
    }

    maybe<JSON> response::body (const HTTP::response &r) {
        try {
            return JSON::parse (r.Body);
        } catch (JSON::exception) {}
        return {};
    }

    bool health_response::valid (const HTTP::response &r) {
        if (!response::valid (r)) return false;
        auto b = response::body (r);
        return bool (b) ? health::valid (*b) : true;
    }

    bool policy::valid (const JSON &j) {
        return j.is_object () && j.contains ("maxscriptsizepolicy") && j["maxscriptsizepolicy"].is_number () &&
            j.contains ("maxtxsigopscountspolicy") && j["maxtxsigopscountspolicy"].is_number () &&
            j.contains ("maxtxsizepolicy") && j["maxtxsizepolicy"].is_number () &&
            j.contains ("miningFee") && j["miningFee"].is_object ();
    }

    bool policy_response::valid (const HTTP::response &r) {
        if (!response::valid (r)) return false;
        auto b = response::body (r);
        if (!bool (b)) return true;
        if (!success::valid (*b)) return false;
        return b->contains ("policy") && policy::valid ((*b)["policy"]);
    }

    bool status::valid (const JSON &j) {
        // we could look at these fields in a little more detail but we don't.
        return j.contains ("blockHash") && j["blockHash"].is_string () &&
            j.contains ("blockHeight") && j["blockHeight"].is_number_unsigned () &&
            j.contains ("txid") && j["txid"].is_string () &&
            j.contains ("merklePath") && j["merklePath"].is_string () &&
            j.contains ("txStatus") && j["txStatus"].is_string ();
    }

    bool status_response::valid (const HTTP::response &r) {
        if (!response::valid (r)) return false;
        auto b = response::body (r);
        if (!bool (b)) return true;
        if (response::is_error (r)) return error::valid (*b) && r.Status == HTTP::status::not_found || r.Status == HTTP::status::conflict;
        if (!success::valid (*b)) return false;
        return status::valid (*b);
    }

    awaitable<submit_response> client::submit (const submit_request &x) {
        HTTP::request::make r = HTTP::request::make {}.method (HTTP::method::post).path (REST.Path + "/v1/tx").add_headers (x.Submit.headers ());
        switch (x.Submit.ContentType) {
            case (octet): {
                r = r.body (bytes (x.Transaction));
            } break;
            case (json): {
                JSON::object_t j;
                j["rawTx"] = encoding::hex::write (bytes (x.Transaction));
                r = r.body (JSON (j));
            } break;
            case (text): {
                r = r.body (encoding::hex::write (bytes (x.Transaction)));
            } break;
            default: throw data::exception {} << "Invalid ARC content type";
        }
        co_return co_await this->operator () (this->REST (r));
    }

    awaitable<submit_txs_response> client::submit_txs (const submit_txs_request &x) {
        HTTP::request::make r = HTTP::request::make {}.method (HTTP::method::post).path (REST.Path + "/v1/txs").add_headers (x.Submit.headers ());

        switch (x.Submit.ContentType) {
            case octet: {
                bytes b (fold ([] (size_t so_far, const extended::transaction &G) {
                    return so_far + G.serialized_size ();
                }, size_t {0}, x.Transactions));

                it_wtr bb {b.begin (), b.end ()};
                for (const extended::transaction &tx : x.Transactions) bb << tx;
                r = r.body (string (b));
            } break;
            case json: {
                JSON::array_t a (x.Transactions.size ());
                int index = 0;
                for (const extended::transaction &tx : x.Transactions) {
                    JSON::object_t j;
                    j["rawTx"] = encoding::hex::write (bytes (tx));
                    a[index++] = j;
                }
                r = r.body (JSON (a).dump ());
            } break;
            case text: {
                r = r.body (string_join (for_each ([] (const extended::transaction &tx) -> string {
                    return encoding::hex::write (bytes (tx));
                }, x.Transactions), "\n"));
            } break;
            default: throw data::exception {} << "Invalid ARC content type";
        }

        co_return co_await this->operator () (this->REST (r));
    }

    namespace {
        ASCII write (content_type_option x) {
            switch (x) {
                case text: return "text/plain";
                case json: return "application/json";
                case octet: return "application/octet-stream";
                default: throw data::exception {} << "unknown ARC content type";
            }
        }

        ASCII write (status_value x) {
            switch (x) {
                case RECEIVED : return "RECEIVED";
                case STORED : return "STORED";
                case ANNOUNCED_TO_NETWORK : return "ANNOUNCED_TO_NETWORK";
                case REQUESTED_BY_NETWORK : return "REQUESTED_BY_NETWORK";
                case SENT_TO_NETWORK : return "SENT_TO_NETWORK";
                case ACCEPTED_BY_NETWORK : return "ACCEPTED_BY_NETWORK";
                case SEEN_ON_NETWORK : return "SEEN_ON_NETWORK";
                default: throw data::exception {} << "unknown ARC status";
            }
        }

        ASCII write (bool b) {
            return b ? "true" : "false";
        }

        ASCII write (int i) {
            return std::to_string (i);
        }
    }

    dispatch<HTTP::header, ASCII> submit::headers () const {
        dispatch<HTTP::header, ASCII> m {};
        m = m.append ({HTTP::header::content_type, write (ContentType)});
        if (bool (CallbackURL)) m = m.append ({"X-CallbackURL", *CallbackURL});
        if (bool (FullStatusUpdates)) m = m.append ({"X-FullStatusUpdates", write (*FullStatusUpdates)});
        if (bool (MaxTimeout)) m = m.append ({"X-MaxTimeout", write (*MaxTimeout)});
        if (bool (SkipFeeValidation)) m = m.append ({"X-SkipFeeValidation", write (*SkipFeeValidation)});
        if (bool (SkipScriptValidation)) m = m.append ({"X-SkipScriptValidation", write (*SkipScriptValidation)});
        if (bool (SkipTxValidation)) m = m.append ({"X-SkipTxValidation", write (*SkipTxValidation)});
        if (bool (CumulativeFeeValidation)) m = m.append ({"X-CumulativeFeeValidation", write (*CumulativeFeeValidation)});
        if (bool (CallbackToken)) m = m.append ({"X-CallbackToken", *CallbackToken});
        if (bool (WaitFor)) m = m.append ({"X-WaitFor", write (*WaitFor)});
        return m;
    }

    bool submit_response::valid (const HTTP::response &r) {
        if (!response::valid (r)) return false;
        auto b = response::body (r);
        if (!bool (b)) return true;

        if (response::is_error (r)) return error::valid (*b) &&
            r.Status == 400 || r.Status == 409 || r.Status == 422 || r.Status == 409 ||
            (unsigned (r.Status) >= 460 && unsigned (r.Status) <= 469) || r.Status == 473;

        if (!success::valid (*b)) return false;
        return status::valid (*b);
    }

    bool submit_txs_response::valid (const HTTP::response &r) {
        if (!response::valid (r)) return false;
        auto b = response::body (r);
        if (!bool (b)) return true;

        if (response::is_error (r)) return error::valid (*b) &&
            r.Status == 400 || r.Status == 409 || r.Status == 409 ||
            (unsigned (r.Status) >= 460 && unsigned (r.Status) <= 469) || r.Status == 473;

        if (!b->is_array ()) return false;
        for (const JSON &j : *b) if (!status::valid (j)) return false;
        return true;
    }

    list<status> submit_txs_response::status (const HTTP::response &r) {
        list<ARC::status> stat;
        auto b = response::body (r);
        for (const JSON &j : *b) stat <<= ARC::status {j};
        return stat;
    }

    // does a transaction satisfy the policy?
    bool policy::satisfies (const extended::transaction &tx) const {

        uint64 mxxp = max_script_size_policy ();
        uint64 mtxxcp = max_tx_sigops_count_policy ();
        uint64 mtxxp = max_tx_size_policy ();
        satoshis_per_byte spb = mining_fee ();

        Bitcoin::transaction t = Bitcoin::transaction (tx);
        if (t.sigops () > mtxxcp ) return false;
        if (t.serialized_size () > mtxxp) return false;
        if (tx.fee () < spb) return false;

        for (const auto &in : tx.Inputs) if (in.Script.size () > mxxp) return false;
        for (const auto &out : tx.Outputs) if (out.Script.size () > mxxp) return false;

        return true;
    }

}
