// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_HD
#define GIGAMONKEY_SCHEMA_HD

#include <gigamonkey/wif.hpp>
#include "keysource.hpp"
#include <ostream>

// HD is a format for infinite sequences of keys that 
// can be derived from a single master. This key format
// will be depricated but needs to be supported for 
// older wallets. 
namespace Gigamonkey::hd {
    
    using chain_code = data::bytes;
    using seed = data::bytes;
    using entropy = data::bytes;
    
    // bip 32 defines the basic format. See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    namespace bip32 {

        enum type : byte {
            main = 0x78,
            test = 0x74
        };
        
        constexpr type inline from_wif(Bitcoin::secret::type t) {
            return t == Bitcoin::secret::main ? main : t == Bitcoin::secret::test ? test : type{0};
        }
        
        constexpr Bitcoin::secret::type inline to_wif(type t) {
            return t == main ? Bitcoin::secret::main : t == test ? Bitcoin::secret::test : Bitcoin::secret::type{0};
        }
        
        constexpr type inline from_address(Bitcoin::address::type t) {
            return t == Bitcoin::address::main ? main : t == Bitcoin::address::test ? test : type{0};
        }
        
        constexpr Bitcoin::address::type inline to_address(type t) {
            return t == main ? Bitcoin::address::main : t == test ? Bitcoin::address::test : Bitcoin::address::type{0};
        }
        
        constexpr bool inline hardened(uint32 child) {
            return child >= 0x80000000;
        }
        
        constexpr uint32 inline harden(uint32 child) {
            return child | 0x80000000;
        }
        
        using path = list<uint32>;
        
        path read_path(string_view);
        string write(path);

        struct pubkey {
            
            secp256k1::pubkey Pubkey;
            chain_code ChainCode;
            type Net;
            byte Depth;
            uint32_t Parent;
            uint32_t Sequence;
            
            bool valid() const {
                return Pubkey.valid() && Pubkey.size() == secp256k1::pubkey::CompressedSize && (Net == main || Net == test);
            }
            
            pubkey(const secp256k1::pubkey& p, const chain_code& cc) : Pubkey{p}, ChainCode{cc} {}
            pubkey(string_view s) : pubkey{read(s)} {}
            pubkey() = default;
            
            static pubkey read(string_view);
            static pubkey from_seed(seed entropy,type net);

            string write() const;

            Bitcoin::address address() const {
                return Gigamonkey::Bitcoin::address{to_address(Net), Pubkey};
            }

            bool operator==(const pubkey &rhs) const;
            bool operator!=(const pubkey &rhs) const;
            
            pubkey derive(path l) const;
            pubkey derive(const string &l) const;
            
            explicit operator Bitcoin::address() const {
                return address();
            }
            
            explicit operator string() const {
                return write();
            }
        };
        
        struct secret {
            
            secp256k1::secret Secret;
            chain_code ChainCode;
            type Net;
            byte Depth;
            uint32_t Parent;
            uint32_t Sequence;

            secret(const secp256k1::secret& s, const chain_code& cc, type network) : Secret{s}, ChainCode{cc}, Net{network} {}
            secret(string_view s) : secret{read(s)} {}
            secret() = default;

            static secret read(string_view);
            static secret from_seed(seed entropy, type net = main);

            string write() const;
            pubkey to_public() const;
            
            bool valid() const {
                return Secret.valid() && (Net == main || Net == test);
            }

            bool operator==(const secret &rhs) const;

            bool operator!=(const secret &rhs) const;
            
            Bitcoin::signature sign(const digest256& d) const;
            
            secret derive(path l) const;
            secret derive(string_view l) const;
            
            explicit operator Bitcoin::secret() const {
                return Bitcoin::secret{to_wif(Net), Secret, true};
            }
            
            explicit operator string() const {
                return write();
            }
        };

        secret derive(const secret&, uint32);
        pubkey derive(const pubkey&, uint32);
        
        inline secret derive(const secret& s, path l) {
            if (l.empty()) return s;
            return derive(derive(s, l.first()), l.rest());
        }
        
        inline pubkey derive(const pubkey& p, path l) {
            if (l.empty()) return p;
            return derive(derive(p, l.first()), l.rest());
        }
        
        inline pubkey pubkey::derive(path l) const {
            return bip32::derive(*this, l);
        }
        
        inline secret secret::derive(path l) const {
            return bip32::derive(*this, l);
        }
        
        inline pubkey pubkey::derive(const string &l) const {
            return bip32::derive(*this, read_path(l));
        }
        
        inline secret secret::derive(string_view l) const {
            return bip32::derive(*this, read_path(l));
        }

        inline secret derive(const secret& x, string_view p) {
            return derive(x, read_path(p));
        }
        
        inline pubkey derive(const pubkey& x, string_view p) {
            return derive(x, read_path(p));
        }

        std::ostream inline &operator<<(std::ostream &os, const pubkey &pubkey) {
            return os << pubkey.write();
        }

        std::ostream inline &operator<<(std::ostream &os, const secret &secret) {
            return os << secret.write();
        }
    
    }
    
    struct keysource final : Gigamonkey::keysource {
        uint32 Index;
        bip32::secret HDSecret;
        Bitcoin::secret Secret;
        
        keysource(uint32 i, const bip32::secret& s, bool compressed = true) : 
            Index{i}, HDSecret{s}, Secret{bip32::to_wif(s.Net), bip32::derive(HDSecret, Index).Secret, compressed} {}
        
        keysource(const bip32::secret& s, bool compressed = true) : keysource{1, s, compressed} {}
        
        Bitcoin::secret first() const override {
            return Secret;
        }
        
        ptr<Gigamonkey::keysource> rest() const override {
            return std::static_pointer_cast<Gigamonkey::keysource>(std::make_shared<keysource>(Index + 1, HDSecret, Secret.Compressed));
        }
    };
    
    namespace bip39 {
        enum language {
            english,
            japanese,
            electrum_sv_english
        };
        
        seed read(std::string words, const string& passphrase="", language lang=language::english);

        std::string generate(entropy, language lang=language::english);
        bool valid(std::string words, language lang=language::english);
    }
    
    namespace bip44 {
        
        constexpr uint32 purpose = bip32::harden(44); // Purpose = 44'
        
        constexpr uint32 coin_type_Bitcoin = bip32::harden(44); // BSV = 0'
        
        constexpr uint32 coin_type_Bitcoin_Cash = bip32::harden(145); 
        
        constexpr uint32 coin_type_Bitcoin_SV = bip32::harden(236); 
        
        constexpr uint32 coin_type_testnet = bip32::harden(1); // BSV Testnet = 1'
        
        constexpr uint32 receive_index = 0; 
        
        constexpr uint32 change_index = 1; 
        
        inline list<uint32> derivation_path(uint32 account, bool change, uint32 index, uint32 coin_type = coin_type_Bitcoin) {
            return list<uint32>{purpose, coin_type, bip32::harden(account), uint32(change), index};
        }
        
        struct pubkey {
            bip32::pubkey Pubkey;
            
            pubkey(const bip32::pubkey& p) : Pubkey{p} {}
            
            Bitcoin::address receive(uint32 index, uint32 account = 0) const {
                return Bitcoin::address(Pubkey.derive(bip32::path{bip32::harden(account), receive_index, index}));
            }
            
            Bitcoin::address change(uint32 index, uint32 account = 0) const {
                return Bitcoin::address(Pubkey.derive(bip32::path{bip32::harden(account), change_index, index}));
            }
            
            bip32::pubkey account(uint32 a) const {
                return Pubkey.derive(bip32::path{a});
            }
        };
        
        struct secret {
            bip32::secret Secret;
            
            pubkey to_public() const;
            
            secret(const bip32::secret &s) : Secret{s} {}
            secret(const seed &x, uint32 coin_type = coin_type_Bitcoin, bip32::type net = bip32::main) : 
                Secret{bip32::secret::from_seed(x, net).derive({purpose, coin_type})} {}
            
            Bitcoin::secret receive(uint32 index, uint32 account = 0) const {
                return Bitcoin::secret(Secret.derive({bip32::harden(account), receive_index, index}));
            }
            
            Bitcoin::secret change(uint32 index, uint32 account = 0) const {
                return Bitcoin::secret(Secret.derive({bip32::harden(account), change_index, index}));
            }
            
            bip32::secret account(uint32 a) const {
                return Secret.derive({a});
            }
        };
        
        // coin types for standard wallets. 
        constexpr uint32 simply_cash_coin_type = coin_type_Bitcoin_Cash;
        
        constexpr uint32 moneybutton_coin_type = coin_type_Bitcoin;
        
        constexpr uint32 relay_x_coin_type = coin_type_Bitcoin_SV;
        
        constexpr uint32 electrum_sv_coin_type = coin_type_Bitcoin_Cash;
        
        secret inline simply_cash_wallet(const string& words, bip32::type net = bip32::main) {
            return secret{bip39::read(words), simply_cash_coin_type, net};
        }
        
        secret inline moneybutton_wallet(const string& words, bip32::type net = bip32::main) {
            return secret{bip39::read(words), moneybutton_coin_type, net};
        }
        
        // Note: electrum sv has its own set of words. It is able to load wallets that were
        // made with the standard set of words, but we do not load electrum words here yet. 
        secret inline electrum_sv_wallet(const string& words, bip39::language = bip39::electrum_sv_english, bip32::type net = bip32::main) {
            return secret{bip39::read(words), electrum_sv_coin_type, net};
        }
        
        secret relay_x_wallet(const string& words); // TODO
        
        secret centbee_wallet(const string& words, uint32 pin); // TODO
        
    }
    
    namespace bip39 {

        inline const cross<std::string>& english_words() {
            static cross<std::string> Words{
                "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse",
                "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act",
                "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult",
                "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead",
                "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley",
                "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing",
                "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal",
                "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart",
                "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm",
                "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
                "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom",
                "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto",
                "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward",
                "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", 
                "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean",
                "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below",
                "belt","bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike",
                "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak",
                "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body",
                "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom",
                "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick",
                "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother",
                "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
                "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage",
                "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel",
                "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", 
                "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog",
                "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement",
                "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter",
                "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief",
                "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
                "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk",
                "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth",
                "cloud",  "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee",
                "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common",
                "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince",
                "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch",
                "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane",
                "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", 
                "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch",
                "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain",
                "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring",
                "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide",
                "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver",
                "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy",
                "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop",
                "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ",
                "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover",
                "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy",
                "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose",
                "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill",
                "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch",
                "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo",
                "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder",
                "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace",
                "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse",
                "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich",
                "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase",
                "erode",  "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics",
                "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", 
                "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand",
                "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric",
                "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy",
                "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature",
                "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few",
                "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger",
                "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash",
                "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush",
                "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", 
                "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame",
                "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel",
                "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap",
                "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze",
                "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle",
                "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe",
                "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla",
                "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity",
                "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", 
                "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand",
                "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", 
                "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high",
                "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow",
                "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour",
                "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry",
                "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal",
                "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch",
                "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict",
                "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input",
                "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest",
                "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar",
                "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice",
                "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", 
                "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
                "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop",
                "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy",
                "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon",
                "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library",
                "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", 
                "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", 
                "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury",
                "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man",
                "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
                "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter",
                "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt",
                "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", 
                "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute",
                "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model",
                "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning",
                "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule",
                "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth",
                "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative",
                "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", 
                "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", 
                "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object",
                "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off",
                "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion",
                "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard",
                "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", 
                "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact",
                "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade",
                "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", 
                "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil",
                "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
                "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe",
                "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", 
                "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular",
                "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power",
                "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride",
                "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit",
                "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public",
                "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity",
                "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
                "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", 
                "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw",
                "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record",
                "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax",
                "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent",
                "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist",
                "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review",
                "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring",
                "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket",
                "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
                "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", 
                "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage",
                "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", 
                "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second",
                "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior",
                "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft",
                "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock",
                "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling",
                "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple",
                "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski",
                "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight",
                "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack",
                "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar",
                "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound",
                "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", 
                "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon",
                "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable",
                "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel",
                "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", 
                "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style",
                "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit",
                "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge",
                "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear",
                "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", 
                "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi",
                "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that",
                "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw",
                "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", 
                "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token",
                "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch",
                "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", 
                "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", 
                "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly",
                "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn",
                "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella",
                "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform",
                "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade",
                "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless",
                "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor",
                "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify",
                "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view",
                "village","vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid",
                "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk",
                "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
                "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
                "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper",
                "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter",
                "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work",
                "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year",
                "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"};
            return Words;
        };

        inline const cross<std::string>& japanese_words() {
            static cross<std::string> Words{
                    "あいこくしん", "あいさつ", "あいだ", "あおぞら", "あかちゃん", "あきる", "あけがた", "あける", "あこがれる",
                    "あさい", "あさひ", "あしあと", "あじわう", "あずかる", "あずき", "あそぶ", "あたえる", "あたためる",
                    "あたりまえ", "あたる", "あつい", "あつかう", "あっしゅく", "あつまり", "あつめる", "あてな", "あてはまる", "あひる",
                    "あぶら", "あぶる", "あふれる", "あまい", "あまど", "あまやかす", "あまり", "あみもの", "あめりか", "あやまる",
                    "あゆむ", "あらいぐま", "あらし", "あらすじ", "あらためる", "あらゆる", "あらわす", "ありがとう", "あわせる",
                    "あわてる", "あんい", "あんがい", "あんこ", "あんぜん", "あんてい", "あんない", "あんまり", "いいだす", "いおん",
                    "いがい", "いがく", "いきおい", "いきなり", "いきもの", "いきる", "いくじ", "いくぶん", "いけばな", "いけん",
                    "いこう", "いこく", "いこつ", "いさましい", "いさん", "いしき", "いじゅう", "いじょう", "いじわる", "いずみ",
                    "いずれ", "いせい", "いせえび", "いせかい", "いせき", "いぜん", "いそうろう", "いそがしい", "いだい",
                    "いだく", "いたずら", "いたみ", "いたりあ", "いちおう", "いちじ", "いちど", "いちば", "いちぶ", "いちりゅう",
                    "いつか", "いっしゅん", "いっせい", "いっそう", "いったん", "いっち", "いってい", "いっぽう", "いてざ", "いてん",
                    "いどう", "いとこ", "いない", "いなか", "いねむり", "いのち", "いのる", "いはつ", "いばる", "いはん", "いびき",
                    "いひん", "いふく", "いへん", "いほう", "いみん", "いもうと", "いもたれ", "いもり", "いやがる", "いやす", "いよかん",
                    "いよく", "いらい", "いらすと", "いりぐち", "いりょう", "いれい", "いれもの", "いれる", "いろえんぴつ", "いわい",
                    "いわう", "いわかん", "いわば", "いわゆる", "いんげんまめ", "いんさつ", "いんしょう", "いんよう", "うえき", "うえる",
                    "うおざ", "うがい", "うかぶ", "うかべる", "うきわ", "うくらいな", "うくれれ", "うけたまわる", "うけつけ",
                    "うけとる", "うけもつ", "うける", "うごかす", "うごく", "うこん", "うさぎ", "うしなう", "うしろがみ", "うすい",
                    "うすぎ", "うすぐらい", "うすめる", "うせつ", "うちあわせ", "うちがわ", "うちき", "うちゅう", "うっかり",
                    "うつくしい", "うったえる", "うつる", "うどん", "うなぎ", "うなじ", "うなずく", "うなる", "うねる", "うのう",
                    "うぶげ", "うぶごえ", "うまれる", "うめる", "うもう", "うやまう", "うよく", "うらがえす", "うらぐち",
                    "うらない", "うりあげ", "うりきれ", "うるさい", "うれしい", "うれゆき", "うれる", "うろこ", "うわき", "うわさ",
                    "うんこう", "うんちん", "うんてん", "うんどう", "えいえん", "えいが", "えいきょう", "えいご", "えいせい",
                    "えいぶん", "えいよう", "えいわ", "えおり", "えがお", "えがく", "えきたい", "えくせる", "えしゃく", "えすて",
                    "えつらん", "えのぐ", "えほうまき", "えほん", "えまき", "えもじ", "えもの", "えらい", "えらぶ", "えりあ",
                    "えんえん", "えんかい", "えんぎ", "えんげき", "えんしゅう", "えんぜつ", "えんそく", "えんちょう", "えんとつ",
                    "おいかける", "おいこす", "おいしい", "おいつく", "おうえん", "おうさま", "おうじ", "おうせつ", "おうたい", "おうふく",
                    "おうべい", "おうよう", "おえる", "おおい", "おおう", "おおどおり", "おおや", "おおよそ", "おかえり", "おかず",
                    "おがむ", "おかわり", "おぎなう", "おきる", "おくさま", "おくじょう", "おくりがな", "おくる", "おくれる",
                    "おこす", "おこなう", "おこる", "おさえる", "おさない", "おさめる", "おしいれ", "おしえる", "おじぎ", "おじさん",
                    "おしゃれ", "おそらく", "おそわる", "おたがい", "おたく", "おだやか", "おちつく", "おっと", "おつり", "おでかけ",
                    "おとしもの", "おとなしい", "おどり", "おどろかす", "おばさん", "おまいり", "おめでとう", "おもいで",
                    "おもう", "おもたい", "おもちゃ", "おやつ", "おやゆび", "およぼす", "おらんだ", "おろす", "おんがく", "おんけい",
                    "おんしゃ", "おんせん", "おんだん", "おんちゅう", "おんどけい", "かあつ", "かいが", "がいき", "がいけん",
                    "がいこう", "かいさつ", "かいしゃ", "かいすいよく", "かいぜん", "かいぞうど", "かいつう", "かいてん",
                    "かいとう", "かいふく", "がいへき", "かいほう", "かいよう", "がいらい", "かいわ", "かえる", "かおり", "かかえる",
                    "かがく", "かがし", "かがみ", "かくご", "かくとく", "かざる", "がぞう", "かたい", "かたち", "がちょう",
                    "がっきゅう", "がっこう", "がっさん", "がっしょう", "かなざわし", "かのう", "がはく", "かぶか", "かほう",
                    "かほご", "かまう", "かまぼこ", "かめれおん", "かゆい", "かようび", "からい", "かるい", "かろう", "かわく",
                    "かわら", "がんか", "かんけい", "かんこう", "かんしゃ", "かんそう", "かんたん", "かんち", "がんばる", "きあい",
                    "きあつ", "きいろ", "ぎいん", "きうい", "きうん", "きえる", "きおう", "きおく", "きおち", "きおん", "きかい", "きかく",
                    "きかんしゃ", "ききて", "きくばり", "きくらげ", "きけんせい", "きこう", "きこえる", "きこく", "きさい", "きさく",
                    "きさま", "きさらぎ", "ぎじかがく", "ぎしき", "ぎじたいけん", "ぎじにってい", "ぎじゅつしゃ",
                    "きすう", "きせい", "きせき", "きせつ", "きそう", "きぞく", "きぞん", "きたえる", "きちょう", "きつえん",
                    "ぎっちり", "きつつき", "きつね", "きてい", "きどう", "きどく", "きない", "きなが", "きなこ", "きぬごし",
                    "きねん", "きのう", "きのした", "きはく", "きびしい", "きひん", "きふく", "きぶん", "きぼう", "きほん", "きまる",
                    "きみつ", "きむずかしい", "きめる", "きもだめし", "きもち", "きもの", "きゃく", "きやく", "ぎゅうにく", "きよう",
                    "きょうりゅう", "きらい", "きらく", "きりん", "きれい", "きれつ", "きろく", "ぎろん", "きわめる", "ぎんいろ",
                    "きんかくじ", "きんじょ", "きんようび", "ぐあい", "くいず", "くうかん", "くうき", "くうぐん", "くうこう",
                    "ぐうせい", "くうそう", "ぐうたら", "くうふく", "くうぼ", "くかん", "くきょう", "くげん", "ぐこう", "くさい",
                    "くさき", "くさばな", "くさる", "くしゃみ", "くしょう", "くすのき", "くすりゆび", "くせげ", "くせん",
                    "ぐたいてき", "くださる", "くたびれる", "くちこみ", "くちさき", "くつした", "ぐっすり", "くつろぐ",
                    "くとうてん", "くどく", "くなん", "くねくね", "くのう", "くふう", "くみあわせ", "くみたてる", "くめる", "くやくしょ",
                    "くらす", "くらべる", "くるま", "くれる", "くろう", "くわしい", "ぐんかん", "ぐんしょく", "ぐんたい", "ぐんて",
                    "けあな", "けいかく", "けいけん", "けいこ", "けいさつ", "げいじゅつ", "けいたい", "げいのうじん", "けいれき",
                    "けいろ", "けおとす", "けおりもの", "げきか", "げきげん", "げきだん", "げきちん", "げきとつ", "げきは",
                    "げきやく", "げこう", "げこくじょう", "げざい", "けさき", "げざん", "けしき", "けしごむ", "けしょう",
                    "げすと", "けたば", "けちゃっぷ", "けちらす", "けつあつ", "けつい", "けつえき", "けっこん", "けつじょ",
                    "けっせき", "けってい", "けつまつ", "げつようび", "げつれい", "けつろん", "げどく", "けとばす", "けとる",
                    "けなげ", "けなす", "けなみ", "けぬき", "げねつ", "けねん", "けはい", "げひん", "けぶかい", "げぼく",
                    "けまり", "けみかる", "けむし", "けむり", "けもの", "けらい", "けろけろ", "けわしい", "けんい", "けんえつ", "けんお",
                    "けんか", "げんき", "けんげん", "けんこう", "けんさく", "けんしゅう", "けんすう", "げんそう", "けんちく",
                    "けんてい", "けんとう", "けんない", "けんにん", "げんぶつ", "けんま", "けんみん", "けんめい", "けんらん", "けんり",
                    "こあくま", "こいぬ", "こいびと", "ごうい", "こうえん", "こうおん", "こうかん", "ごうきゅう", "ごうけい",
                    "こうこう", "こうさい", "こうじ", "こうすい", "ごうせい", "こうそく", "こうたい", "こうちゃ", "こうつう", "こうてい",
                    "こうどう", "こうない", "こうはい", "ごうほう", "ごうまん", "こうもく", "こうりつ", "こえる", "こおり", "ごかい",
                    "ごがつ", "ごかん", "こくご", "こくさい", "こくとう", "こくない", "こくはく", "こぐま", "こけい", "こける",
                    "ここのか", "こころ", "こさめ", "こしつ", "こすう", "こせい", "こせき", "こぜん", "こそだて", "こたい", "こたえる",
                    "こたつ", "こちょう", "こっか", "こつこつ", "こつばん", "こつぶ", "こてい", "こてん", "ことがら", "ことし",
                    "ことば", "ことり", "こなごな", "こねこね", "このまま", "このみ", "このよ", "ごはん", "こひつじ", "こふう",
                    "こふん", "こぼれる", "ごまあぶら", "こまかい", "ごますり", "こまつな", "こまる", "こむぎこ", "こもじ",
                    "こもち", "こもの", "こもん", "こやく", "こやま", "こゆう", "こゆび", "こよい", "こよう", "こりる", "これくしょん",
                    "ころっけ", "こわもて", "こわれる", "こんいん", "こんかい", "こんき", "こんしゅう", "こんすい", "こんだて", "こんとん",
                    "こんなん", "こんびに", "こんぽん", "こんまけ", "こんや", "こんれい", "こんわく", "ざいえき", "さいかい",
                    "さいきん", "ざいげん", "ざいこ", "さいしょ", "さいせい", "ざいたく", "ざいちゅう", "さいてき", "ざいりょう",
                    "さうな", "さかいし", "さがす", "さかな", "さかみち", "さがる", "さぎょう", "さくし", "さくひん", "さくら",
                    "さこく", "さこつ", "さずかる", "ざせき", "さたん", "さつえい", "ざつおん", "ざっか", "ざつがく",
                    "さっきょく", "ざっし", "さつじん", "ざっそう", "さつたば", "さつまいも", "さてい", "さといも", "さとう",
                    "さとおや", "さとし", "さとる", "さのう", "さばく", "さびしい", "さべつ", "さほう", "さほど", "さます",
                    "さみしい", "さみだれ", "さむけ", "さめる", "さやえんどう", "さゆう", "さよう", "さよく", "さらだ", "ざるそば",
                    "さわやか", "さわる", "さんいん", "さんか", "さんきゃく", "さんこう", "さんさい", "ざんしょ", "さんすう", "さんせい",
                    "さんそ", "さんち", "さんま", "さんみ", "さんらん", "しあい", "しあげ", "しあさって", "しあわせ", "しいく", "しいん",
                    "しうち", "しえい", "しおけ", "しかい", "しかく", "じかん", "しごと", "しすう", "じだい", "したうけ", "したぎ",
                    "したて", "したみ", "しちょう", "しちりん", "しっかり", "しつじ", "しつもん", "してい", "してき", "してつ", "じてん",
                    "じどう", "しなぎれ", "しなもの", "しなん", "しねま", "しねん", "しのぐ", "しのぶ", "しはい", "しばかり",
                    "しはつ", "しはらい", "しはん", "しひょう", "しふく", "じぶん", "しへい", "しほう", "しほん", "しまう", "しまる",
                    "しみん", "しむける", "じむしょ", "しめい", "しめる", "しもん", "しゃいん", "しゃうん", "しゃおん", "じゃがいも",
                    "しやくしょ", "しゃくほう", "しゃけん", "しゃこ", "しゃざい", "しゃしん", "しゃせん", "しゃそう", "しゃたい",
                    "しゃちょう", "しゃっきん", "じゃま", "しゃりん", "しゃれい", "じゆう", "じゅうしょ", "しゅくはく", "じゅしん",
                    "しゅっせき", "しゅみ", "しゅらば", "じゅんばん", "しょうかい", "しょくたく", "しょっけん", "しょどう",
                    "しょもつ", "しらせる", "しらべる", "しんか", "しんこう", "じんじゃ", "しんせいじ", "しんちく", "しんりん",
                    "すあげ", "すあし", "すあな", "ずあん", "すいえい", "すいか", "すいとう", "ずいぶん", "すいようび",
                    "すうがく", "すうじつ", "すうせん", "すおどり", "すきま", "すくう", "すくない", "すける", "すごい", "すこし",
                    "ずさん", "すずしい", "すすむ", "すすめる", "すっかり", "ずっしり", "ずっと", "すてき", "すてる", "すねる",
                    "すのこ", "すはだ", "すばらしい", "ずひょう", "ずぶぬれ", "すぶり", "すふれ", "すべて", "すべる",
                    "ずほう", "すぼん", "すまい", "すめし", "すもう", "すやき", "すらすら", "するめ", "すれちがう", "すろっと",
                    "すわる", "すんぜん", "すんぽう", "せあぶら", "せいかつ", "せいげん", "せいじ", "せいよう", "せおう",
                    "せかいかん", "せきにん", "せきむ", "せきゆ", "せきらんうん", "せけん", "せこう", "せすじ", "せたい", "せたけ",
                    "せっかく", "せっきゃく", "ぜっく", "せっけん", "せっこつ", "せっさたくま", "せつぞく", "せつだん", "せつでん",
                    "せっぱん", "せつび", "せつぶん", "せつめい", "せつりつ", "せなか", "せのび", "せはば", "せびろ", "せぼね",
                    "せまい", "せまる", "せめる", "せもたれ", "せりふ", "ぜんあく", "せんい", "せんえい", "せんか", "せんきょ", "せんく",
                    "せんげん", "ぜんご", "せんさい", "せんしゅ", "せんすい", "せんせい", "せんぞ", "せんたく", "せんちょう",
                    "せんてい", "せんとう", "せんぬき", "せんねん", "せんぱい", "ぜんぶ", "ぜんぽう", "せんむ", "せんめんじょ",
                    "せんもん", "せんやく", "せんゆう", "せんよう", "ぜんら", "ぜんりゃく", "せんれい", "せんろ", "そあく",
                    "そいとげる", "そいね", "そうがんきょう", "そうき", "そうご", "そうしん", "そうだん", "そうなん", "そうび",
                    "そうめん", "そうり", "そえもの", "そえん", "そがい", "そげき", "そこう", "そこそこ", "そざい", "そしな", "そせい",
                    "そせん", "そそぐ", "そだてる", "そつう", "そつえん", "そっかん", "そつぎょう", "そっけつ", "そっこう", "そっせん",
                    "そっと", "そとがわ", "そとづら", "そなえる", "そなた", "そふぼ", "そぼく", "そぼろ", "そまつ", "そまる",
                    "そむく", "そむりえ", "そめる", "そもそも", "そよかぜ", "そらまめ", "そろう", "そんかい", "そんけい", "そんざい",
                    "そんしつ", "そんぞく", "そんちょう", "ぞんび", "ぞんぶん", "そんみん", "たあい", "たいいん", "たいうん",
                    "たいえき", "たいおう", "だいがく", "たいき", "たいぐう", "たいけん", "たいこ", "たいざい", "だいじょうぶ",
                    "だいすき", "たいせつ", "たいそう", "だいたい", "たいちょう", "たいてい", "だいどころ", "たいない", "たいねつ",
                    "たいのう", "たいはん", "だいひょう", "たいふう", "たいへん", "たいほ", "たいまつばな", "たいみんぐ", "たいむ",
                    "たいめん", "たいやき", "たいよう", "たいら", "たいりょく", "たいる", "たいわん", "たうえ", "たえる", "たおす", "たおる",
                    "たおれる", "たかい", "たかね", "たきび", "たくさん", "たこく", "たこやき", "たさい", "たしざん", "だじゃれ",
                    "たすける", "たずさわる", "たそがれ", "たたかう", "たたく", "ただしい", "たたみ", "たちばな", "だっかい",
                    "だっきゃく", "だっこ", "だっしゅつ", "だったい", "たてる", "たとえる", "たなばた", "たにん", "たぬき",
                    "たのしみ", "たはつ", "たぶん", "たべる", "たぼう", "たまご", "たまる", "だむる", "ためいき", "ためす",
                    "ためる", "たもつ", "たやすい", "たよる", "たらす", "たりきほんがん", "たりょう", "たりる", "たると", "たれる",
                    "たれんと", "たろっと", "たわむれる", "だんあつ", "たんい", "たんおん", "たんか", "たんき", "たんけん", "たんご",
                    "たんさん", "たんじょうび", "だんせい", "たんそく", "たんたい", "だんち", "たんてい", "たんとう", "だんな",
                    "たんにん", "だんねつ", "たんのう", "たんぴん", "だんぼう", "たんまつ", "たんめい", "だんれつ", "だんろ",
                    "だんわ", "ちあい", "ちあん", "ちいき", "ちいさい", "ちえん", "ちかい", "ちから", "ちきゅう", "ちきん", "ちけいず",
                    "ちけん", "ちこく", "ちさい", "ちしき", "ちしりょう", "ちせい", "ちそう", "ちたい", "ちたん", "ちちおや", "ちつじょ", "ちてき", "ちてん",
                    "ちぬき", "ちぬり", "ちのう", "ちひょう", "ちへいせん", "ちほう", "ちまた", "ちみつ", "ちみどろ", "ちめいど", "ちゃんこなべ", "ちゅうい",
                    "ちゆりょく", "ちょうし", "ちょさくけん", "ちらし", "ちらみ", "ちりがみ", "ちりょう", "ちるど", "ちわわ", "ちんたい", "ちんもく", "ついか",
                    "ついたち", "つうか", "つうじょう", "つうはん", "つうわ", "つかう", "つかれる", "つくね", "つくる", "つけね", "つける", "つごう", "つたえる",
                    "つづく", "つつじ", "つつむ", "つとめる", "つながる", "つなみ", "つねづね", "つのる", "つぶす", "つまらない", "つまる", "つみき",
                    "つめたい", "つもり", "つもる", "つよい", "つるぼ", "つるみく", "つわもの", "つわり", "てあし", "てあて", "てあみ", "ていおん", "ていか",
                    "ていき", "ていけい", "ていこく", "ていさつ", "ていし", "ていせい", "ていたい", "ていど", "ていねい", "ていひょう", "ていへん", "ていぼう",
                    "てうち", "ておくれ", "てきとう", "てくび", "でこぼこ", "てさぎょう", "てさげ", "てすり", "てそう", "てちがい", "てちょう", "てつがく",
                    "てつづき", "でっぱ", "てつぼう", "てつや", "でぬかえ", "てぬき", "てぬぐい", "てのひら", "てはい", "てぶくろ", "てふだ", "てほどき",
                    "てほん", "てまえ", "てまきずし", "てみじか", "てみやげ", "てらす", "てれび", "てわけ", "てわたし", "でんあつ", "てんいん", "てんかい",
                    "てんき", "てんぐ", "てんけん", "てんごく", "てんさい", "てんし", "てんすう", "でんち", "てんてき", "てんとう", "てんない", "てんぷら",
                    "てんぼうだい", "てんめつ", "てんらんかい", "でんりょく", "でんわ", "どあい", "といれ", "どうかん", "とうきゅう", "どうぐ", "とうし",
                    "とうむぎ", "とおい", "とおか", "とおく", "とおす", "とおる", "とかい", "とかす", "ときおり", "ときどき", "とくい", "とくしゅう", "とくてん",
                    "とくに", "とくべつ", "とけい", "とける", "とこや", "とさか", "としょかん", "とそう", "とたん", "とちゅう", "とっきゅう", "とっくん", 
                    "とつぜん", "とつにゅう", "とどける", "ととのえる", "とない", "となえる", "となり", "とのさま", "とばす", "どぶがわ", "とほう", "とまる", 
                    "とめる", "ともだち", "ともる", "どようび", "とらえる", "とんかつ", "どんぶり", "ないかく", "ないこう", "ないしょ", "ないす", "ないせん", 
                    "ないそう", "なおす", "ながい", "なくす", "なげる", "なこうど", "なさけ", "なたでここ", "なっとう", "なつやすみ", "ななおし", "なにごと", 
                    "なにもの", "なにわ", "なのか", "なふだ", "なまいき", "なまえ", "なまみ", "なみだ", "なめらか", "なめる", "なやむ", "ならう", "ならび", 
                    "ならぶ", "なれる", "なわとび", "なわばり", "にあう", "にいがた", "にうけ", "におい", "にかい", "にがて", "にきび", "にくしみ", "にくまん",
                    "にげる", "にさんかたんそ", "にしき", "にせもの", "にちじょう", "にちようび", "にっか", "にっき", "にっけい", "にっこう", "にっさん", 
                    "にっしょく", "にっすう", "にっせき", "にってい", "になう", "にほん", "にまめ", "にもつ", "にやり", "にゅういん", "にりんしゃ", "にわとり",
                    "にんい", "にんか", "にんき", "にんげん", "にんしき", "にんずう", "にんそう", "にんたい", "にんち", "にんてい", "にんにく", "にんぷ", 
                    "にんまり", "にんむ", "にんめい", "にんよう", "ぬいくぎ", "ぬかす", "ぬぐいとる", "ぬぐう", "ぬくもり", "ぬすむ", "ぬまえび", "ぬめり", 
                    "ぬらす", "ぬんちゃく",
                    "ねあげ", "ねいき", "ねいる", "ねいろ", "ねぐせ", "ねくたい", "ねくら", "ねこぜ", "ねこむ", "ねさげ", "ねすごす", "ねそべる", "ねだん",
                    "ねつい", "ねっしん", "ねつぞう", "ねったいぎょ", "ねぶそく", "ねふだ", "ねぼう", "ねほりはほり", "ねまき", "ねまわし", "ねみみ", "ねむい",
                    "ねむたい", "ねもと", "ねらう", "ねわざ", "ねんいり", "ねんおし", "ねんかん", "ねんきん", "ねんぐ", "ねんざ", "ねんし", "ねんちゃく",
                    "ねんど", "ねんぴ", "ねんぶつ", "ねんまつ", "ねんりょう", "ねんれい", "のいず", "のおづま", "のがす", "のきなみ", "のこぎり", "のこす",
                    "のこる", "のせる", "のぞく", "のぞむ", "のたまう", "のちほど", "のっく", "のばす", "のはら", "のべる", "のぼる", "のみもの", "のやま",
                    "のらいぬ", "のらねこ", "のりもの", "のりゆき", "のれん", "のんき", "ばあい", "はあく", "ばあさん", "ばいか", "ばいく", "はいけん",
                    "はいご", "はいしん", "はいすい", "はいせん", "はいそう", "はいち", "ばいばい", "はいれつ", "はえる", "はおる", "はかい", "ばかり", "はかる",
                    "はくしゅ", "はけん", "はこぶ", "はさみ", "はさん", "はしご", "ばしょ", "はしる", "はせる", "ぱそこん", "はそん", "はたん", "はちみつ",
                    "はつおん", "はっかく", "はづき", "はっきり", "はっくつ", "はっけん", "はっこう", "はっさん", "はっしん", "はったつ", "はっちゅう", "はってん",
                    "はっぴょう", "はっぽう", "はなす", "はなび", "はにかむ", "はぶらし", "はみがき", "はむかう", "はめつ", "はやい", "はやし", "はらう",
                    "はろうぃん", "はわい", "はんい", "はんえい", "はんおん", "はんかく", "はんきょう", "ばんぐみ", "はんこ", "はんしゃ", "はんすう", "はんだん",
                    "ぱんち", "ぱんつ", "はんてい", "はんとし", "はんのう", "はんぱ", "はんぶん", "はんぺん", "はんぼうき", "はんめい", "はんらん", "はんろん",
                    "ひいき", "ひうん", "ひえる", "ひかく", "ひかり", "ひかる", "ひかん", "ひくい", "ひけつ", "ひこうき", "ひこく", "ひさい", "ひさしぶり",
                    "ひさん", "びじゅつかん", "ひしょ", "ひそか", "ひそむ", "ひたむき", "ひだり", "ひたる", "ひつぎ", "ひっこし", "ひっし", "ひつじゅひん",
                    "ひっす", "ひつぜん", "ぴったり", "ぴっちり", "ひつよう", "ひてい", "ひとごみ", "ひなまつり", "ひなん", "ひねる", "ひはん", "ひびく",
                    "ひひょう", "ひほう", "ひまわり", "ひまん", "ひみつ", "ひめい", "ひめじし", "ひやけ", "ひやす", "ひよう", "びょうき", "ひらがな", "ひらく",
                    "ひりつ", "ひりょう", "ひるま", "ひるやすみ", "ひれい", "ひろい", "ひろう", "ひろき", "ひろゆき", "ひんかく", "ひんけつ", "ひんこん", 
                    "ひんしゅ", "ひんそう", "ぴんち", "ひんぱん", "びんぼう", "ふあん", "ふいうち", "ふうけい", "ふうせん", "ぷうたろう", "ふうとう", "ふうふ",
                    "ふえる", "ふおん", "ふかい", "ふきん", "ふくざつ", "ふくぶくろ", "ふこう", "ふさい", "ふしぎ", "ふじみ", "ふすま", "ふせい", "ふせぐ", 
                    "ふそく", "ぶたにく", "ふたん", "ふちょう", "ふつう", "ふつか", "ふっかつ", "ふっき", "ふっこく", "ぶどう", "ふとる", "ふとん", "ふのう", 
                    "ふはい", "ふひょう", "ふへん", "ふまん", "ふみん", "ふめつ", "ふめん", "ふよう", "ふりこ", "ふりる", "ふるい", "ふんいき", "ぶんがく", 
                    "ぶんぐ", "ふんしつ", "ぶんせき", "ふんそう", "ぶんぽう", "へいあん", "へいおん", "へいがい", "へいき", "へいげん", "へいこう", "へいさ", 
                    "へいしゃ", "へいせつ", "へいそ", "へいたく", "へいてん", "へいねつ", "へいわ", "へきが", "へこむ", "べにいろ", "べにしょうが", "へらす", 
                    "へんかん", "べんきょう", "べんごし", "へんさい", "へんたい", "べんり", "ほあん", "ほいく", "ぼうぎょ", "ほうこく", "ほうそう", "ほうほう", 
                    "ほうもん", "ほうりつ", "ほえる", "ほおん", "ほかん", "ほきょう", "ぼきん", "ほくろ", "ほけつ", "ほけん", "ほこう", "ほこる", "ほしい", 
                    "ほしつ", "ほしゅ", "ほしょう", "ほせい", "ほそい", "ほそく", "ほたて", "ほたる", "ぽちぶくろ", "ほっきょく", "ほっさ", "ほったん", 
                    "ほとんど", "ほめる", "ほんい", "ほんき", "ほんけ", "ほんしつ", "ほんやく", "まいにち", "まかい", "まかせる", "まがる", "まける", "まこと", 
                    "まさつ", "まじめ", "ますく", "まぜる", "まつり", "まとめ", "まなぶ", "まぬけ", "まねく", "まほう", "まもる", "まゆげ", "まよう", "まろやか",
                    "まわす", "まわり", "まわる", "まんが", "まんきつ", "まんぞく", "まんなか", "みいら", "みうち", "みえる", "みがく", "みかた", "みかん", 
                    "みけん", "みこん", "みじかい", "みすい", "みすえる", "みせる", "みっか", "みつかる", "みつける", "みてい", "みとめる", "みなと", 
                    "みなみかさい", "みねらる", "みのう", "みのがす", "みほん", "みもと", "みやげ", "みらい", "みりょく", "みわく", "みんか", "みんぞく", 
                    "むいか", "むえき", "むえん", "むかい", "むかう", "むかえ", "むかし", "むぎちゃ", "むける", "むげん", "むさぼる", "むしあつい", "むしば", 
                    "むじゅん", "むしろ", "むすう", "むすこ", "むすぶ", "むすめ", "むせる", "むせん", "むちゅう", "むなしい", "むのう", "むやみ", "むよう", 
                    "むらさき", "むりょう", "むろん", "めいあん", "めいうん", "めいえん", "めいかく", "めいきょく", "めいさい", "めいし", "めいそう", "めいぶつ",
                    "めいれい", "めいわく", "めぐまれる", "めざす", "めした", "めずらしい", "めだつ", "めまい", "めやす", "めんきょ", "めんせき", "めんどう",
                    "もうしあげる", "もうどうけん", "もえる", "もくし", "もくてき", "もくようび", "もちろん", "もどる", "もらう", "もんく", "もんだい", "やおや", 
                    "やける", "やさい", "やさしい", "やすい", "やすたろう", "やすみ", "やせる", "やそう", "やたい", "やちん", "やっと", "やっぱり", "やぶる", 
                    "やめる", "ややこしい", "やよい", "やわらかい", "ゆうき", "ゆうびんきょく", "ゆうべ", "ゆうめい", "ゆけつ", "ゆしゅつ", "ゆせん", "ゆそう", 
                    "ゆたか", "ゆちゃく", "ゆでる", "ゆにゅう", "ゆびわ", "ゆらい", "ゆれる", "ようい", "ようか", "ようきゅう", "ようじ", "ようす", "ようちえん",
                    "よかぜ", "よかん", "よきん", "よくせい", "よくぼう", "よけい", "よごれる", "よさん", "よしゅう", "よそう", "よそく", "よっか", "よてい", 
                    "よどがわく", "よねつ", "よやく", "よゆう", "よろこぶ", "よろしい", "らいう", "らくがき", "らくご", "らくさつ", "らくだ", "らしんばん", 
                    "らせん", "らぞく", "らたい", "らっか", "られつ", "りえき", "りかい", "りきさく", "りきせつ", "りくぐん", "りくつ", "りけん", "りこう", 
                    "りせい", "りそう", "りそく", "りてん", "りねん", "りゆう", "りゅうがく", "りよう", "りょうり", "りょかん", "りょくちゃ", "りょこう", 
                    "りりく", "りれき", "りろん", "りんご", "るいけい", "るいさい", "るいじ", "るいせき", "るすばん", "るりがわら", "れいかん", "れいぎ", 
                    "れいせい", "れいぞうこ", "れいとう", "れいぼう", "れきし", "れきだい", "れんあい", "れんけい", "れんこん", "れんさい", "れんしゅう", 
                    "れんぞく", "れんらく", "ろうか", "ろうご", "ろうじん", "ろうそく", "ろくが", "ろこつ", "ろじうら", "ろしゅつ", "ろせん", "ろてん", "ろめん",
                    "ろれつ", "ろんぎ", "ろんぱ", "ろんぶん", "ろんり", "わかす", "わかめ", "わかやま", "わかれる", "わしつ", "わじまし", "わすれもの", "わらう",
                    "われる"
            };
            
            
            return Words;
        }
    
    }

}

#endif

