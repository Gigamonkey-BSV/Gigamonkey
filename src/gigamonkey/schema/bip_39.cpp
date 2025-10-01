// Copyright (c) 2020-2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/schema/bip_39.hpp>
#include <data/encoding/base58.hpp>
#include <data/encoding/endian.hpp>
#include <data/io/unimplemented.hpp>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hmac.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/pwdbased.h>
#include <boost/locale.hpp>

namespace Gigamonkey::HD::BIP_39 {
    char inline getBit (int index, bytes bitarray) {
        return (bitarray[index/8] >> 7 - (index & 0x7)) & 0x1;
    }

    void inline setBit (int index, int value, bytes &bitarray) {
        bitarray[index/8] = bitarray[index/8] | (value  << 7 - (index & 0x7));
    }
    
    const cross<UTF8> &getWordList (language lang) {
        switch (lang) {
            case english:
                return english_words ();
            case japanese:
                return japanese_words ();
            default:
                return english_words ();
        }
    }
    
    UTF8 getLangSplit (language lang) {
        switch (lang) {
            case japanese:
                return "\u3000";
            default:
                return " ";
        }
    }

    seed read (UTF8 words, const UTF8 &passphrase, language lang) {
        if (lang != english)
            throw data::method::unimplemented ("Non English Language");
        /*if(!valid(passphrase,lang)) {
            throw "Invalid Words";
        }*/
        std::string passcode;
        char wordsBA2[words.length ()];
        for (int i = 0; i < words.length (); i++) wordsBA2[i] = words[i];
        std::string salt = "mnemonic" + passphrase;
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
        byte key[64];

        pbkdf2.DeriveKey (key, sizeof (key), 0, (const byte *) wordsBA2, words.length (), (const byte *) salt.data (), salt.length (), 2048);
        seed x (64);
        std::copy (std::begin (key), std::end (key), x.begin ());
        return x;
    }

    UTF8 generate (entropy ent, language lang) {
        if (lang != english) throw data::method::unimplemented ("Non English Language");

        assert (ent.size () % 4 == 0);
        assert (ent.size () >= 16 && ent.size () <= 32);

        byte abDigest[CryptoPP::SHA256::DIGESTSIZE];
        CryptoPP::SHA256 ().CalculateDigest (abDigest, ent.data (), ent.size ());
        int checksumLength = (ent.size () * 8) / 32;
        byte checkByte = abDigest[0];
        byte mask = 1;
        mask = (1 << checksumLength) - 1;
        mask = mask << 8-checksumLength;
        checkByte &= mask;
        ent.emplace_back (checkByte);
        std::vector<int16> word_indices ((((ent.size () - 1) * 8) + checksumLength) / 11);
        std::fill (word_indices.begin (), word_indices.end (), 0);

        for (int i = 0; i < word_indices.size () * 11; i++)
            word_indices[i /11]+=getBit (i,ent) << (10 - (i % 11));

        cross<UTF8> words_ret;
        const cross<UTF8> &wordList = getWordList (lang);

        for (short word_index : word_indices) words_ret.emplace_back (wordList[word_index]);

        std::string output = "";
        for (std::string str : words_ret) output += str + getLangSplit (lang);

        switch (lang) {
            case japanese:
                boost::trim_right_if (output, boost::is_any_of (getLangSplit (lang)));
            case english:
                boost::trim_right (output);
        }

        return output;
    }

    bool valid (UTF8 words_text, language lang) {
        std::vector<UTF8> wordsList;
        boost::split (wordsList, words_text, boost::is_any_of (getLangSplit (lang)));
        std::vector<int> wordIndices (wordsList.size ());
        const cross<UTF8> &refWordList = getWordList (lang);

        for (int i = 0; i < wordsList.size (); i++) {
            bool found = false;
            for (int j = 0; j < refWordList.size (); j++) {
                if (refWordList[j] == wordsList[i]) {
                    wordIndices[i] = j;
                    found = true;
                }
            }

            if (!found) return false;
        }

        int wordIndicesSize = wordIndices.size ();
        double numBits = ((wordIndices.size ()) * 11);
        bytes byteArray (std::ceil (numBits / 8));

        for (int i = 0; i < numBits; i++) {
            bool bit = ((wordIndices[i/11]) & (1 << (10 - (i % 11))));
            setBit (i, bit, byteArray);
        }

        byte check = byteArray[byteArray.size () - 1];
        byte abDigest[CryptoPP::SHA256::DIGESTSIZE];
        CryptoPP::SHA256 ().CalculateDigest (abDigest, byteArray.data (), byteArray.size () - 1);
        int checksumLength = ((byteArray.size () - 1) * 8) / 32;
        byte checkByte = abDigest[0];
        byte mask = 1;
        mask = (1 << checksumLength) - 1;
        mask = mask << 8 - checksumLength;
        checkByte &= mask;

        return checkByte == check;
    }
    
    const cross<UTF8> &english_words () {
        static cross<UTF8> Words {
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
    
    const cross<UTF8> &japanese_words () {
        static cross<UTF8> Words {
            UTF8 ("あいこくしん"), UTF8 {"あいさつ"}, UTF8 {"あいだ"}, UTF8 {"あおぞら"}, UTF8 {"あかちゃん"}, UTF8 {"あきる"},
            UTF8 {"あけがた"}, UTF8 {"あける"}, UTF8 {"あこがれる"}, UTF8 {"あさい"}, UTF8 {"あさひ"}, UTF8 {"あしあと"},
            UTF8 {"あじわう"}, UTF8 {"あずかる"},  UTF8 {"あずき"}, UTF8 {"あそぶ"}, UTF8 {"あたえる"}, UTF8 {"あたためる"},
            UTF8 {"あたりまえ"}, UTF8 {"あたる"}, UTF8 {"あつい"}, UTF8 {"あつかう"}, UTF8 {"あっしゅく"}, UTF8 {"あつまり"},
            UTF8 {"あつめる"}, UTF8 {"あてな"}, UTF8 {"あてはまる"}, UTF8 {"あひる"}, UTF8 {"あぶら"}, UTF8 {"あぶる"},
            UTF8 {"あふれる"}, UTF8 {"あまい"}, UTF8 {"あまど"}, UTF8 {"あまやかす"}, UTF8 {"あまり"}, UTF8 {"あみもの"},
            UTF8 {"あめりか"}, UTF8 {"あやまる"}, UTF8 {"あゆむ"}, UTF8 {"あらいぐま"}, UTF8 {"あらし"}, UTF8 {"あらすじ"},
            UTF8 {"あらためる"}, UTF8 {"あらゆる"}, UTF8 {"あらわす"}, UTF8 {"ありがとう"}, UTF8 {"あわせる"}, UTF8 {"あわてる"},
            UTF8 {"あんい"}, UTF8 {"あんがい"}, UTF8 {"あんこ"}, UTF8 {"あんぜん"}, UTF8 {"あんてい"}, UTF8 {"あんない"},
            UTF8 {"あんまり"}, UTF8 {"いいだす"}, UTF8 {"いおん"}, UTF8 {"いがい"}, UTF8 {"いがく"}, UTF8 {"いきおい"},
            UTF8 {"いきなり"}, UTF8 {"いきもの"}, UTF8 {"いきる"}, UTF8 {"いくじ"}, UTF8 {"いくぶん"}, UTF8 {"いけばな"},
            UTF8 {"いけん"}, UTF8 {"いこう"}, UTF8 {"いこく"}, UTF8 {"いこつ"}, UTF8 {"いさましい"}, UTF8 {"いさん"},
            UTF8 {"いしき"}, UTF8 {"いじゅう"}, UTF8 {"いじょう"}, UTF8 {"いじわる"}, UTF8 {"いずみ"}, UTF8 {"いずれ"},
            UTF8 {"いせい"}, UTF8 {"いせえび"}, UTF8 {"いせかい"}, UTF8 {"いせき"}, UTF8 {"いぜん"}, UTF8 {"いそうろう"},
            UTF8 {"いそがしい"}, UTF8 {"いだい"}, UTF8 {"いだく"}, UTF8 {"いたずら"}, UTF8 {"いたみ"}, UTF8 {"いたりあ"},
            UTF8 {"いちおう"}, UTF8 {"いちじ"}, UTF8 {"いちど"}, UTF8 {"いちば"}, UTF8 {"いちぶ"}, UTF8 {"いちりゅう"},
            UTF8 {"いつか"}, UTF8 {"いっしゅん"}, UTF8 {"いっせい"}, UTF8 {"いっそう"}, UTF8 {"いったん"}, UTF8 {"いっち"},
            UTF8 {"いってい"}, UTF8 {"いっぽう"}, UTF8 {"いてざ"}, UTF8 {"いてん"}, UTF8 {"いどう"}, UTF8 {"いとこ"},
            UTF8 {"いない"}, UTF8 {"いなか"}, UTF8 {"いねむり"}, UTF8 {"いのち"}, UTF8 {"いのる"}, UTF8 {"いはつ"},
            UTF8 {"いばる"}, UTF8 {"いはん"}, UTF8 {"いびき"}, UTF8 {"いひん"}, UTF8 {"いふく"}, UTF8 {"いへん"},
            UTF8 {"いほう"}, UTF8 {"いみん"}, UTF8 {"いもうと"}, UTF8 {"いもたれ"}, UTF8 {"いもり"}, UTF8 {"いやがる"},
            UTF8 {"いやす"}, UTF8 {"いよかん"}, UTF8 {"いよく"}, UTF8 {"いらい"}, UTF8 {"いらすと"}, UTF8 {"いりぐち"},
            UTF8 {"いりょう"}, UTF8 {"いれい"}, UTF8 {"いれもの"}, UTF8 {"いれる"}, UTF8 {"いろえんぴつ"}, UTF8 {"いわい"},
            UTF8 {"いわう"}, UTF8 {"いわかん"}, UTF8 {"いわば"}, UTF8 {"いわゆる"}, UTF8 {"いんげんまめ"}, UTF8 {"いんさつ"},
            UTF8 {"いんしょう"}, UTF8 {"いんよう"}, UTF8 {"うえき"}, UTF8 {"うえる"}, UTF8 {"うおざ"}, UTF8 {"うがい"},
            UTF8 {"うかぶ"}, UTF8 {"うかべる"}, UTF8 {"うきわ"}, UTF8 {"うくらいな"}, UTF8 {"うくれれ"}, UTF8 {"うけたまわる"},
            UTF8 {"うけつけ"}, UTF8 {"うけとる"}, UTF8 {"うけもつ"}, UTF8 {"うける"}, UTF8 {"うごかす"}, UTF8 {"うごく"},
            UTF8 {"うこん"}, UTF8 {"うさぎ"}, UTF8 {"うしなう"}, UTF8 {"うしろがみ"}, UTF8 {"うすい"}, UTF8 {"うすぎ"},
            UTF8 {"うすぐらい"}, UTF8 {"うすめる"}, UTF8 {"うせつ"}, UTF8 {"うちあわせ"}, UTF8 {"うちがわ"}, UTF8 {"うちき"},
            UTF8 {"うちゅう"}, UTF8 {"うっかり"}, UTF8 {"うつくしい"}, UTF8 {"うったえる"}, UTF8 {"うつる"}, UTF8 {"うどん"},
            UTF8 {"うなぎ"}, UTF8 {"うなじ"}, UTF8 {"うなずく"}, UTF8 {"うなる"}, UTF8 {"うねる"}, UTF8 {"うのう"},
            UTF8 {"うぶげ"}, UTF8 {"うぶごえ"}, UTF8 {"うまれる"}, UTF8 {"うめる"}, UTF8 {"うもう"}, UTF8 {"うやまう"},
            UTF8 {"うよく"}, UTF8 {"うらがえす"}, UTF8 {"うらぐち"}, UTF8 {"うらない"}, UTF8 {"うりあげ"}, UTF8 {"うりきれ"},
            UTF8 {"うるさい"}, UTF8 {"うれしい"}, UTF8 {"うれゆき"}, UTF8 {"うれる"}, UTF8 {"うろこ"}, UTF8 {"うわき"},
            UTF8 {"うわさ"}, UTF8 {"うんこう"}, UTF8 {"うんちん"}, UTF8 {"うんてん"}, UTF8 {"うんどう"}, UTF8 {"えいえん"},
            UTF8 {"えいが"}, UTF8 {"えいきょう"}, UTF8 {"えいご"}, UTF8 {"えいせい"}, UTF8 {"えいぶん"}, UTF8 {"えいよう"},
            UTF8 {"えいわ"}, UTF8 {"えおり"}, UTF8 {"えがお"}, UTF8 {"えがく"}, UTF8 {"えきたい"}, UTF8 {"えくせる"},
            UTF8 {"えしゃく"}, UTF8 {"えすて"}, UTF8 {"えつらん"}, UTF8 {"えのぐ"}, UTF8 {"えほうまき"},  UTF8 {"えほん"},
            UTF8 {"えまき"}, UTF8 {"えもじ"}, UTF8 {"えもの"}, UTF8 {"えらい"}, UTF8 {"えらぶ"}, UTF8 {"えりあ"},
            UTF8 {"えんえん"}, UTF8 {"えんかい"}, UTF8 {"えんぎ"}, UTF8 {"えんげき"}, UTF8 {"えんしゅう"}, UTF8 {"えんぜつ"},
            UTF8 {"えんそく"}, UTF8 {"えんちょう"}, UTF8 {"えんとつ"}, UTF8 {"おいかける"}, UTF8 {"おいこす"},  UTF8 {"おいしい"},
            UTF8 {"おいつく"}, UTF8 {"おうえん"}, UTF8 {"おうさま"}, UTF8 {"おうじ"}, UTF8 {"おうせつ"}, UTF8 {"おうたい"},
            UTF8 {"おうふく"},  UTF8 {"おうべい"}, UTF8 {"おうよう"}, UTF8 {"おえる"}, UTF8 {"おおい"}, UTF8 {"おおう"},
            UTF8 {"おおどおり"}, UTF8 {"おおや"}, UTF8 {"おおよそ"}, UTF8 {"おかえり"}, UTF8 {"おかず"}, UTF8 {"おがむ"},
            UTF8 {"おかわり"}, UTF8 {"おぎなう"}, UTF8 {"おきる"}, UTF8 {"おくさま"}, UTF8 {"おくじょう"}, UTF8 {"おくりがな"},
            UTF8 {"おくる"}, UTF8 {"おくれる"}, UTF8 {"おこす"}, UTF8 {"おこなう"}, UTF8 {"おこる"}, UTF8 {"おさえる"},
            UTF8 {"おさない"}, UTF8 {"おさめる"}, UTF8 {"おしいれ"}, UTF8 {"おしえる"}, UTF8 {"おじぎ"}, UTF8 {"おじさん"},
            UTF8 {"おしゃれ"}, UTF8 {"おそらく"}, UTF8 {"おそわる"}, UTF8 {"おたがい"}, UTF8 {"おたく"}, UTF8 {"おだやか"},
            UTF8 {"おちつく"}, UTF8 {"おっと"}, UTF8 {"おつり"}, UTF8 {"おでかけ"}, UTF8 {"おとしもの"}, UTF8 {"おとなしい"},
            UTF8 {"おどり"}, UTF8 {"おどろかす"}, UTF8 {"おばさん"}, UTF8 {"おまいり"},  UTF8 {"おめでとう"}, UTF8 {"おもいで"},
            UTF8 {"おもう"}, UTF8 {"おもたい"}, UTF8 {"おもちゃ"}, UTF8 {"おやつ"}, UTF8 {"おやゆび"}, UTF8 {"およぼす"},
            UTF8 {"おらんだ"}, UTF8 {"おろす"}, UTF8 {"おんがく"}, UTF8 {"おんけい"}, UTF8 {"おんしゃ"}, UTF8 {"おんせん"},
            UTF8 {"おんだん"}, UTF8 {"おんちゅう"}, UTF8 {"おんどけい"},  UTF8 {"かあつ"}, UTF8 {"かいが"}, UTF8 {"がいき"},
            UTF8 {"がいけん"}, UTF8 {"がいこう"}, UTF8 {"かいさつ"}, UTF8 {"かいしゃ"}, UTF8 {"かいすいよく"}, UTF8 {"かいぜん"},
            UTF8 {"かいぞうど"}, UTF8 {"かいつう"}, UTF8 {"かいてん"}, UTF8 {"かいとう"}, UTF8 {"かいふく"}, UTF8 {"がいへき"},
            UTF8 {"かいほう"}, UTF8 {"かいよう"}, UTF8 {"がいらい"}, UTF8 {"かいわ"}, UTF8 {"かえる"}, UTF8 {"かおり"},
            UTF8 {"かかえる"}, UTF8 {"かがく"}, UTF8 {"かがし"}, UTF8 {"かがみ"}, UTF8 {"かくご"}, UTF8 {"かくとく"},
            UTF8 {"かざる"}, UTF8 {"がぞう"}, UTF8 {"かたい"}, UTF8 {"かたち"}, UTF8 {"がちょう"}, UTF8 {"がっきゅう"},
            UTF8 {"がっこう"}, UTF8 {"がっさん"}, UTF8 {"がっしょう"}, UTF8 {"かなざわし"}, UTF8 {"かのう"}, UTF8 {"がはく"},
            UTF8 {"かぶか"}, UTF8 {"かほう"}, UTF8 {"かほご"}, UTF8 {"かまう"}, UTF8 {"かまぼこ"}, UTF8 {"かめれおん"},
            UTF8 {"かゆい"}, UTF8 {"かようび"}, UTF8 {"からい"}, UTF8 {"かるい"}, UTF8 {"かろう"}, UTF8 {"かわく"},
            UTF8 {"かわら"}, UTF8 {"がんか"}, UTF8 {"かんけい"}, UTF8 {"かんこう"}, UTF8 {"かんしゃ"},
            UTF8 {"かんそう"}, UTF8 {"かんたん"}, UTF8 {"かんち"}, UTF8 {"がんばる"}, UTF8 {"きあい"}, UTF8 {"きあつ"},
            UTF8 {"きいろ"}, UTF8 {"ぎいん"}, UTF8 {"きうい"}, UTF8 {"きうん"}, UTF8 {"きえる"}, UTF8 {"きおう"},
            UTF8 {"きおく"}, UTF8 {"きおち"}, UTF8 {"きおん"}, UTF8 {"きかい"}, UTF8 {"きかく"}, UTF8 {"きかんしゃ"},
            UTF8 {"ききて"}, UTF8 {"きくばり"}, UTF8 {"きくらげ"}, UTF8 {"きけんせい"}, UTF8 {"きこう"}, UTF8 {"きこえる"},
            UTF8 {"きこく"}, UTF8 {"きさい"}, UTF8 {"きさく"}, UTF8 {"きさま"}, UTF8 {"きさらぎ"}, UTF8 {"ぎじかがく"},
            UTF8 {"ぎしき"}, UTF8 {"ぎじたいけん"}, UTF8 {"ぎじにってい"}, UTF8 {"ぎじゅつしゃ"}, UTF8 {"きすう"}, UTF8 {"きせい"},
            UTF8 {"きせき"}, UTF8 {"きせつ"}, UTF8 {"きそう"}, UTF8 {"きぞく"}, UTF8 {"きぞん"}, UTF8 {"きたえる"},
            UTF8 {"きちょう"}, UTF8 {"きつえん"}, UTF8 {"ぎっちり"}, UTF8 {"きつつき"}, UTF8 {"きつね"}, UTF8 {"きてい"},
            UTF8 {"きどう"}, UTF8 {"きどく"}, UTF8 {"きない"}, UTF8 {"きなが"}, UTF8 {"きなこ"}, UTF8 {"きぬごし"},
            UTF8 {"きねん"}, UTF8 {"きのう"}, UTF8 {"きのした"}, UTF8 {"きはく"}, UTF8 {"きびしい"}, UTF8 {"きひん"},
            UTF8 {"きふく"}, UTF8 {"きぶん"}, UTF8 {"きぼう"}, UTF8 {"きほん"}, UTF8 {"きまる"}, UTF8 {"きみつ"},
            UTF8 {"きむずかしい"}, UTF8 {"きめる"}, UTF8 {"きもだめし"}, UTF8 {"きもち"}, UTF8 {"きもの"}, UTF8 {"きゃく"},
            UTF8 {"きやく"}, UTF8 {"ぎゅうにく"}, UTF8 {"きよう"}, UTF8 {"きょうりゅう"}, UTF8 {"きらい"}, UTF8 {"きらく"},
            UTF8 {"きりん"}, UTF8 {"きれい"}, UTF8 {"きれつ"}, UTF8 {"きろく"}, UTF8 {"ぎろん"}, UTF8 {"きわめる"},
            UTF8 {"ぎんいろ"}, UTF8 {"きんかくじ"}, UTF8 {"きんじょ"}, UTF8 {"きんようび"}, UTF8 {"ぐあい"}, UTF8 {"くいず"},
            UTF8 {"くうかん"}, UTF8 {"くうき"}, UTF8 {"くうぐん"}, UTF8 {"くうこう"}, UTF8 {"ぐうせい"}, UTF8 {"くうそう"},
            UTF8 {"ぐうたら"}, UTF8 {"くうふく"}, UTF8 {"くうぼ"}, UTF8 {"くかん"}, UTF8 {"くきょう"},
            UTF8 {"くげん"}, UTF8 {"ぐこう"}, UTF8 {"くさい"}, UTF8 {"くさき"}, UTF8 {"くさばな"}, UTF8 {"くさる"},
            UTF8 {"くしゃみ"}, UTF8 {"くしょう"}, UTF8 {"くすのき"}, UTF8 {"くすりゆび"}, UTF8 {"くせげ"}, UTF8 {"くせん"},
            UTF8 {"ぐたいてき"}, UTF8 {"くださる"}, UTF8 {"くたびれる"}, UTF8 {"くちこみ"}, UTF8 {"くちさき"},
            UTF8 {"くつした"}, UTF8 {"ぐっすり"}, UTF8 {"くつろぐ"}, UTF8 {"くとうてん"}, UTF8 {"くどく"}, UTF8 {"くなん"},
            UTF8 {"くねくね"}, UTF8 {"くのう"}, UTF8 {"くふう"}, UTF8 {"くみあわせ"}, UTF8 {"くみたてる"}, UTF8 {"くめる"},
            UTF8 {"くやくしょ"}, UTF8 {"くらす"}, UTF8 {"くらべる"}, UTF8 {"くるま"}, UTF8 {"くれる"}, UTF8 {"くろう"},
            UTF8 {"くわしい"}, UTF8 {"ぐんかん"}, UTF8 {"ぐんしょく"}, UTF8 {"ぐんたい"}, UTF8 {"ぐんて"}, UTF8 {"けあな"},
            UTF8 {"けいかく"}, UTF8 {"けいけん"}, UTF8 {"けいこ"}, UTF8 {"けいさつ"}, UTF8 {"げいじゅつ"}, UTF8 {"けいたい"},
            UTF8 {"げいのうじん"}, UTF8 {"けいれき"}, UTF8 {"けいろ"}, UTF8 {"けおとす"}, UTF8 {"けおりもの"}, UTF8 {"げきか"},
            UTF8 {"げきげん"}, UTF8 {"げきだん"}, UTF8 {"げきちん"}, UTF8 {"げきとつ"}, UTF8 {"げきは"},
            UTF8 {"げきやく"}, UTF8 {"げこう"}, UTF8 {"げこくじょう"}, UTF8 {"げざい"}, UTF8 {"けさき"},
            UTF8 {"げざん"}, UTF8 {"けしき"}, UTF8 {"けしごむ"}, UTF8 {"けしょう"},
            UTF8 {"げすと"}, UTF8 {"けたば"}, UTF8 {"けちゃっぷ"}, UTF8 {"けちらす"}, UTF8 {"けつあつ"},
            UTF8 {"けつい"}, UTF8 {"けつえき"}, UTF8 {"けっこん"}, UTF8 {"けつじょ"},
            UTF8 {"けっせき"}, UTF8 {"けってい"}, UTF8 {"けつまつ"}, UTF8 {"げつようび"}, UTF8 {"げつれい"},
            UTF8 {"けつろん"}, UTF8 {"げどく"}, UTF8 {"けとばす"}, UTF8 {"けとる"},
            UTF8 {"けなげ"}, UTF8 {"けなす"}, UTF8 {"けなみ"}, UTF8 {"けぬき"}, UTF8 {"げねつ"}, UTF8 {"けねん"},
            UTF8 {"けはい"}, UTF8 {"げひん"}, UTF8 {"けぶかい"}, UTF8 {"げぼく"},
            UTF8 {"けまり"}, UTF8 {"けみかる"}, UTF8 {"けむし"}, UTF8 {"けむり"}, UTF8 {"けもの"}, UTF8 {"けらい"},
            UTF8 {"けろけろ"}, UTF8 {"けわしい"}, UTF8 {"けんい"}, UTF8 {"けんえつ"}, UTF8 {"けんお"},
            UTF8 {"けんか"}, UTF8 {"げんき"}, UTF8 {"けんげん"}, UTF8 {"けんこう"}, UTF8 {"けんさく"}, UTF8 {"けんしゅう"},
            UTF8 {"けんすう"}, UTF8 {"げんそう"}, UTF8 {"けんちく"},
            UTF8 {"けんてい"}, UTF8 {"けんとう"}, UTF8 {"けんない"}, UTF8 {"けんにん"}, UTF8 {"げんぶつ"},
            UTF8 {"けんま"}, UTF8 {"けんみん"}, UTF8 {"けんめい"}, UTF8 {"けんらん"}, UTF8 {"けんり"},
            UTF8 {"こあくま"}, UTF8 {"こいぬ"}, UTF8 {"こいびと"}, UTF8 {"ごうい"}, UTF8 {"こうえん"}, UTF8 {"こうおん"},
            UTF8 {"こうかん"}, UTF8 {"ごうきゅう"}, UTF8 {"ごうけい"},
            UTF8 {"こうこう"}, UTF8 {"こうさい"}, UTF8 {"こうじ"}, UTF8 {"こうすい"}, UTF8 {"ごうせい"},
            UTF8 {"こうそく"}, UTF8 {"こうたい"}, UTF8 {"こうちゃ"}, UTF8 {"こうつう"}, UTF8 {"こうてい"},
            UTF8 {"こうどう"}, UTF8 {"こうない"}, UTF8 {"こうはい"}, UTF8 {"ごうほう"}, UTF8 {"ごうまん"},
            UTF8 {"こうもく"}, UTF8 {"こうりつ"}, UTF8 {"こえる"}, UTF8 {"こおり"}, UTF8 {"ごかい"},
            UTF8 {"ごがつ"}, UTF8 {"ごかん"}, UTF8 {"こくご"}, UTF8 {"こくさい"}, UTF8 {"こくとう"},
            UTF8 {"こくない"}, UTF8 {"こくはく"}, UTF8 {"こぐま"}, UTF8 {"こけい"}, UTF8 {"こける"},
            UTF8 {"ここのか"}, UTF8 {"こころ"}, UTF8 {"こさめ"}, UTF8 {"こしつ"}, UTF8 {"こすう"},
            UTF8 {"こせい"}, UTF8 {"こせき"}, UTF8 {"こぜん"}, UTF8 {"こそだて"}, UTF8 {"こたい"}, UTF8 {"こたえる"},
            UTF8 {"こたつ"}, UTF8 {"こちょう"}, UTF8 {"こっか"}, UTF8 {"こつこつ"}, UTF8 {"こつばん"},
            UTF8 {"こつぶ"}, UTF8 {"こてい"}, UTF8 {"こてん"}, UTF8 {"ことがら"}, UTF8 {"ことし"},
            UTF8 {"ことば"}, UTF8 {"ことり"}, UTF8 {"こなごな"}, UTF8 {"こねこね"}, UTF8 {"このまま"},
            UTF8 {"このみ"}, UTF8 {"このよ"}, UTF8 {"ごはん"}, UTF8 {"こひつじ"}, UTF8 {"こふう"},
            UTF8 {"こふん"}, UTF8 {"こぼれる"}, UTF8 {"ごまあぶら"}, UTF8 {"こまかい"}, UTF8 {"ごますり"}, UTF8 {"こまつな"},
            UTF8 {"こまる"}, UTF8 {"こむぎこ"}, UTF8 {"こもじ"},
            UTF8 {"こもち"}, UTF8 {"こもの"}, UTF8 {"こもん"}, UTF8 {"こやく"}, UTF8 {"こやま"}, UTF8 {"こゆう"},
            UTF8 {"こゆび"}, UTF8 {"こよい"}, UTF8 {"こよう"}, UTF8 {"こりる"}, UTF8 {"これくしょん"},
            UTF8 {"ころっけ"}, UTF8 {"こわもて"}, UTF8 {"こわれる"}, UTF8 {"こんいん"}, UTF8 {"こんかい"}, UTF8 {"こんき"},
            UTF8 {"こんしゅう"}, UTF8 {"こんすい"}, UTF8 {"こんだて"}, UTF8 {"こんとん"},
            UTF8 {"こんなん"}, UTF8 {"こんびに"}, UTF8 {"こんぽん"}, UTF8 {"こんまけ"}, UTF8 {"こんや"}, UTF8 {"こんれい"},
            UTF8 {"こんわく"}, UTF8 {"ざいえき"}, UTF8 {"さいかい"},
            UTF8 {"さいきん"}, UTF8 {"ざいげん"}, UTF8 {"ざいこ"}, UTF8 {"さいしょ"}, UTF8 {"さいせい"}, UTF8 {"ざいたく"},
            UTF8 {"ざいちゅう"}, UTF8 {"さいてき"}, UTF8 {"ざいりょう"},
            UTF8 {"さうな"}, UTF8 {"さかいし"}, UTF8 {"さがす"}, UTF8 {"さかな"}, UTF8 {"さかみち"}, UTF8 {"さがる"},
            UTF8 {"さぎょう"}, UTF8 {"さくし"}, UTF8 {"さくひん"}, UTF8 {"さくら"},
            UTF8 {"さこく"}, UTF8 {"さこつ"}, UTF8 {"さずかる"}, UTF8 {"ざせき"}, UTF8 {"さたん"}, UTF8 {"さつえい"},
            UTF8 {"ざつおん"}, UTF8 {"ざっか"}, UTF8 {"ざつがく"},
            UTF8 {"さっきょく"}, UTF8 {"ざっし"}, UTF8 {"さつじん"}, UTF8 {"ざっそう"}, UTF8 {"さつたば"}, UTF8 {"さつまいも"},
            UTF8 {"さてい"}, UTF8 {"さといも"}, UTF8 {"さとう"},
            UTF8 {"さとおや"}, UTF8 {"さとし"}, UTF8 {"さとる"}, UTF8 {"さのう"}, UTF8 {"さばく"}, UTF8 {"さびしい"},
            UTF8 {"さべつ"}, UTF8 {"さほう"}, UTF8 {"さほど"}, UTF8 {"さます"},
            UTF8 {"さみしい"}, UTF8 {"さみだれ"}, UTF8 {"さむけ"}, UTF8 {"さめる"}, UTF8 {"さやえんどう"}, UTF8 {"さゆう"},
            UTF8 {"さよう"}, UTF8 {"さよく"}, UTF8 {"さらだ"}, UTF8 {"ざるそば"},
            UTF8 {"さわやか"}, UTF8 {"さわる"}, UTF8 {"さんいん"}, UTF8 {"さんか"}, UTF8 {"さんきゃく"}, UTF8 {"さんこう"},
            UTF8 {"さんさい"}, UTF8 {"ざんしょ"}, UTF8 {"さんすう"}, UTF8 {"さんせい"},
            UTF8 {"さんそ"}, UTF8 {"さんち"}, UTF8 {"さんま"}, UTF8 {"さんみ"}, UTF8 {"さんらん"}, UTF8 {"しあい"},
            UTF8 {"しあげ"}, UTF8 {"しあさって"}, UTF8 {"しあわせ"}, UTF8 {"しいく"}, UTF8 {"しいん"},
            UTF8 {"しうち"}, UTF8 {"しえい"}, UTF8 {"しおけ"}, UTF8 {"しかい"}, UTF8 {"しかく"}, UTF8 {"じかん"},
            UTF8 {"しごと"}, UTF8 {"しすう"}, UTF8 {"じだい"}, UTF8 {"したうけ"}, UTF8 {"したぎ"},
            UTF8 {"したて"}, UTF8 {"したみ"}, UTF8 {"しちょう"}, UTF8 {"しちりん"}, UTF8 {"しっかり"}, UTF8 {"しつじ"},
            UTF8 {"しつもん"}, UTF8 {"してい"}, UTF8 {"してき"}, UTF8 {"してつ"}, UTF8 {"じてん"},
            UTF8 {"じどう"}, UTF8 {"しなぎれ"}, UTF8 {"しなもの"}, UTF8 {"しなん"}, UTF8 {"しねま"}, UTF8 {"しねん"},
            UTF8 {"しのぐ"}, UTF8 {"しのぶ"}, UTF8 {"しはい"}, UTF8 {"しばかり"},
            UTF8 {"しはつ"}, UTF8 {"しはらい"}, UTF8 {"しはん"}, UTF8 {"しひょう"}, UTF8 {"しふく"}, UTF8 {"じぶん"},
            UTF8 {"しへい"}, UTF8 {"しほう"}, UTF8 {"しほん"}, UTF8 {"しまう"}, UTF8 {"しまる"},
            UTF8 {"しみん"}, UTF8 {"しむける"}, UTF8 {"じむしょ"}, UTF8 {"しめい"}, UTF8 {"しめる"}, UTF8 {"しもん"},
            UTF8 {"しゃいん"}, UTF8 {"しゃうん"}, UTF8 {"しゃおん"}, UTF8 {"じゃがいも"},
            UTF8 {"しやくしょ"}, UTF8 {"しゃくほう"}, UTF8 {"しゃけん"}, UTF8 {"しゃこ"}, UTF8 {"しゃざい"},
            UTF8 {"しゃしん"}, UTF8 {"しゃせん"}, UTF8 {"しゃそう"}, UTF8 {"しゃたい"},
            UTF8 {"しゃちょう"}, UTF8 {"しゃっきん"}, UTF8 {"じゃま"}, UTF8 {"しゃりん"}, UTF8 {"しゃれい"},
            UTF8 {"じゆう"}, UTF8 {"じゅうしょ"}, UTF8 {"しゅくはく"}, UTF8 {"じゅしん"},
            UTF8 {"しゅっせき"}, UTF8 {"しゅみ"}, UTF8 {"しゅらば"}, UTF8 {"じゅんばん"}, UTF8 {"しょうかい"},
            UTF8 {"しょくたく"}, UTF8 {"しょっけん"}, UTF8 {"しょどう"},
            UTF8 {"しょもつ"}, UTF8 {"しらせる"}, UTF8 {"しらべる"}, UTF8 {"しんか"}, UTF8 {"しんこう"}, UTF8 {"じんじゃ"},
            UTF8 {"しんせいじ"}, UTF8 {"しんちく"}, UTF8 {"しんりん"},
            UTF8 {"すあげ"}, UTF8 {"すあし"}, UTF8 {"すあな"}, UTF8 {"ずあん"}, UTF8 {"すいえい"}, UTF8 {"すいか"},
            UTF8 {"すいとう"}, UTF8 {"ずいぶん"}, UTF8 {"すいようび"},
            UTF8 {"すうがく"}, UTF8 {"すうじつ"}, UTF8 {"すうせん"}, UTF8 {"すおどり"}, UTF8 {"すきま"}, UTF8 {"すくう"},
            UTF8 {"すくない"}, UTF8 {"すける"}, UTF8 {"すごい"}, UTF8 {"すこし"},
            UTF8 {"ずさん"}, UTF8 {"すずしい"}, UTF8 {"すすむ"}, UTF8 {"すすめる"}, UTF8 {"すっかり"}, UTF8 {"ずっしり"},
            UTF8 {"ずっと"}, UTF8 {"すてき"}, UTF8 {"すてる"}, UTF8 {"すねる"},
            UTF8 {"すのこ"}, UTF8 {"すはだ"}, UTF8 {"すばらしい"}, UTF8 {"ずひょう"}, UTF8 {"ずぶぬれ"}, UTF8 {"すぶり"},
            UTF8 {"すふれ"}, UTF8 {"すべて"}, UTF8 {"すべる"},
            UTF8 {"ずほう"}, UTF8 {"すぼん"}, UTF8 {"すまい"}, UTF8 {"すめし"}, UTF8 {"すもう"}, UTF8 {"すやき"},
            UTF8 {"すらすら"}, UTF8 {"するめ"}, UTF8 {"すれちがう"}, UTF8 {"すろっと"},
            UTF8 {"すわる"}, UTF8 {"すんぜん"}, UTF8 {"すんぽう"}, UTF8 {"せあぶら"}, UTF8 {"せいかつ"}, UTF8 {"せいげん"},
            UTF8 {"せいじ"}, UTF8 {"せいよう"}, UTF8 {"せおう"},
            UTF8 {"せかいかん"}, UTF8 {"せきにん"}, UTF8 {"せきむ"}, UTF8 {"せきゆ"}, UTF8 {"せきらんうん"}, UTF8 {"せけん"},
            UTF8 {"せこう"}, UTF8 {"せすじ"}, UTF8 {"せたい"}, UTF8 {"せたけ"},
            UTF8 {"せっかく"}, UTF8 {"せっきゃく"}, UTF8 {"ぜっく"}, UTF8 {"せっけん"}, UTF8 {"せっこつ"}, UTF8 {"せっさたくま"},
            UTF8 {"せつぞく"}, UTF8 {"せつだん"}, UTF8 {"せつでん"},
            UTF8 {"せっぱん"}, UTF8 {"せつび"}, UTF8 {"せつぶん"}, UTF8 {"せつめい"}, UTF8 {"せつりつ"}, UTF8 {"せなか"},
            UTF8 {"せのび"}, UTF8 {"せはば"}, UTF8 {"せびろ"}, UTF8 {"せぼね"},
            UTF8 {"せまい"}, UTF8 {"せまる"}, UTF8 {"せめる"}, UTF8 {"せもたれ"}, UTF8 {"せりふ"}, UTF8 {"ぜんあく"},
            UTF8 {"せんい"}, UTF8 {"せんえい"}, UTF8 {"せんか"}, UTF8 {"せんきょ"}, UTF8 {"せんく"},
            UTF8 {"せんげん"}, UTF8 {"ぜんご"}, UTF8 {"せんさい"}, UTF8 {"せんしゅ"}, UTF8 {"せんすい"}, UTF8 {"せんせい"},
            UTF8 {"せんぞ"}, UTF8 {"せんたく"}, UTF8 {"せんちょう"},
            UTF8 {"せんてい"}, UTF8 {"せんとう"}, UTF8 {"せんぬき"}, UTF8 {"せんねん"}, UTF8 {"せんぱい"}, UTF8 {"ぜんぶ"},
            UTF8 {"ぜんぽう"}, UTF8 {"せんむ"}, UTF8 {"せんめんじょ"},
            UTF8 {"せんもん"}, UTF8 {"せんやく"}, UTF8 {"せんゆう"}, UTF8 {"せんよう"}, UTF8 {"ぜんら"}, UTF8 {"ぜんりゃく"},
            UTF8 {"せんれい"}, UTF8 {"せんろ"}, UTF8 {"そあく"},
            UTF8 {"そいとげる"}, UTF8 {"そいね"}, UTF8 {"そうがんきょう"}, UTF8 {"そうき"}, UTF8 {"そうご"}, UTF8 {"そうしん"},
            UTF8 {"そうだん"}, UTF8 {"そうなん"}, UTF8 {"そうび"},
            UTF8 {"そうめん"}, UTF8 {"そうり"}, UTF8 {"そえもの"}, UTF8 {"そえん"}, UTF8 {"そがい"}, UTF8 {"そげき"},
            UTF8 {"そこう"}, UTF8 {"そこそこ"}, UTF8 {"そざい"}, UTF8 {"そしな"}, UTF8 {"そせい"},
            UTF8 {"そせん"}, UTF8 {"そそぐ"}, UTF8 {"そだてる"}, UTF8 {"そつう"}, UTF8 {"そつえん"}, UTF8 {"そっかん"},
            UTF8 {"そつぎょう"}, UTF8 {"そっけつ"}, UTF8 {"そっこう"}, UTF8 {"そっせん"},
            UTF8 {"そっと"}, UTF8 {"そとがわ"}, UTF8 {"そとづら"}, UTF8 {"そなえる"}, UTF8 {"そなた"}, UTF8 {"そふぼ"},
            UTF8 {"そぼく"}, UTF8 {"そぼろ"}, UTF8 {"そまつ"}, UTF8 {"そまる"},
            UTF8 {"そむく"}, UTF8 {"そむりえ"}, UTF8 {"そめる"}, UTF8 {"そもそも"}, UTF8 {"そよかぜ"}, UTF8 {"そらまめ"},
            UTF8 {"そろう"}, UTF8 {"そんかい"}, UTF8 {"そんけい"}, UTF8 {"そんざい"},
            UTF8 {"そんしつ"}, UTF8 {"そんぞく"}, UTF8 {"そんちょう"}, UTF8 {"ぞんび"}, UTF8 {"ぞんぶん"}, UTF8 {"そんみん"},
            UTF8 {"たあい"}, UTF8 {"たいいん"}, UTF8 {"たいうん"},
            UTF8 {"たいえき"}, UTF8 {"たいおう"}, UTF8 {"だいがく"}, UTF8 {"たいき"}, UTF8 {"たいぐう"}, UTF8 {"たいけん"},
            UTF8 {"たいこ"}, UTF8 {"たいざい"}, UTF8 {"だいじょうぶ"},
            UTF8 {"だいすき"}, UTF8 {"たいせつ"}, UTF8 {"たいそう"}, UTF8 {"だいたい"}, UTF8 {"たいちょう"}, UTF8 {"たいてい"},
            UTF8 {"だいどころ"}, UTF8 {"たいない"}, UTF8 {"たいねつ"},
            UTF8 {"たいのう"}, UTF8 {"たいはん"}, UTF8 {"だいひょう"}, UTF8 {"たいふう"}, UTF8 {"たいへん"}, UTF8 {"たいほ"},
            UTF8 {"たいまつばな"}, UTF8 {"たいみんぐ"}, UTF8 {"たいむ"},
            UTF8 {"たいめん"}, UTF8 {"たいやき"}, UTF8 {"たいよう"}, UTF8 {"たいら"}, UTF8 {"たいりょく"}, UTF8 {"たいる"},
            UTF8 {"たいわん"}, UTF8 {"たうえ"}, UTF8 {"たえる"}, UTF8 {"たおす"}, UTF8 {"たおる"},
            UTF8 {"たおれる"}, UTF8 {"たかい"}, UTF8 {"たかね"}, UTF8 {"たきび"}, UTF8 {"たくさん"}, UTF8 {"たこく"},
            UTF8 {"たこやき"}, UTF8 {"たさい"}, UTF8 {"たしざん"}, UTF8 {"だじゃれ"},
            UTF8 {"たすける"}, UTF8 {"たずさわる"}, UTF8 {"たそがれ"}, UTF8 {"たたかう"}, UTF8 {"たたく"}, UTF8 {"ただしい"},
            UTF8 {"たたみ"}, UTF8 {"たちばな"}, UTF8 {"だっかい"},
            UTF8 {"だっきゃく"}, UTF8 {"だっこ"}, UTF8 {"だっしゅつ"}, UTF8 {"だったい"}, UTF8 {"たてる"}, UTF8 {"たとえる"},
            UTF8 {"たなばた"}, UTF8 {"たにん"}, UTF8 {"たぬき"},
            UTF8 {"たのしみ"}, UTF8 {"たはつ"}, UTF8 {"たぶん"}, UTF8 {"たべる"}, UTF8 {"たぼう"}, UTF8 {"たまご"},
            UTF8 {"たまる"}, UTF8 {"だむる"}, UTF8 {"ためいき"}, UTF8 {"ためす"},
            UTF8 {"ためる"}, UTF8 {"たもつ"}, UTF8 {"たやすい"}, UTF8 {"たよる"}, UTF8 {"たらす"}, UTF8 {"たりきほんがん"},
            UTF8 {"たりょう"}, UTF8 {"たりる"}, UTF8 {"たると"}, UTF8 {"たれる"},
            UTF8 {"たれんと"}, UTF8 {"たろっと"}, UTF8 {"たわむれる"}, UTF8 {"だんあつ"}, UTF8 {"たんい"}, UTF8 {"たんおん"},
            UTF8 {"たんか"}, UTF8 {"たんき"}, UTF8 {"たんけん"}, UTF8 {"たんご"},
            UTF8 {"たんさん"}, UTF8 {"たんじょうび"}, UTF8 {"だんせい"}, UTF8 {"たんそく"}, UTF8 {"たんたい"}, UTF8 {"だんち"},
            UTF8 {"たんてい"}, UTF8 {"たんとう"}, UTF8 {"だんな"},
            UTF8 {"たんにん"}, UTF8 {"だんねつ"}, UTF8 {"たんのう"}, UTF8 {"たんぴん"}, UTF8 {"だんぼう"}, UTF8 {"たんまつ"},
            UTF8 {"たんめい"}, UTF8 {"だんれつ"}, UTF8 {"だんろ"},
            UTF8 {"だんわ"}, UTF8 {"ちあい"}, UTF8 {"ちあん"}, UTF8 {"ちいき"}, UTF8 {"ちいさい"}, UTF8 {"ちえん"},
            UTF8 {"ちかい"}, UTF8 {"ちから"}, UTF8 {"ちきゅう"}, UTF8 {"ちきん"}, UTF8 {"ちけいず"},
            UTF8 {"ちけん"}, UTF8 {"ちこく"}, UTF8 {"ちさい"}, UTF8 {"ちしき"}, UTF8 {"ちしりょう"}, UTF8 {"ちせい"},
            UTF8 {"ちそう"}, UTF8 {"ちたい"}, UTF8 {"ちたん"}, UTF8 {"ちちおや"}, UTF8 {"ちつじょ"},
            UTF8 {"ちてき"}, UTF8 {"ちてん"}, UTF8 {"ちぬき"}, UTF8 {"ちぬり"}, UTF8 {"ちのう"}, UTF8 {"ちひょう"},
            UTF8 {"ちへいせん"}, UTF8 {"ちほう"}, UTF8 {"ちまた"}, UTF8 {"ちみつ"}, UTF8 {"ちみどろ"},
            UTF8 {"ちめいど"}, UTF8 {"ちゃんこなべ"}, UTF8 {"ちゅうい"}, UTF8 {"ちゆりょく"}, UTF8 {"ちょうし"},
            UTF8 {"ちょさくけん"}, UTF8 {"ちらし"}, UTF8 {"ちらみ"}, UTF8 {"ちりがみ"},
            UTF8 {"ちりょう"}, UTF8 {"ちるど"}, UTF8 {"ちわわ"}, UTF8 {"ちんたい"}, UTF8 {"ちんもく"}, UTF8 {"ついか"},
            UTF8 {"ついたち"}, UTF8 {"つうか"}, UTF8 {"つうじょう"}, UTF8 {"つうはん"}, UTF8 {"つうわ"},
            UTF8 {"つかう"}, UTF8 {"つかれる"}, UTF8 {"つくね"}, UTF8 {"つくる"}, UTF8 {"つけね"}, UTF8 {"つける"},
            UTF8 {"つごう"}, UTF8 {"つたえる"}, UTF8 {"つづく"}, UTF8 {"つつじ"}, UTF8 {"つつむ"},
            UTF8 {"つとめる"}, UTF8 {"つながる"}, UTF8 {"つなみ"}, UTF8 {"つねづね"}, UTF8 {"つのる"}, UTF8 {"つぶす"},
            UTF8 {"つまらない"}, UTF8 {"つまる"}, UTF8 {"つみき"}, UTF8 {"つめたい"}, UTF8 {"つもり"},
            UTF8 {"つもる"}, UTF8 {"つよい"}, UTF8 {"つるぼ"}, UTF8 {"つるみく"}, UTF8 {"つわもの"}, UTF8 {"つわり"},
            UTF8 {"てあし"}, UTF8 {"てあて"}, UTF8 {"てあみ"}, UTF8 {"ていおん"}, UTF8 {"ていか"},
            UTF8 {"ていき"}, UTF8 {"ていけい"}, UTF8 {"ていこく"}, UTF8 {"ていさつ"}, UTF8 {"ていし"}, UTF8 {"ていせい"},
            UTF8 {"ていたい"}, UTF8 {"ていど"}, UTF8 {"ていねい"}, UTF8 {"ていひょう"},
            UTF8 {"ていへん"}, UTF8 {"ていぼう"}, UTF8 {"てうち"}, UTF8 {"ておくれ"}, UTF8 {"てきとう"}, UTF8 {"てくび"},
            UTF8 {"でこぼこ"}, UTF8 {"てさぎょう"}, UTF8 {"てさげ"}, UTF8 {"てすり"}, UTF8 {"てそう"},
            UTF8 {"てちがい"}, UTF8 {"てちょう"}, UTF8 {"てつがく"}, UTF8 {"てつづき"}, UTF8 {"でっぱ"}, UTF8 {"てつぼう"},
            UTF8 {"てつや"}, UTF8 {"でぬかえ"}, UTF8 {"てぬき"}, UTF8 {"てぬぐい"},
            UTF8 {"てのひら"}, UTF8 {"てはい"}, UTF8 {"てぶくろ"}, UTF8 {"てふだ"}, UTF8 {"てほどき"}, UTF8 {"てほん"},
            UTF8 {"てまえ"}, UTF8 {"てまきずし"}, UTF8 {"てみじか"}, UTF8 {"てみやげ"}, UTF8 {"てらす"},
            UTF8 {"てれび"}, UTF8 {"てわけ"}, UTF8 {"てわたし"}, UTF8 {"でんあつ"}, UTF8 {"てんいん"}, UTF8 {"てんかい"},
            UTF8 {"てんき"}, UTF8 {"てんぐ"}, UTF8 {"てんけん"}, UTF8 {"てんごく"}, UTF8 {"てんさい"},
            UTF8 {"てんし"}, UTF8 {"てんすう"}, UTF8 {"でんち"}, UTF8 {"てんてき"}, UTF8 {"てんとう"}, UTF8 {"てんない"},
            UTF8 {"てんぷら"}, UTF8 {"てんぼうだい"}, UTF8 {"てんめつ"}, UTF8 {"てんらんかい"},
            UTF8 {"でんりょく"}, UTF8 {"でんわ"}, UTF8 {"どあい"}, UTF8 {"といれ"}, UTF8 {"どうかん"}, UTF8 {"とうきゅう"},
            UTF8 {"どうぐ"}, UTF8 {"とうし"}, UTF8 {"とうむぎ"}, UTF8 {"とおい"}, UTF8 {"とおか"},
            UTF8 {"とおく"}, UTF8 {"とおす"}, UTF8 {"とおる"}, UTF8 {"とかい"}, UTF8 {"とかす"}, UTF8 {"ときおり"},
            UTF8 {"ときどき"}, UTF8 {"とくい"}, UTF8 {"とくしゅう"}, UTF8 {"とくてん"}, UTF8 {"とくに"},
            UTF8 {"とくべつ"}, UTF8 {"とけい"}, UTF8 {"とける"}, UTF8 {"とこや"}, UTF8 {"とさか"}, UTF8 {"としょかん"},
            UTF8 {"とそう"}, UTF8 {"とたん"}, UTF8 {"とちゅう"}, UTF8 {"とっきゅう"}, UTF8 {"とっくん"},
            UTF8 {"とつぜん"}, UTF8 {"とつにゅう"}, UTF8 {"とどける"}, UTF8 {"ととのえる"}, UTF8 {"とない"}, UTF8 {"となえる"},
            UTF8 {"となり"}, UTF8 {"とのさま"}, UTF8 {"とばす"}, UTF8 {"どぶがわ"},
            UTF8 {"とほう"}, UTF8 {"とまる"}, UTF8 {"とめる"}, UTF8 {"ともだち"}, UTF8 {"ともる"}, UTF8 {"どようび"},
            UTF8 {"とらえる"}, UTF8 {"とんかつ"}, UTF8 {"どんぶり"}, UTF8 {"ないかく"}, UTF8 {"ないこう"},
            UTF8 {"ないしょ"}, UTF8 {"ないす"}, UTF8 {"ないせん"}, UTF8 {"ないそう"}, UTF8 {"なおす"}, UTF8 {"ながい"},
            UTF8 {"なくす"}, UTF8 {"なげる"}, UTF8 {"なこうど"}, UTF8 {"なさけ"}, UTF8 {"なたでここ"},
            UTF8 {"なっとう"}, UTF8 {"なつやすみ"}, UTF8 {"ななおし"}, UTF8 {"なにごと"}, UTF8 {"なにもの"}, UTF8 {"なにわ"},
            UTF8 {"なのか"}, UTF8 {"なふだ"}, UTF8 {"なまいき"}, UTF8 {"なまえ"}, UTF8 {"なまみ"},
            UTF8 {"なみだ"}, UTF8 {"なめらか"}, UTF8 {"なめる"}, UTF8 {"なやむ"}, UTF8 {"ならう"}, UTF8 {"ならび"},
            UTF8 {"ならぶ"}, UTF8 {"なれる"}, UTF8 {"なわとび"}, UTF8 {"なわばり"}, UTF8 {"にあう"},
            UTF8 {"にいがた"}, UTF8 {"にうけ"}, UTF8 {"におい"}, UTF8 {"にかい"}, UTF8 {"にがて"}, UTF8 {"にきび"},
            UTF8 {"にくしみ"}, UTF8 {"にくまん"}, UTF8 {"にげる"}, UTF8 {"にさんかたんそ"}, UTF8 {"にしき"},
            UTF8 {"にせもの"}, UTF8 {"にちじょう"}, UTF8 {"にちようび"}, UTF8 {"にっか"}, UTF8 {"にっき"}, UTF8 {"にっけい"},
            UTF8 {"にっこう"}, UTF8 {"にっさん"}, UTF8 {"にっしょく"}, UTF8 {"にっすう"},
            UTF8 {"にっせき"}, UTF8 {"にってい"}, UTF8 {"になう"}, UTF8 {"にほん"}, UTF8 {"にまめ"}, UTF8 {"にもつ"},
            UTF8 {"にやり"}, UTF8 {"にゅういん"}, UTF8 {"にりんしゃ"}, UTF8 {"にわとり"}, UTF8 {"にんい"},
            UTF8 {"にんか"}, UTF8 {"にんき"}, UTF8 {"にんげん"}, UTF8 {"にんしき"}, UTF8 {"にんずう"}, UTF8 {"にんそう"},
            UTF8 {"にんたい"}, UTF8 {"にんち"}, UTF8 {"にんてい"}, UTF8 {"にんにく"}, UTF8 {"にんぷ"},
            UTF8 {"にんまり"}, UTF8 {"にんむ"}, UTF8 {"にんめい"}, UTF8 {"にんよう"}, UTF8 {"ぬいくぎ"}, UTF8 {"ぬかす"},
            UTF8 {"ぬぐいとる"}, UTF8 {"ぬぐう"}, UTF8 {"ぬくもり"}, UTF8 {"ぬすむ"},
            UTF8 {"ぬまえび"}, UTF8 {"ぬめり"}, UTF8 {"ぬらす"}, UTF8 {"ぬんちゃく"}, UTF8 {"ねあげ"}, UTF8 {"ねいき"},
            UTF8 {"ねいる"}, UTF8 {"ねいろ"}, UTF8 {"ねぐせ"}, UTF8 {"ねくたい"}, UTF8 {"ねくら"},
            UTF8 {"ねこぜ"}, UTF8 {"ねこむ"}, UTF8 {"ねさげ"}, UTF8 {"ねすごす"}, UTF8 {"ねそべる"}, UTF8 {"ねだん"},
            UTF8 {"ねつい"}, UTF8 {"ねっしん"}, UTF8 {"ねつぞう"}, UTF8 {"ねったいぎょ"},
            UTF8 {"ねぶそく"}, UTF8 {"ねふだ"}, UTF8 {"ねぼう"}, UTF8 {"ねほりはほり"}, UTF8 {"ねまき"}, UTF8 {"ねまわし"},
            UTF8 {"ねみみ"}, UTF8 {"ねむい"}, UTF8 {"ねむたい"}, UTF8 {"ねもと"}, UTF8 {"ねらう"},
            UTF8 {"ねわざ"}, UTF8 {"ねんいり"}, UTF8 {"ねんおし"}, UTF8 {"ねんかん"}, UTF8 {"ねんきん"}, UTF8 {"ねんぐ"},
            UTF8 {"ねんざ"}, UTF8 {"ねんし"}, UTF8 {"ねんちゃく"}, UTF8 {"ねんど"}, UTF8 {"ねんぴ"},
            UTF8 {"ねんぶつ"}, UTF8 {"ねんまつ"}, UTF8 {"ねんりょう"}, UTF8 {"ねんれい"}, UTF8 {"のいず"}, UTF8 {"のおづま"},
            UTF8 {"のがす"}, UTF8 {"のきなみ"}, UTF8 {"のこぎり"}, UTF8 {"のこす"},
            UTF8 {"のこる"}, UTF8 {"のせる"}, UTF8 {"のぞく"}, UTF8 {"のぞむ"}, UTF8 {"のたまう"}, UTF8 {"のちほど"},
            UTF8 {"のっく"}, UTF8 {"のばす"}, UTF8 {"のはら"}, UTF8 {"のべる"}, UTF8 {"のぼる"}, UTF8 {"のみもの"}, UTF8 {"のやま"},
            UTF8 {"のらいぬ"}, UTF8 {"のらねこ"}, UTF8 {"のりもの"}, UTF8 {"のりゆき"}, UTF8 {"のれん"}, UTF8 {"のんき"},
            UTF8 {"ばあい"}, UTF8 {"はあく"}, UTF8 {"ばあさん"}, UTF8 {"ばいか"}, UTF8 {"ばいく"}, UTF8 {"はいけん"},
            UTF8 {"はいご"}, UTF8 {"はいしん"}, UTF8 {"はいすい"}, UTF8 {"はいせん"}, UTF8 {"はいそう"}, UTF8 {"はいち"},
            UTF8 {"ばいばい"}, UTF8 {"はいれつ"}, UTF8 {"はえる"}, UTF8 {"はおる"}, UTF8 {"はかい"}, UTF8 {"ばかり"}, UTF8 {"はかる"},
            UTF8 {"はくしゅ"}, UTF8 {"はけん"}, UTF8 {"はこぶ"}, UTF8 {"はさみ"}, UTF8 {"はさん"}, UTF8 {"はしご"},
            UTF8 {"ばしょ"}, UTF8 {"はしる"}, UTF8 {"はせる"}, UTF8 {"ぱそこん"}, UTF8 {"はそん"}, UTF8 {"はたん"},
            UTF8 {"はちみつ"},
            UTF8 {"はつおん"}, UTF8 {"はっかく"}, UTF8 {"はづき"}, UTF8 {"はっきり"}, UTF8 {"はっくつ"}, UTF8 {"はっけん"},
            UTF8 {"はっこう"}, UTF8 {"はっさん"}, UTF8 {"はっしん"}, UTF8 {"はったつ"}, UTF8 {"はっちゅう"}, UTF8 {"はってん"},
            UTF8 {"はっぴょう"}, UTF8 {"はっぽう"}, UTF8 {"はなす"}, UTF8 {"はなび"}, UTF8 {"はにかむ"}, UTF8 {"はぶらし"},
            UTF8 {"はみがき"}, UTF8 {"はむかう"}, UTF8 {"はめつ"}, UTF8 {"はやい"}, UTF8 {"はやし"}, UTF8 {"はらう"},
            UTF8 {"はろうぃん"}, UTF8 {"はわい"}, UTF8 {"はんい"}, UTF8 {"はんえい"}, UTF8 {"はんおん"}, UTF8 {"はんかく"},
            UTF8 {"はんきょう"}, UTF8 {"ばんぐみ"}, UTF8 {"はんこ"}, UTF8 {"はんしゃ"}, UTF8 {"はんすう"}, UTF8 {"はんだん"},
            UTF8 {"ぱんち"}, UTF8 {"ぱんつ"}, UTF8 {"はんてい"}, UTF8 {"はんとし"}, UTF8 {"はんのう"}, UTF8 {"はんぱ"},
            UTF8 {"はんぶん"}, UTF8 {"はんぺん"}, UTF8 {"はんぼうき"}, UTF8 {"はんめい"}, UTF8 {"はんらん"}, UTF8 {"はんろん"},
            UTF8 {"ひいき"}, UTF8 {"ひうん"}, UTF8 {"ひえる"}, UTF8 {"ひかく"}, UTF8 {"ひかり"}, UTF8 {"ひかる"},
            UTF8 {"ひかん"}, UTF8 {"ひくい"}, UTF8 {"ひけつ"}, UTF8 {"ひこうき"}, UTF8 {"ひこく"}, UTF8 {"ひさい"},
            UTF8 {"ひさしぶり"},
            UTF8 {"ひさん"}, UTF8 {"びじゅつかん"}, UTF8 {"ひしょ"}, UTF8 {"ひそか"}, UTF8 {"ひそむ"}, UTF8 {"ひたむき"},
            UTF8 {"ひだり"}, UTF8 {"ひたる"}, UTF8 {"ひつぎ"}, UTF8 {"ひっこし"}, UTF8 {"ひっし"}, UTF8 {"ひつじゅひん"},
            UTF8 {"ひっす"}, UTF8 {"ひつぜん"}, UTF8 {"ぴったり"}, UTF8 {"ぴっちり"}, UTF8 {"ひつよう"}, UTF8 {"ひてい"},
            UTF8 {"ひとごみ"}, UTF8 {"ひなまつり"}, UTF8 {"ひなん"}, UTF8 {"ひねる"}, UTF8 {"ひはん"}, UTF8 {"ひびく"},
            UTF8 {"ひひょう"}, UTF8 {"ひほう"}, UTF8 {"ひまわり"}, UTF8 {"ひまん"}, UTF8 {"ひみつ"}, UTF8 {"ひめい"},
            UTF8 {"ひめじし"}, UTF8 {"ひやけ"}, UTF8 {"ひやす"}, UTF8 {"ひよう"}, UTF8 {"びょうき"}, UTF8 {"ひらがな"},
            UTF8 {"ひらく"},
            UTF8 {"ひりつ"}, UTF8 {"ひりょう"}, UTF8 {"ひるま"}, UTF8 {"ひるやすみ"}, UTF8 {"ひれい"}, UTF8 {"ひろい"},
            UTF8 {"ひろう"}, UTF8 {"ひろき"}, UTF8 {"ひろゆき"}, UTF8 {"ひんかく"}, UTF8 {"ひんけつ"}, UTF8 {"ひんこん"},
            UTF8 {"ひんしゅ"}, UTF8 {"ひんそう"}, UTF8 {"ぴんち"}, UTF8 {"ひんぱん"}, UTF8 {"びんぼう"}, UTF8 {"ふあん"},
            UTF8 {"ふいうち"}, UTF8 {"ふうけい"}, UTF8 {"ふうせん"}, UTF8 {"ぷうたろう"}, UTF8 {"ふうとう"}, UTF8 {"ふうふ"},
            UTF8 {"ふえる"}, UTF8 {"ふおん"}, UTF8 {"ふかい"}, UTF8 {"ふきん"}, UTF8 {"ふくざつ"}, UTF8 {"ふくぶくろ"},
            UTF8 {"ふこう"}, UTF8 {"ふさい"}, UTF8 {"ふしぎ"}, UTF8 {"ふじみ"}, UTF8 {"ふすま"}, UTF8 {"ふせい"},
            UTF8 {"ふせぐ"},
            UTF8 {"ふそく"}, UTF8 {"ぶたにく"}, UTF8 {"ふたん"}, UTF8 {"ふちょう"}, UTF8 {"ふつう"}, UTF8 {"ふつか"},
            UTF8 {"ふっかつ"}, UTF8 {"ふっき"}, UTF8 {"ふっこく"}, UTF8 {"ぶどう"}, UTF8 {"ふとる"}, UTF8 {"ふとん"},
            UTF8 {"ふのう"},
            UTF8 {"ふはい"}, UTF8 {"ふひょう"}, UTF8 {"ふへん"}, UTF8 {"ふまん"}, UTF8 {"ふみん"}, UTF8 {"ふめつ"},
            UTF8 {"ふめん"}, UTF8 {"ふよう"}, UTF8 {"ふりこ"}, UTF8 {"ふりる"}, UTF8 {"ふるい"}, UTF8 {"ふんいき"},
            UTF8 {"ぶんがく"},
            UTF8 {"ぶんぐ"}, UTF8 {"ふんしつ"}, UTF8 {"ぶんせき"}, UTF8 {"ふんそう"}, UTF8 {"ぶんぽう"}, UTF8 {"へいあん"},
            UTF8 {"へいおん"}, UTF8 {"へいがい"}, UTF8 {"へいき"}, UTF8 {"へいげん"}, UTF8 {"へいこう"}, UTF8 {"へいさ"},
            UTF8 {"へいしゃ"}, UTF8 {"へいせつ"}, UTF8 {"へいそ"}, UTF8 {"へいたく"}, UTF8 {"へいてん"}, UTF8 {"へいねつ"},
            UTF8 {"へいわ"}, UTF8 {"へきが"}, UTF8 {"へこむ"}, UTF8 {"べにいろ"}, UTF8 {"べにしょうが"}, UTF8 {"へらす"},
            UTF8 {"へんかん"}, UTF8 {"べんきょう"}, UTF8 {"べんごし"}, UTF8 {"へんさい"}, UTF8 {"へんたい"}, UTF8 {"べんり"},
            UTF8 {"ほあん"}, UTF8 {"ほいく"}, UTF8 {"ぼうぎょ"}, UTF8 {"ほうこく"}, UTF8 {"ほうそう"}, UTF8 {"ほうほう"},
            UTF8 {"ほうもん"}, UTF8 {"ほうりつ"}, UTF8 {"ほえる"}, UTF8 {"ほおん"}, UTF8 {"ほかん"}, UTF8 {"ほきょう"},
            UTF8 {"ぼきん"}, UTF8 {"ほくろ"}, UTF8 {"ほけつ"}, UTF8 {"ほけん"}, UTF8 {"ほこう"}, UTF8 {"ほこる"}, UTF8 {"ほしい"},
            UTF8 {"ほしつ"}, UTF8 {"ほしゅ"}, UTF8 {"ほしょう"}, UTF8 {"ほせい"}, UTF8 {"ほそい"}, UTF8 {"ほそく"},
            UTF8 {"ほたて"}, UTF8 {"ほたる"}, UTF8 {"ぽちぶくろ"}, UTF8 {"ほっきょく"}, UTF8 {"ほっさ"}, UTF8 {"ほったん"},
            UTF8 {"ほとんど"}, UTF8 {"ほめる"}, UTF8 {"ほんい"}, UTF8 {"ほんき"}, UTF8 {"ほんけ"}, UTF8 {"ほんしつ"},
            UTF8 {"ほんやく"}, UTF8 {"まいにち"}, UTF8 {"まかい"}, UTF8 {"まかせる"}, UTF8 {"まがる"}, UTF8 {"まける"},
            UTF8 {"まこと"},
            UTF8 {"まさつ"}, UTF8 {"まじめ"}, UTF8 {"ますく"}, UTF8 {"まぜる"}, UTF8 {"まつり"}, UTF8 {"まとめ"},
            UTF8 {"まなぶ"}, UTF8 {"まぬけ"}, UTF8 {"まねく"}, UTF8 {"まほう"}, UTF8 {"まもる"}, UTF8 {"まゆげ"},
            UTF8 {"まよう"}, UTF8 {"まろやか"},
            UTF8 {"まわす"}, UTF8 {"まわり"}, UTF8 {"まわる"}, UTF8 {"まんが"}, UTF8 {"まんきつ"}, UTF8 {"まんぞく"},
            UTF8 {"まんなか"}, UTF8 {"みいら"}, UTF8 {"みうち"}, UTF8 {"みえる"}, UTF8 {"みがく"}, UTF8 {"みかた"}, UTF8 {"みかん"},
            UTF8 {"みけん"}, UTF8 {"みこん"}, UTF8 {"みじかい"}, UTF8 {"みすい"}, UTF8 {"みすえる"}, UTF8 {"みせる"},
            UTF8 {"みっか"}, UTF8 {"みつかる"}, UTF8 {"みつける"}, UTF8 {"みてい"}, UTF8 {"みとめる"}, UTF8 {"みなと"},
            UTF8 {"みなみかさい"}, UTF8 {"みねらる"}, UTF8 {"みのう"}, UTF8 {"みのがす"}, UTF8 {"みほん"}, UTF8 {"みもと"},
            UTF8 {"みやげ"}, UTF8 {"みらい"}, UTF8 {"みりょく"}, UTF8 {"みわく"}, UTF8 {"みんか"}, UTF8 {"みんぞく"},
            UTF8 {"むいか"}, UTF8 {"むえき"}, UTF8 {"むえん"}, UTF8 {"むかい"}, UTF8 {"むかう"}, UTF8 {"むかえ"},
            UTF8 {"むかし"}, UTF8 {"むぎちゃ"}, UTF8 {"むける"}, UTF8 {"むげん"}, UTF8 {"むさぼる"}, UTF8 {"むしあつい"},
            UTF8 {"むしば"},
            UTF8 {"むじゅん"}, UTF8 {"むしろ"}, UTF8 {"むすう"}, UTF8 {"むすこ"}, UTF8 {"むすぶ"}, UTF8 {"むすめ"},
            UTF8 {"むせる"}, UTF8 {"むせん"}, UTF8 {"むちゅう"}, UTF8 {"むなしい"}, UTF8 {"むのう"}, UTF8 {"むやみ"}, UTF8 {"むよう"},
            UTF8 {"むらさき"}, UTF8 {"むりょう"}, UTF8 {"むろん"}, UTF8 {"めいあん"}, UTF8 {"めいうん"}, UTF8 {"めいえん"},
            UTF8 {"めいかく"}, UTF8 {"めいきょく"}, UTF8 {"めいさい"}, UTF8 {"めいし"}, UTF8 {"めいそう"}, UTF8 {"めいぶつ"},
            UTF8 {"めいれい"}, UTF8 {"めいわく"}, UTF8 {"めぐまれる"}, UTF8 {"めざす"}, UTF8 {"めした"}, UTF8 {"めずらしい"},
            UTF8 {"めだつ"}, UTF8 {"めまい"}, UTF8 {"めやす"}, UTF8 {"めんきょ"}, UTF8 {"めんせき"}, UTF8 {"めんどう"},
            UTF8 {"もうしあげる"}, UTF8 {"もうどうけん"}, UTF8 {"もえる"}, UTF8 {"もくし"}, UTF8 {"もくてき"}, UTF8 {"もくようび"},
            UTF8 {"もちろん"}, UTF8 {"もどる"}, UTF8 {"もらう"}, UTF8 {"もんく"}, UTF8 {"もんだい"}, UTF8 {"やおや"},
            UTF8 {"やける"}, UTF8 {"やさい"}, UTF8 {"やさしい"}, UTF8 {"やすい"}, UTF8 {"やすたろう"}, UTF8 {"やすみ"},
            UTF8 {"やせる"}, UTF8 {"やそう"}, UTF8 {"やたい"}, UTF8 {"やちん"}, UTF8 {"やっと"}, UTF8 {"やっぱり"},
            UTF8 {"やぶる"},
            UTF8 {"やめる"}, UTF8 {"ややこしい"}, UTF8 {"やよい"}, UTF8 {"やわらかい"}, UTF8 {"ゆうき"},
            UTF8 {"ゆうびんきょく"}, UTF8 {"ゆうべ"}, UTF8 {"ゆうめい"}, UTF8 {"ゆけつ"}, UTF8 {"ゆしゅつ"}, UTF8 {"ゆせん"},
            UTF8 {"ゆそう"},
            UTF8 {"ゆたか"}, UTF8 {"ゆちゃく"}, UTF8 {"ゆでる"}, UTF8 {"ゆにゅう"}, UTF8 {"ゆびわ"}, UTF8 {"ゆらい"},
            UTF8 {"ゆれる"}, UTF8 {"ようい"}, UTF8 {"ようか"}, UTF8 {"ようきゅう"}, UTF8 {"ようじ"}, UTF8 {"ようす"},
            UTF8 {"ようちえん"},
            UTF8 {"よかぜ"}, UTF8 {"よかん"}, UTF8 {"よきん"}, UTF8 {"よくせい"}, UTF8 {"よくぼう"}, UTF8 {"よけい"},
            UTF8 {"よごれる"}, UTF8 {"よさん"}, UTF8 {"よしゅう"}, UTF8 {"よそう"}, UTF8 {"よそく"}, UTF8 {"よっか"},
            UTF8 {"よてい"},
            UTF8 {"よどがわく"}, UTF8 {"よねつ"}, UTF8 {"よやく"}, UTF8 {"よゆう"}, UTF8 {"よろこぶ"}, UTF8 {"よろしい"},
            UTF8 {"らいう"}, UTF8 {"らくがき"}, UTF8 {"らくご"}, UTF8 {"らくさつ"}, UTF8 {"らくだ"}, UTF8 {"らしんばん"},
            UTF8 {"らせん"}, UTF8 {"らぞく"}, UTF8 {"らたい"}, UTF8 {"らっか"}, UTF8 {"られつ"}, UTF8 {"りえき"},
            UTF8 {"りかい"}, UTF8 {"りきさく"}, UTF8 {"りきせつ"}, UTF8 {"りくぐん"}, UTF8 {"りくつ"}, UTF8 {"りけん"},
            UTF8 {"りこう"},
            UTF8 {"りせい"}, UTF8 {"りそう"}, UTF8 {"りそく"}, UTF8 {"りてん"}, UTF8 {"りねん"}, UTF8 {"りゆう"},
            UTF8 {"りゅうがく"}, UTF8 {"りよう"}, UTF8 {"りょうり"}, UTF8 {"りょかん"}, UTF8 {"りょくちゃ"}, UTF8 {"りょこう"},
            UTF8 {"りりく"}, UTF8 {"りれき"}, UTF8 {"りろん"}, UTF8 {"りんご"}, UTF8 {"るいけい"}, UTF8 {"るいさい"},
            UTF8 {"るいじ"}, UTF8 {"るいせき"}, UTF8 {"るすばん"}, UTF8 {"るりがわら"}, UTF8 {"れいかん"}, UTF8 {"れいぎ"},
            UTF8 {"れいせい"}, UTF8 {"れいぞうこ"}, UTF8 {"れいとう"}, UTF8 {"れいぼう"}, UTF8 {"れきし"}, UTF8 {"れきだい"},
            UTF8 {"れんあい"}, UTF8 {"れんけい"}, UTF8 {"れんこん"}, UTF8 {"れんさい"}, UTF8 {"れんしゅう"},
            UTF8 {"れんぞく"}, UTF8 {"れんらく"}, UTF8 {"ろうか"}, UTF8 {"ろうご"}, UTF8 {"ろうじん"}, UTF8 {"ろうそく"},
            UTF8 {"ろくが"}, UTF8 {"ろこつ"}, UTF8 {"ろじうら"}, UTF8 {"ろしゅつ"}, UTF8 {"ろせん"}, UTF8 {"ろてん"},
            UTF8 {"ろめん"},
            UTF8 {"ろれつ"}, UTF8 {"ろんぎ"}, UTF8 {"ろんぱ"}, UTF8 {"ろんぶん"}, UTF8 {"ろんり"}, UTF8 {"わかす"},
            UTF8 {"わかめ"},
            UTF8 {"わかやま"}, UTF8 {"わかれる"}, UTF8 {"わしつ"}, UTF8 {"わじまし"}, UTF8 {"わすれもの"}, UTF8 {"わらう"},
            UTF8 {"われる"}
        };
        
        return Words;
    }
}
