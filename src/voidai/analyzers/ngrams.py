"""A character model for domain labels, built from an embedded word list.

The question this answers is narrow: **does this name look like something a
person chose, or like something a program emitted?**

## Why not entropy

The DNS tunnelling analyzer answers a similar question with Shannon entropy,
and it works there because it measures 40-to-60-character encoded subdomains,
where per-character entropy separates base32 payload (~4.6 bits) from English
(~3.2). A second-level label is 6 to 20 characters, and at that length
per-character entropy is bounded by `log2(len)` and therefore measures length
rather than randomness. Measured over the 41 real labels of eight characters
or more in `tests/data/real.passivedns` against random strings of matched
length:

    real registered labels    entropy ratio  0.855 mean
    random alphabetic         entropy ratio  0.893 mean
    random hexadecimal        entropy ratio  0.807 mean

Three percentage points of separation, and *inverted* on hex-encoded families
— an entropy component would score a hex DGA as more natural than
`googleapis`. So this module exists, and the DGA analyzer does not use entropy
at all. `docs/benchmarks.md` §9 has the account.

## What the table is, and where it comes from

A bigram log-likelihood over the embedded `WORDS` list below: ordinary English
vocabulary, no brand names, no domain labels. The counts are computed once at
import — cheap, deterministic, and no file to ship or fetch.

**The word list is the datum; the table is derived from it.** That ordering is
deliberate. Writing down 1,369 bigram probabilities directly would mean
inventing three significant figures of English letter-pair statistics from
memory and presenting them as measured. A list of common words is something
that can be read and checked by eye, and the frequencies follow from it by
arithmetic.

**No brand names, and no label from the validation fixture.** `google`,
`akamai` and `mozilla` are absent on purpose: `tests/data/real.passivedns` is
the corpus this model's specificity is measured against, and fitting the model
to it would turn a measurement into a tautology.

## What it cannot do

**A dictionary DGA defeats it, by construction.** Families that concatenate
words from a list — `suppobox` and its relatives — produce names this model
scores as *more* English than English, because they are. Measured: 200
synthetic two-word concatenations score a median 0.065 against a real-label
median of 0.145. Catching those needs a word-boundary model, which is a
different piece of work and is not attempted here.

**The model is English.** A German or Turkish second-level label will read as
improbable and can false positive. The `nxdomain_rate` component is what
carries a family in that case, and on telemetry without `rcode` there is
nothing to carry it — which is one of the two reasons specificity is reported
separately for the two telemetry shapes.
"""

from __future__ import annotations

import math
from functools import lru_cache

#: Ordinary English vocabulary. Brand names and domain labels are excluded on
#: purpose — see the module docstring. Order is irrelevant; only the bigram
#: counts derived from it are used.
WORDS: tuple[str, ...] = (
    "about", "above", "accept", "access", "account", "across", "action", "active", "add",
    "address", "admin", "advance", "advice", "after", "again", "against", "age", "agency",
    "agent", "air", "album", "alert", "all", "allow", "almost", "alone", "along", "already",
    "also", "always", "among", "amount", "analysis", "and", "animal", "another", "answer", "any",
    "apart", "appear", "apple", "apply", "approach", "area", "argue", "arm", "around", "arrive",
    "art", "article", "artist", "ask", "assume", "attack", "attention", "author", "available",
    "avoid", "away", "baby", "back", "bad", "bag", "balance", "ball", "bank", "bar", "base",
    "basic", "battle", "beach", "bear", "beat", "beautiful", "because", "become", "bed", "before",
    "begin", "behavior", "behind", "believe", "below", "benefit", "best", "better", "between",
    "beyond", "big", "bill", "bird", "birth", "bit", "black", "block", "blood", "blue", "board",
    "boat", "body", "book", "border", "born", "both", "box", "boy", "brain", "branch", "bread",
    "break", "bridge", "bright", "bring", "broad", "brother", "brown", "budget", "build", "bus",
    "business", "busy", "buy", "call", "camera", "camp", "campaign", "can", "cancer", "candidate",
    "capital", "car", "card", "care", "career", "carry", "case", "cash", "cat", "catch", "cause",
    "cell", "center", "central", "century", "certain", "chain", "chair", "challenge", "chance",
    "change", "channel", "chapter", "charge", "check", "chief", "child", "choice", "choose",
    "church", "circle", "city", "civil", "claim", "class", "clean", "clear", "click", "climb",
    "clock", "close", "cloud", "club", "coach", "coast", "code", "coffee", "cold", "collect",
    "college", "color", "column", "come", "comfort", "command", "comment", "common", "community",
    "company", "compare", "complete", "computer", "concern", "condition", "conference", "confirm",
    "connect", "consider", "contact", "contain", "content", "continue", "contract", "control",
    "cook", "cool", "copy", "corner", "correct", "cost", "could", "count", "country", "couple",
    "course", "court", "cover", "crack", "create", "credit", "crime", "crisis", "critical",
    "cross", "crowd", "culture", "cup", "current", "custom", "customer", "cut", "cycle", "daily",
    "damage", "dance", "danger", "dark", "data", "date", "daughter", "day", "deal", "death",
    "debate", "debt", "decade", "decide", "deep", "defense", "degree", "deliver", "demand",
    "deny", "depend", "describe", "design", "desk", "detail", "develop", "device", "die", "diet",
    "differ", "difficult", "dinner", "direct", "discover", "discuss", "disease", "display",
    "distance", "district", "divide", "doctor", "document", "dog", "door", "double", "down",
    "draw", "dream", "dress", "drink", "drive", "drop", "drug", "during", "duty", "each", "early",
    "earn", "earth", "ease", "east", "easy", "eat", "economy", "edge", "edit", "education",
    "effect", "effort", "eight", "either", "election", "element", "else", "email", "employee",
    "end", "energy", "engine", "english", "enjoy", "enough", "enter", "entire", "entry",
    "environment", "equal", "error", "escape", "especially", "establish", "even", "evening",
    "event", "ever", "every", "evidence", "exact", "example", "except", "exchange", "exercise",
    "exist", "expand", "expect", "expense", "experience", "expert", "explain", "express",
    "extend", "extra", "eye", "face", "fact", "factor", "fail", "fair", "fall", "family",
    "famous", "far", "farm", "fashion", "fast", "father", "fault", "favor", "fear", "feature",
    "federal", "feed", "feel", "field", "fight", "figure", "file", "fill", "film", "final",
    "finance", "find", "fine", "finger", "finish", "fire", "firm", "first", "fish", "fit", "five",
    "fix", "flag", "flat", "flight", "floor", "flow", "flower", "fly", "focus", "follow", "food",
    "foot", "for", "force", "foreign", "forest", "forget", "form", "former", "forward", "found",
    "four", "frame", "free", "french", "fresh", "friend", "from", "front", "fuel", "full", "fund",
    "future", "gain", "game", "garden", "gas", "gate", "gather", "general", "generate", "get",
    "gift", "girl", "give", "glass", "global", "goal", "gold", "good", "govern", "grade", "grand",
    "grant", "grass", "gray", "great", "green", "ground", "group", "grow", "guard", "guess",
    "guest", "guide", "gun", "guy", "hair", "half", "hall", "hand", "handle", "hang", "happen",
    "happy", "hard", "have", "head", "health", "hear", "heart", "heat", "heavy", "help", "here",
    "high", "hill", "history", "hit", "hold", "hole", "home", "hope", "horse", "hospital", "host",
    "hot", "hotel", "hour", "house", "how", "however", "huge", "human", "hundred", "hunt", "hurt",
    "idea", "identify", "image", "imagine", "impact", "important", "improve", "include", "income",
    "increase", "indeed", "independent", "index", "indicate", "industry", "influence", "inform",
    "initial", "injury", "inside", "instead", "institute", "insurance", "interest", "internal",
    "international", "internet", "interview", "into", "introduce", "invest", "involve", "issue",
    "item", "join", "joint", "journal", "journey", "judge", "jump", "just", "keep", "key", "kid",
    "kill", "kind", "kitchen", "knee", "know", "knowledge", "lab", "labor", "lack", "lake",
    "land", "language", "large", "last", "late", "later", "laugh", "launch", "law", "layer",
    "lead", "leaf", "learn", "least", "leave", "left", "legal", "length", "less", "letter",
    "level", "library", "license", "lie", "life", "light", "like", "limit", "line", "link",
    "list", "listen", "little", "live", "load", "loan", "local", "locate", "lock", "log", "long",
    "look", "lose", "loss", "lot", "love", "low", "machine", "magazine", "mail", "main",
    "maintain", "major", "make", "man", "manage", "many", "map", "march", "mark", "market",
    "marriage", "mass", "master", "match", "material", "matter", "may", "maybe", "mean",
    "measure", "meat", "media", "medical", "medium", "meet", "member", "memory", "mention",
    "message", "metal", "method", "middle", "might", "military", "milk", "million", "mind",
    "mine", "minute", "mirror", "miss", "mission", "mobile", "model", "modern", "moment", "money",
    "monitor", "month", "moon", "moral", "more", "morning", "most", "mother", "motion",
    "mountain", "mouth", "move", "movie", "much", "music", "must", "name", "nation", "native",
    "natural", "nature", "near", "necessary", "neck", "need", "network", "never", "new", "news",
    "next", "nice", "night", "nine", "none", "normal", "north", "note", "nothing", "notice",
    "novel", "now", "number", "object", "observe", "obtain", "occur", "ocean", "off", "offer",
    "office", "officer", "official", "often", "oil", "old", "once", "one", "online", "only",
    "open", "operate", "opinion", "option", "orange", "order", "organize", "origin", "other",
    "out", "outside", "over", "own", "pace", "pack", "page", "pain", "paint", "pair", "panel",
    "paper", "parent", "park", "part", "partner", "party", "pass", "past", "path", "patient",
    "pattern", "pause", "pay", "peace", "people", "per", "perfect", "perform", "perhaps",
    "period", "person", "phase", "phone", "photo", "physical", "pick", "picture", "piece",
    "place", "plan", "plant", "plastic", "plate", "play", "please", "plenty", "point", "police",
    "policy", "politics", "poor", "pop", "popular", "port", "position", "possible", "post",
    "potential", "pound", "power", "practice", "prepare", "present", "president", "press",
    "pressure", "pretty", "prevent", "price", "primary", "print", "prior", "private", "prize",
    "probably", "problem", "process", "produce", "product", "professor", "profile", "profit",
    "program", "project", "promise", "proper", "propose", "protect", "prove", "provide", "public",
    "pull", "purchase", "purpose", "push", "put", "quality", "quarter", "question", "quick",
    "quiet", "quite", "race", "radio", "rain", "raise", "range", "rapid", "rate", "rather",
    "reach", "read", "ready", "real", "reason", "receive", "recent", "recognize", "record", "red",
    "reduce", "refer", "reflect", "reform", "refuse", "region", "regular", "reject", "relate",
    "release", "remain", "remember", "remove", "repeat", "replace", "report", "represent",
    "require", "research", "reserve", "resource", "respond", "rest", "result", "retail", "return",
    "reveal", "review", "rich", "ride", "right", "ring", "rise", "risk", "river", "road", "rock",
    "role", "roll", "room", "root", "round", "route", "rule", "run", "rural", "safe", "sale",
    "salt", "same", "sample", "sand", "save", "say", "scale", "scene", "school", "science",
    "score", "screen", "sea", "search", "season", "seat", "second", "secret", "section", "secure",
    "see", "seek", "seem", "select", "sell", "send", "senior", "sense", "series", "serious",
    "serve", "service", "set", "settle", "seven", "several", "shade", "shadow", "shake", "shape",
    "share", "sharp", "she", "sheet", "shelf", "shift", "ship", "shoe", "shoot", "shop", "short",
    "should", "shoulder", "show", "side", "sign", "signal", "silence", "silver", "similar",
    "simple", "since", "sing", "single", "sister", "sit", "site", "situation", "six", "size",
    "skill", "skin", "sky", "sleep", "slice", "slide", "slight", "slow", "small", "smart",
    "smile", "smoke", "snow", "social", "soft", "software", "soil", "solar", "soldier", "solid",
    "solution", "solve", "some", "son", "song", "soon", "sort", "sound", "source", "south",
    "space", "speak", "special", "specific", "speech", "speed", "spend", "spirit", "split",
    "sport", "spot", "spread", "spring", "square", "stable", "staff", "stage", "stand",
    "standard", "star", "start", "state", "station", "stay", "steal", "step", "stick", "still",
    "stock", "stone", "stop", "store", "storm", "story", "straight", "strange", "strategy",
    "stream", "street", "strength", "stress", "strike", "strong", "structure", "student", "study",
    "stuff", "style", "subject", "success", "such", "sudden", "suffer", "sugar", "suggest",
    "summer", "sun", "supply", "support", "suppose", "sure", "surface", "surprise", "survey",
    "survive", "sweet", "swim", "switch", "system", "table", "take", "talk", "tall", "tank",
    "tape", "target", "task", "taste", "tax", "teach", "team", "tear", "technology", "tell",
    "ten", "term", "test", "text", "than", "thank", "that", "the", "their", "them", "then",
    "theory", "there", "these", "they", "thin", "thing", "think", "third", "this", "those",
    "though", "thought", "thousand", "threat", "three", "through", "throw", "thus", "ticket",
    "tie", "time", "tiny", "tip", "tire", "title", "today", "together", "tone", "tonight", "too",
    "tool", "tooth", "top", "topic", "total", "touch", "tough", "tour", "toward", "tower", "town",
    "trace", "track", "trade", "traditional", "traffic", "train", "transfer", "travel", "treat",
    "tree", "trial", "trip", "trouble", "truck", "true", "trust", "truth", "try", "turn", "twice",
    "two", "type", "under", "understand", "union", "unique", "unit", "universe", "unless",
    "until", "update", "upon", "urban", "use", "user", "usual", "valley", "value", "variety",
    "various", "very", "victim", "video", "view", "village", "visit", "voice", "vote", "wait",
    "walk", "wall", "want", "war", "warm", "warn", "wash", "watch", "water", "wave", "way",
    "weak", "wealth", "wear", "weather", "week", "weight", "welcome", "well", "west", "what",
    "wheel", "when", "where", "whether", "which", "while", "white", "who", "whole", "why", "wide",
    "wife", "wild", "will", "win", "wind", "window", "wine", "wing", "winter", "wire", "wish",
    "with", "within", "without", "woman", "wonder", "wood", "word", "work", "world", "worry",
    "worth", "would", "write", "wrong", "yard", "year", "yellow", "yes", "yesterday", "yet",
    "you", "young", "your", "yourself", "youth", "zone",
)

#: Characters a DNS label may contain. Sets the size of the bigram space, and
#: therefore how much probability mass smoothing hands to pairs the word list
#: never produced — which is every pair involving a digit or a hyphen.
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-"

#: Add-alpha smoothing. Every one of the 1,369 possible pairs gets this much
#: pseudo-count, so a pair the word list never contained has a small
#: probability rather than an infinite surprise. Without it a single unseen
#: pair would saturate any name containing one, and every hyphenated label
#: would score as maximally algorithmic.
_SMOOTHING = 0.5


def _build() -> tuple[dict[str, float], float, float, float]:
    """Count bigrams over `WORDS` and return the model and its two anchors.

    Returns `(probabilities, floor, natural, improbable)`:

      `floor`      probability of a pair the word list never produced
      `natural`    mean surprise of text drawn from this model — the value a
                   name made of ordinary English pairs earns
      `improbable` surprise of a name every pair of which is unseen

    Both anchors are properties of the model itself. Deriving them from the
    validation corpus instead would calibrate the detector against the traffic
    it is scored on, which is the error `docs/benchmarks.md` §3 documents.
    """
    counts: dict[str, int] = {}
    total = 0
    for word in WORDS:
        for index in range(len(word) - 1):
            pair = word[index : index + 2]
            counts[pair] = counts.get(pair, 0) + 1
            total += 1

    space = len(ALPHABET) ** 2
    denominator = total + _SMOOTHING * space
    probabilities = {pair: (count + _SMOOTHING) / denominator for pair, count in counts.items()}
    floor = _SMOOTHING / denominator

    natural = sum(
        (count / total) * -math.log2(probabilities[pair]) for pair, count in counts.items()
    )
    improbable = -math.log2(floor)
    return probabilities, floor, natural, improbable


_PROBABILITIES, _FLOOR, NATURAL_SURPRISE, IMPROBABLE_SURPRISE = _build()


def mean_surprise(label: str) -> float | None:
    """Mean bits of surprise per character pair, under the English model.

    `None` for a label with no pairs at all — a single character. That is
    unmeasurable rather than unsurprising, and the caller must drop the
    component rather than score it.
    """
    pairs = [label[index : index + 2] for index in range(len(label) - 1)]
    if not pairs:
        return None
    return sum(-math.log2(_PROBABILITIES.get(pair, _FLOOR)) for pair in pairs) / len(pairs)


#: One entry per distinct label, not per record. An estate resolves the same
#: few thousand registered domains from hundreds of hosts, and the analyzer
#: scores every (host, domain) pair — so without this the model is recomputed
#: for `google` once per host that visited it. Measured on a 1.1M-record,
#: 9,800-host frame: 332,700 scored labels over roughly a thousand distinct
#: ones. Bounded so memory stays flat on a capture whose names really are all
#: different, which is exactly what a generation family looks like.
@lru_cache(maxsize=200_000)
def improbability(label: str) -> float | None:
    """Map a label onto [0, 1]: 0 reads as English, 1 as machine-generated.

    Anchored at `NATURAL_SURPRISE` and `IMPROBABLE_SURPRISE`, both derived
    from the model rather than from any corpus. Measured over
    `tests/data/real.passivedns`, real registered labels of eight characters
    or more have a median of 0.145 and a 90th percentile of 0.467; random
    alphabetic strings of matched length have a median of 0.667 and hex
    strings 0.941.
    """
    surprise = mean_surprise(label)
    if surprise is None:
        return None
    span = max(IMPROBABLE_SURPRISE - NATURAL_SURPRISE, 1e-9)
    scaled = (surprise - NATURAL_SURPRISE) / span
    return 0.0 if scaled < 0.0 else 1.0 if scaled > 1.0 else scaled
