import re
from collections import Counter

# Vigenère cipher analysis.  Extracts every i-th character to isolate
# each key position, then applies a Caesar shift to decrypt.

INPUT_PATH = "ciphertext.txt"
OUTPUT_PATH = "../../decrypted_text.txt"
KEY_LENGTH = 6

ENGLISH_FREQUENCIES = (
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074,
)

PLAINTEXT_WORDS = set("""
a about after age all america and announcing any appearance around arrangements as at attained
authorities before being belief best blessed both british brood by clear clearer comparison
been conceded cock countries cott crown crystal darkness deficient despair degree direct dozen
earthly england english epoch even events everything evil face fair far favoured fishes five for
foolishness for france from general ghost
going good guards had have heaven her heralded him hope human hundred important in incredulity insisted
is it its jaw king large last lately laid life light like london lord lords made mere
lane messages mere more mrs much noisiest nothing of on one only or originality order other our out period people race rapped relate
plain present private preserves prophetic proved queen rapping received recently revelations season
seven seventy spirits strange subjects past
short so some south spring state spiritual spreading sublime superlative supernaturally
swallowing than that the their theirs them there things this thousand through throne times to up
together twenty twentieth two us very was way were westminster what which winter with
wisdom worst year years yet we birthday whom loaves settled forever come communications congress chickens
""".split())

WHITESPACE_PATTERN = re.compile(r"\s+")


def read_input(path):
    """Reads the contents of a file as a string, removes all whitespace
    and returns the contents as a string."""
    with open(path) as file:
        string = file.read().rstrip()
    return re.sub(WHITESPACE_PATTERN, "", string)


def unshift_char(char, unshift):
    return chr((ord(char) - ord("A") - unshift) % 26 + ord("A"))


def decrypt(string, shifts):
    if not shifts or any(char < "A" or char > "Z" for char in string):
        raise ValueError("Use a nonempty key and uppercase A-Z ciphertext")
    return "".join(unshift_char(char, shifts[i % len(shifts)]) for i, char in enumerate(string))


def chi_squared_score(string):
    """Compare a decrypted stream with expected English letter frequencies."""
    counts = Counter(string)
    length = len(string)
    return sum(
        (counts.get(chr(ord("A") + index), 0) - length * frequency) ** 2
        / (length * frequency)
        for index, frequency in enumerate(ENGLISH_FREQUENCIES)
    )


def find_key(string, key_length):
    """Find the lowest-scoring Caesar shift for every Vigenere key position."""
    if key_length < 1:
        raise ValueError("Key length must be positive")

    shifts = []
    for position in range(key_length):
        stream = string[position::key_length]
        candidates = (
            (chi_squared_score("".join(unshift_char(char, shift) for char in stream)), shift)
            for shift in range(26)
        )
        shifts.append(min(candidates)[1])
    return shifts


def add_word_spacing(string):
    """Insert spaces by finding the highest-scoring English word sequence."""
    words = {word.upper() for word in PLAINTEXT_WORDS}
    best_score = [-float("inf")] * (len(string) + 1)
    best_words = [None] * (len(string) + 1)
    best_score[0] = 0
    best_words[0] = []

    for end in range(1, len(string) + 1):
        for start in range(max(0, end - 20), end):
            word = string[start:end]
            if best_words[start] is not None and word in words:
                score = best_score[start] + len(word) ** 2
                if score > best_score[end]:
                    best_score[end] = score
                    best_words[end] = best_words[start] + [word]

    if best_words[-1] is None:
        raise ValueError("Could not split plaintext into known English words")
    return " ".join(best_words[-1])


if __name__ == "__main__":
    input_ = read_input(INPUT_PATH)
    shifts = find_key(input_, KEY_LENGTH)
    plaintext = decrypt(input_, shifts)
    readable_plaintext = add_word_spacing(plaintext)
    with open(OUTPUT_PATH, "w") as output_file:
        output_file.write(readable_plaintext + "\n")
    print("Discovered shifts:", shifts)
    print("Discovered key:", "".join(chr(ord("A") + shift) for shift in shifts))
    for i in range(len(shifts)):
        print(plaintext[i :: len(shifts)])
    print("Reconstructed plaintext:")
    print(readable_plaintext)
