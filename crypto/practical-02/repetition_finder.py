import re

# Kasiski examination.  Finds repeated substrings in ciphertext to help
# determine the key length of a polyalphabetic cipher (e.g., Vigenère).

INPUT_PATH = "ciphertext.txt"

WHITESPACE_PATTERN = re.compile(r"\s+")


def read_input(path):
    """Reads the contents of a file as a string, removes all whitespace
    and returns the contents as a string."""
    with open(path) as file:
        string = file.read().rstrip()
    return re.sub(WHITESPACE_PATTERN, "", string)


def find_repetitions(string, slen):
    """Count repeated substrings, including overlapping occurrences."""
    return {text: len(positions) for text, positions in find_positions(string, slen).items()}


def find_positions(string, slen):
    """Return repeated substrings and their zero-based starting positions."""
    if slen < 1:
        raise ValueError("Substring length must be positive")
    positions = {}
    for i in range(len(string) - slen + 1):
        subs = string[i : i + slen]
        positions.setdefault(subs, []).append(i)
    return {text: starts for text, starts in positions.items() if len(starts) > 1}


if __name__ == "__main__":
    input_ = read_input(INPUT_PATH)
    # Bound the search; extend this range if longer repeats are of interest.
    for length in range(min(12, len(input_)), 2, -1):
        counts = find_repetitions(input_, length)
        if counts:
            print(f"{length}: {counts}")
    starts = find_positions(input_, 8).get("NTIOMLME", [])
    print("NTIOMLME positions (one-based):", [i + 1 for i in starts])
    print("Pairwise distances:", [b - a for i, a in enumerate(starts) for b in starts[i + 1 :]])
