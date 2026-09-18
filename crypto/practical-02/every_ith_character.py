import re

# Vigenère cipher analysis.  Extracts every i-th character to isolate
# each key position, then applies a Caesar shift to decrypt.

INPUT_PATH = "ciphertext.txt"

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


if __name__ == "__main__":
    input_ = read_input(INPUT_PATH)
    shifts = [5, 0, 12, 14, 20, 18]
    plaintext = decrypt(input_, shifts)
    for i in range(len(shifts)):
        print(plaintext[i :: len(shifts)])
    print("Reconstructed plaintext:")
    print(plaintext)
