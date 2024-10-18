import argparse


def calculate_hash(input_str: str, debug=False, lowercase=False):
    hash_value = 5381

    if lowercase:
        print(f"Converting characters to lowercase: {lowercase}")

    if debug:
        max_iter_length = len(str(len(input_str)))
        print(f"Init value:   {hex(hash_value)}")

    for i, char in enumerate(input_str):
        if lowercase:
            char = char.lower()

        # Force 32 bit number
        hash_value = (hash_value * 33 + ord(char)) % (2**32)

        if debug:
            print(f"Iteration {i:>{max_iter_length}}: {hex(hash_value)}")

    return hash_value


def main():
    parser = argparse.ArgumentParser(description="Calculate hash value of a string")
    parser.add_argument(
        "input_str", type=str, help="Input string to calculate hash value"
    )

    parser.add_argument("-debug", action="store_true", help="Print debug information")
    parser.add_argument(
        "-lowercase",
        action="store_true",
        help="Convert every character to lowercase before hashing",
    )
    args = parser.parse_args()

    print(f"Input string: {args.input_str}")

    hash_value = calculate_hash(args.input_str, args.debug, args.lowercase)

    print(f"Hash value:   {hex(hash_value)}")
    print(f"Hash value:   {hash_value}")


if __name__ == "__main__":
    main()
