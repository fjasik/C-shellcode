import argparse
import struct


def get_aligned_numbers(num1, num2):
    str_num1 = str(num1)
    str_num2 = str(num2)

    max_len = max(len(str_num1), len(str_num2))

    return (str_num1.rjust(max_len), str_num2.rjust(max_len))


def concatenate_files(input_file1, input_file2, output_file, include_length):
    with open(input_file1, "rb") as file1, open(input_file2, "rb") as file2:
        data1 = file1.read()
        data2 = file2.read()

    [formatted_length1, formatted_length2] = get_aligned_numbers(len(data1), len(data2))

    print(f"Size of the first binary : {formatted_length1} bytes")
    print(f"Size of the second binary: {formatted_length2} bytes")

    concatenated_data = data1

    if include_length:
        # Add the length of the second file as DWORD (4 bytes, little-endian)
        length_bytes = struct.pack("<I", len(data2))
        concatenated_data += length_bytes
        print("Note:")
        print(
            f"Interposed between the two binaries the length of the second one as DWORD"
        )

    concatenated_data += data2

    with open(output_file, "wb") as output:
        output.write(concatenated_data)

    print(f"Concatenated binary data written to: {output_file}")
    print(f"Total length: {len(concatenated_data)} bytes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Concatenates two binary files.")

    parser.add_argument(
        "input_file1",
        help="Path to first binary data (the reflective loader shellcode)",
    )

    parser.add_argument("input_file2", help="Path to second binary data (the dll)")

    parser.add_argument(
        "-o",
        "--output_file",
        default="./concat.bin",
        help="Path to the output binary file (default: ./concat.bin)",
    )

    parser.add_argument(
        "--length",
        action="store_true",
        help="Include the length of the second file between the files (DWORD)",
    )

    args = parser.parse_args()

    concatenate_files(args.input_file1, args.input_file2, args.output_file, args.length)
