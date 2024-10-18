import argparse

def binary_to_cpp_header(input_file, output_file):
    with open(input_file, 'rb') as file:
        binary_data = file.read()

    with open(output_file, 'w') as file:
        file.write('#pragma once\n\n')
        file.write('namespace Reflective::PipeToSocket {\n')
        file.write('\tstatic constexpr unsigned char shellcodeArray[] = {\n')

        chunk_size = 20
        for i in range(0, len(binary_data), chunk_size):
            chunk = binary_data[i:i + chunk_size]

            result_string = ""

            hex_bytes = [f'0x{byte:02X}' for byte in chunk]
            result_string += ', '.join(hex_bytes)

            # This keeps a trailing comma in the array
            file.write(f'\t\t{result_string},\n')

        file.write('\t};\n')
        file.write('}')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert a binary file to a C++ header file with an unsigned char array.')
    parser.add_argument('input_file', help='Path to the input binary file')
    parser.add_argument('output_file', help='Path to the output C++ header file')

    args = parser.parse_args()

    binary_to_cpp_header(args.input_file, args.output_file)