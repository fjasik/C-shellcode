import argparse
import pefile

def extract_text_section(pe_file_path, output_file_path):
    try:
        print("Extracting the .text section from the executable...")

        pe = pefile.PE(pe_file_path)

        # Find the text section by iterating through sections
        text_section = None
        for section in pe.sections:
            if b".text" in section.Name:
                text_section = section
                break

        if not text_section:
            print("Text section not found in the PE file")
            return
        
        print(f"Size of .text section: {text_section.SizeOfRawData} (0x{text_section.SizeOfRawData:X}) bytes")

        if "reflective_loader" in pe_file_path:
            dllOffset = text_section.SizeOfRawData - 0xE
            print(f"Compiling reflective_loader, make sure the dll offset is set to: {dllOffset} (0x{dllOffset:X})")

        if (not output_file_path):
            output_file_path = f"{pe_file_path}[.text]"

        with open(output_file_path, 'wb') as f:
            f.write(text_section.get_data())

        print(f"Section extracted and saved to: '{output_file_path}'")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract the .text section from an executable")
    parser.add_argument("input_file", help="Path to the executable")
    parser.add_argument(
        "-o",
        "--output_file",
        default=None,
        help="Path to the output binary file (default: input_file[.text])",
    )

    args = parser.parse_args()

    extract_text_section(args.input_file, args.output_file)
