# IMPORTANT: This script was created used ChatGPT. Use at your own risk.

# sni_filter.py
import socket
import threading
import select

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8443

# Change WARNING_IP to a server you want to redirect blocked requests to 
WARNING_IP = "1.1.1.1"
WARNING_PORT = 8080

BLOCKED_DOMAINS = {
    "badsite.com",
    "exampleadult.com",
    "malware.test",
}

BUFFER_SIZE = 8192


def extract_sni(data):
    try:
        if data[0] != 0x16:
            return None

        session_id_length = data[43]
        idx = 44 + session_id_length

        cipher_suites_length = int.from_bytes(data[idx:idx+2], 'big')
        idx += 2 + cipher_suites_length

        compression_methods_length = data[idx]
        idx += 1 + compression_methods_length

        extensions_length = int.from_bytes(data[idx:idx+2], 'big')
        idx += 2

        end = idx + extensions_length

        while idx + 4 <= end:
            ext_type = int.from_bytes(data[idx:idx+2], 'big')
            ext_len = int.from_bytes(data[idx+2:idx+4], 'big')
            idx += 4

            if ext_type == 0:  # SNI
                sni_data = data[idx:idx+ext_len]

                name_len = int.from_bytes(sni_data[3:5], 'big')
                server_name = sni_data[5:5+name_len].decode()

                return server_name.lower()

            idx += ext_len

    except Exception:
        return None

    return None


def pipe(src, dst):
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        src.close()
        dst.close()


def handle_client(client_socket):
    try:
        hello = client_socket.recv(BUFFER_SIZE, socket.MSG_PEEK)

        hostname = extract_sni(hello)

        print(f"SNI: {hostname}")

        blocked = False

        if hostname:
            for domain in BLOCKED_DOMAINS:
                if hostname == domain or hostname.endswith("." + domain):
                    blocked = True
                    break

        if blocked:
            print(f"BLOCKED: {hostname}")

            remote = socket.create_connection((WARNING_IP, WARNING_PORT))

        else:
            remote = socket.create_connection((hostname, 443))

        t1 = threading.Thread(target=pipe, args=(client_socket, remote))
        t2 = threading.Thread(target=pipe, args=(remote, client_socket))

        t1.start()
        t2.start()

    except Exception as e:
        print("Error:", e)
        client_socket.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(100)

    print(f"Listening on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client,)).start()


if __name__ == "__main__":
    main()
