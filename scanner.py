import socket
import time
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor




#logging setup

logging.basicConfig(filename="scanner.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")



#parser setup

parser = argparse.ArgumentParser(description="Python TCP port scanner")

parser.add_argument("target", help="Target IP address or hostname")

parser.add_argument("start",type=int, help="Starting port")

parser.add_argument("end",type=int, help="Ending port")

parser.add_argument("--threads",type=int, default=1.0, help="Number of worker threads (default: 20)")

parser.add_argument("--timeout",type=float,default=1.0, help="Connection timeout in seconds (default: 1) ")

parser.add_argument("--output",default="scan_results.txt", help="Output file (default: scan_results.txt)")



args = parser.parse_args()

target = args.target
start_port = args.start
end_port = args.end

max_workers = args.threads
timeout = args.timeout
output_file = args.output

# VALIDATE THREADS

if max_workers < 1:
    print("Error: Threads must be at least 1.")
    exit()


# VALIDATE TIMEOUT

if timeout <= 0:
    print("Error: Timeout must be greater than 0.")
    exit()

# RESOLVE TARGET


try:

    ip = socket.gethostbyname(target)

except socket.gaierror:

    logging.error(
        f"Could not resolve target: {target}"
    )

    print("Error: Invalid hostname or IP address.")
    exit()

#valid port numbers

if start_port < 1 or end_port > 65535:

    logging.error("Invalid port range")

    print("Error: Ports must be between 1 and 65535.")
    exit()


if start_port > end_port:

    logging.error(
        "Starting port is greater than ending port"
    )

    print(
        "Error: Starting port cannot be greater "
        "than ending port."
    )

    exit()


print("=" * 55)
print("                 PYTHON PORT SCANNER")
print("=" * 55)

print(f"Target       : {target}")
print(f"IP Address   : {ip}")
print(f"Port Range   : {start_port} - {end_port}")


print(f"Threads      : {max_workers}")
print(f"Timeout      : {timeout} seconds")
print(f"Output File  : {output_file}")


print("=" * 55)
print()


logging.info(
    f"Scan started: target={target}, "
    f"ports={start_port}-{end_port}, "
    f"threads={max_workers}, "
    f"timeout={timeout}"
)


start_time = time.time()

open_ports = []



def scan_ports(port):

    s = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    try:
        s.settimeout(timeout)

        result = s.connect_ex((ip, port))

        if result == 0:

            # Service detection
            try:
                service = socket.getservbyport(port)

            except OSError:
                service = "UNKNOWN"

            # Banner grabbing
            banner = "NO BANNER"

            try:
                s.settimeout(timeout)

                # Send HTTP request for common HTTP ports
                if port in [80, 8080, 8000, 8008]:

                    request = (
                        "HEAD / HTTP/1.1\r\n"
                        f"Host: {target}\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                    )

                    s.sendall(
                        request.encode()
                    )

                data = s.recv(1024)

                if data:
                    banner = data.decode(
                        "utf-8",
                        errors="replace"
                    ).strip()

            except (
                socket.timeout,
                ConnectionResetError,
                OSError
            ):
                pass

            print(
                f"[OPEN] Port {port:<5} "
                f"Service: {service:<10} "
                f"Banner: {banner}"
            )

            open_ports.append(
                (port, service, banner)
            )

    except OSError as error:

        logging.error(
            f"Error scanning port {port}: {error}"
        )

    finally:

        s.close()



print("Scanning...\n")

with ThreadPoolExecutor(max_workers=max_workers) as executor:
    executor.map(
        scan_ports,
        range(start_port, end_port + 1)
    )

#Stop timer



end_time = time.time()
scan_time = end_time - start_time



open_ports.sort(
    key=lambda x: x[0]
)


#FINAL RESULTS

print()
print("=" * 55)
print("                    SCAN COMPLETE")
print("=" * 55)

print(f"Target       : {target}")
print(f"IP Address   : {ip}")
print(f"Open Ports   : {len(open_ports)}")
print(f"Scan Time    : {scan_time:.2f} seconds")
print("=" * 55)




# ==========================================
# SAVE RESULTS
# ==========================================

try:

    with open(output_file, "w") as file:

        file.write("PYTHON PORT SCANNER\n")
        file.write("=" * 55 + "\n")

        file.write(
            f"Target       : {target}\n"
        )

        file.write(
            f"IP Address   : {ip}\n"
        )

        file.write(
            f"Port Range   : {start_port} - {end_port}\n"
        )

        file.write(
            f"Threads      : {max_workers}\n"
        )

        file.write(
            f"Timeout      : {timeout} seconds\n"
        )

        file.write(
            f"Open Ports   : {len(open_ports)}\n"
        )

        file.write(
            f"Scan Time    : {scan_time:.2f} seconds\n"
        )

        file.write("\nOPEN PORT DETAILS\n")
        file.write("=" * 55 + "\n")

        for port, service, banner in open_ports:

            file.write(
                f"\nPort    : {port}\n"
            )

            file.write(
                f"Service : {service}\n"
            )

            file.write(
                f"Banner  : {banner}\n"
            )

    print(
        f"Results saved to {output_file}"
    )

    logging.info(
        f"Results saved to {output_file}"
    )

except OSError as error:

    print(
        f"Error saving results: {error}"
    )

    logging.error(
        f"Could not save results: {error}"
    )


#FINISHED

# ==========================================
# FINISHED
# ==========================================

logging.info(
    f"Scan completed in {scan_time:.2f} seconds"
)
