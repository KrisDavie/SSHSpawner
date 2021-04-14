# Modified from https://github.com/NERSC/sshspawner/

import argparse
import socket


def main():
    args = parse_arguments()
    if args.ip:
        print("{} {}".format(ip(), ports()))
    else:
        print(ports())


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ip", "-i", help="Include IP address in output", action="store_true"
    )
    return parser.parse_args()


def ports():
    s1 = socket.socket()
    s1.bind(("", 0))
    port1 = s1.getsockname()[1]
    s2 = socket.socket()
    s2.bind(("", 0))
    port2 = s2.getsockname()[1]
    s1.close()
    s2.close()
    return "{} {}".format(port1, port2)


def ip(address=("8.8.8.8", 80)):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(address)
    ip = s.getsockname()[0]
    s.close()
    return ip


if __name__ == "__main__":
    main()