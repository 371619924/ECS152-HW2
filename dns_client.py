#!/usr/bin/env python3

import json
import random
import socket
import struct
import time


DOMAIN = "tmz.com"
DNS_PORT = 53
HTTP_PORT = 80
TIMEOUT_SECONDS = 10

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_AAAA = 28
TYPE_OPT = 41
CLASS_IN = 1

TYPE_NAMES = {
    TYPE_A: "A",
    TYPE_NS: "NS",
    TYPE_CNAME: "CNAME",
    TYPE_AAAA: "AAAA",
    TYPE_OPT: "OPT",
}

ROOT_SERVERS = [
    "198.41.0.4",
    "199.9.14.201",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
]


class DNSError(Exception):
    pass


def unique_keep_order(items):
    seen = set()
    result = []

    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)

    return result


def encode_name(name):
    name = name.strip(".")

    if name == "":
        return b"\x00"

    result = bytearray()

    for label in name.split("."):
        label_bytes = label.encode("ascii")

        if len(label_bytes) > 63:
            raise DNSError("DNS label is too long")

        result.append(len(label_bytes))
        result.extend(label_bytes)

    result.append(0)
    return bytes(result)


def build_query(name, qtype=TYPE_A, use_edns=True):
    transaction_id = random.randint(0, 0xFFFF)

    flags = 0x0000
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 1 if use_edns else 0

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount,
    )

    question = encode_name(name) + struct.pack("!HH", qtype, CLASS_IN)

    if not use_edns:
        return transaction_id, header + question

    opt_name = b"\x00"
    opt_type = TYPE_OPT
    udp_payload_size = 1232
    extended_rcode_version_flags = 0
    rdlength = 0

    opt_record = opt_name + struct.pack(
        "!HHIH",
        opt_type,
        udp_payload_size,
        extended_rcode_version_flags,
        rdlength,
    )

    return transaction_id, header + question + opt_record


def decode_name(packet, offset):
    labels = []
    jumped = False
    next_offset = offset
    visited_offsets = set()

    while True:
        if offset >= len(packet):
            raise DNSError("name offset is outside packet")

        length = packet[offset]

        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(packet):
                raise DNSError("truncated compression pointer")

            pointer = ((length & 0x3F) << 8) | packet[offset + 1]

            if pointer in visited_offsets:
                raise DNSError("compression pointer loop")

            visited_offsets.add(pointer)

            if not jumped:
                next_offset = offset + 2

            offset = pointer
            jumped = True
            continue

        if (length & 0xC0) != 0:
            raise DNSError("invalid DNS label length")

        offset += 1

        if length == 0:
            if not jumped:
                next_offset = offset
            break

        if offset + length > len(packet):
            raise DNSError("truncated DNS label")

        label = packet[offset:offset + length].decode("ascii", errors="replace")
        labels.append(label)
        offset += length

    return ".".join(labels), next_offset


def parse_record(packet, offset):
    name, offset = decode_name(packet, offset)

    if offset + 10 > len(packet):
        raise DNSError("truncated resource record header")

    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", packet, offset)
    offset += 10

    rdata_offset = offset
    rdata_end = offset + rdlength

    if rdata_end > len(packet):
        raise DNSError("truncated resource record data")

    raw_rdata = packet[rdata_offset:rdata_end]

    if rtype == TYPE_A and rdlength == 4:
        data = socket.inet_ntoa(raw_rdata)
    elif rtype == TYPE_AAAA and rdlength == 16:
        data = socket.inet_ntop(socket.AF_INET6, raw_rdata)
    elif rtype == TYPE_NS or rtype == TYPE_CNAME:
        data, _ = decode_name(packet, rdata_offset)
    else:
        data = raw_rdata.hex()

    if isinstance(data, str):
        data = data.lower().rstrip(".")

    record = {
        "name": name.lower().rstrip("."),
        "type": rtype,
        "type_name": TYPE_NAMES.get(rtype, str(rtype)),
        "class": rclass,
        "ttl": ttl,
        "data": data,
    }

    return record, rdata_end


def parse_response(packet, expected_id):
    if len(packet) < 12:
        raise DNSError("DNS response is too short")

    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH",
        packet,
        0,
    )

    if transaction_id != expected_id:
        raise DNSError("transaction ID mismatch")

    rcode = flags & 0x000F

    if rcode != 0:
        raise DNSError("DNS server returned error rcode=" + str(rcode))

    offset = 12

    questions = []

    for _ in range(qdcount):
        qname, offset = decode_name(packet, offset)

        if offset + 4 > len(packet):
            raise DNSError("truncated question section")

        qtype, qclass = struct.unpack_from("!HH", packet, offset)
        offset += 4

        questions.append({
            "name": qname.lower().rstrip("."),
            "type": qtype,
            "class": qclass,
        })

    answers = []

    for _ in range(ancount):
        record, offset = parse_record(packet, offset)
        answers.append(record)

    authorities = []

    for _ in range(nscount):
        record, offset = parse_record(packet, offset)
        authorities.append(record)

    additionals = []

    for _ in range(arcount):
        record, offset = parse_record(packet, offset)
        additionals.append(record)

    return {
        "flags": flags,
        "truncated": bool(flags & 0x0200),
        "questions": questions,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals,
    }


def recv_all(sock, length):
    chunks = []
    remaining = length

    while remaining > 0:
        chunk = sock.recv(remaining)

        if not chunk:
            raise DNSError("TCP DNS connection closed early")

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def query_dns_udp(server_ip, name, qtype=TYPE_A):
    expected_id, packet = build_query(name, qtype=qtype, use_edns=True)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT_SECONDS)

        start = time.perf_counter()
        sock.sendto(packet, (server_ip, DNS_PORT))
        response_packet, _ = sock.recvfrom(4096)
        rtt_ms = (time.perf_counter() - start) * 1000.0

    response = parse_response(response_packet, expected_id)
    return response, rtt_ms


def query_dns_tcp(server_ip, name, qtype=TYPE_A):
    expected_id, packet = build_query(name, qtype=qtype, use_edns=True)
    framed_packet = struct.pack("!H", len(packet)) + packet

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(TIMEOUT_SECONDS)

        start = time.perf_counter()

        sock.connect((server_ip, DNS_PORT))
        sock.sendall(framed_packet)

        length_prefix = recv_all(sock, 2)
        response_length = struct.unpack("!H", length_prefix)[0]
        response_packet = recv_all(sock, response_length)

        rtt_ms = (time.perf_counter() - start) * 1000.0

    response = parse_response(response_packet, expected_id)
    return response, rtt_ms


def query_dns(server_ip, name, qtype=TYPE_A):
    response, rtt_ms = query_dns_udp(server_ip, name, qtype=qtype)

    if response["truncated"]:
        response, rtt_ms = query_dns_tcp(server_ip, name, qtype=qtype)

    return response, rtt_ms


def query_any_server(servers, name, qtype=TYPE_A):
    last_error = None

    for server_ip in unique_keep_order(servers):
        try:
            response, rtt_ms = query_dns(server_ip, name, qtype=qtype)
            return response, rtt_ms, server_ip
        except Exception as exc:
            last_error = exc

    raise DNSError("all DNS servers failed for " + name + ": " + str(last_error))


def get_a_records(response, name):
    target = name.lower().rstrip(".")
    result = []

    for record in response["answers"]:
        if record["type"] == TYPE_A and record["name"] == target:
            result.append(record["data"])

    return unique_keep_order(result)


def get_cnames(response, name):
    target = name.lower().rstrip(".")
    result = []

    for record in response["answers"]:
        if record["type"] == TYPE_CNAME and record["name"] == target:
            result.append(record["data"])

    return unique_keep_order(result)


def get_ns_names(response):
    result = []

    for record in response["authorities"]:
        if record["type"] == TYPE_NS:
            result.append(record["data"])

    return unique_keep_order(result)


def get_glue_ips(response, ns_names):
    wanted = set()

    for name in ns_names:
        wanted.add(name.lower().rstrip("."))

    result = []

    for record in response["additionals"]:
        if record["type"] == TYPE_A and record["name"] in wanted:
            result.append(record["data"])

    if len(result) == 0:
        for record in response["additionals"]:
            if record["type"] == TYPE_A:
                result.append(record["data"])

    return unique_keep_order(result)


def tld_label(name):
    parts = name.lower().strip(".").split(".")

    if len(parts) >= 2:
        return "." + parts[-1]

    return name.lower().strip(".")


def server_role_for_depth(depth, name):
    if depth == 0:
        return "root"

    if depth == 1:
        return "TLD (" + tld_label(name) + ")"

    return "authoritative"


def resolve_iterative(name, qtype=TYPE_A, verbose=False, max_depth=20):
    name = name.lower().rstrip(".")
    current_servers = ROOT_SERVERS[:]
    total_dns_rtt_ms = 0.0

    for depth in range(max_depth):
        response, rtt_ms, used_server = query_any_server(current_servers, name, qtype=qtype)
        total_dns_rtt_ms += rtt_ms

        if verbose:
            role = server_role_for_depth(depth, name)
            print("Step " + str(depth + 1) + " [" + role + "]: querying " + used_server + " for " + name + " ...")

        a_records = get_a_records(response, name)

        if len(a_records) > 0:
            return a_records, total_dns_rtt_ms

        cnames = get_cnames(response, name)

        if len(cnames) > 0:
            cname_ips, cname_rtt = resolve_iterative(
                cnames[0],
                qtype=qtype,
                verbose=False,
                max_depth=max_depth,
            )
            return cname_ips, total_dns_rtt_ms + cname_rtt

        ns_names = get_ns_names(response)

        if len(ns_names) == 0:
            raise DNSError("no A records, CNAMEs, or NS referrals found for " + name)

        next_servers = get_glue_ips(response, ns_names)

        if len(next_servers) == 0:
            extra_rtt = 0.0

            for ns_name in ns_names:
                try:
                    ns_ips, ns_rtt = resolve_iterative(
                        ns_name,
                        qtype=TYPE_A,
                        verbose=False,
                        max_depth=max_depth,
                    )

                    extra_rtt += ns_rtt
                    next_servers.extend(ns_ips)

                    if len(next_servers) > 0:
                        break

                except DNSError:
                    pass

            total_dns_rtt_ms += extra_rtt

        next_servers = unique_keep_order(next_servers)

        if len(next_servers) == 0:
            raise DNSError("could not find IP addresses for next DNS servers")

        current_servers = next_servers

    raise DNSError("resolution exceeded max depth for " + name)


def measure_http_rtt(ips, host_header):
    request = (
        "GET / HTTP/1.1\r\n"
        "Host: " + host_header + "\r\n"
        "User-Agent: ECS152A-DNS-Client\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii")

    last_error = None

    for ip in ips:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT_SECONDS)

                start = time.perf_counter()

                sock.connect((ip, HTTP_PORT))
                sock.sendall(request)
                sock.recv(4096)

                rtt_ms = (time.perf_counter() - start) * 1000.0

                return ip, rtt_ms

        except Exception as exc:
            last_error = exc

    raise OSError("HTTP request failed for all resolved IPs: " + str(last_error))


def main():
    try:
        ips, dns_rtt_ms = resolve_iterative(DOMAIN, qtype=TYPE_A, verbose=True)
        ips = unique_keep_order(ips)
        print("Step 4 [" + DOMAIN + "]: A records = " + ", ".join(ips))

    except Exception as exc:
        print("Step 4 [" + DOMAIN + "]: A records = ")
        raise SystemExit("DNS resolution failed: " + str(exc))

    try:
        http_ip, http_rtt_ms = measure_http_rtt(ips, DOMAIN)

    except Exception:
        http_ip = ips[0] if len(ips) > 0 else "0.0.0.0"
        http_rtt_ms = -1.0

    dns_rtt_ms = round(dns_rtt_ms, 1)
    http_rtt_ms = round(http_rtt_ms, 1)

    print("DNS RTT: " + format(dns_rtt_ms, ".1f") + "ms")
    print("HTTP RTT to " + http_ip + ": " + format(http_rtt_ms, ".1f") + "ms")

    output = {
        "ips": ips,
        "dns_rtt_ms": dns_rtt_ms,
        "http_rtt_ms": http_rtt_ms,
    }

    with open("final_ips.json", "w", encoding="utf-8") as outfile:
        json.dump(output, outfile, indent=2)
        outfile.write("\n")


if __name__ == "__main__":
    main()