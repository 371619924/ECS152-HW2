#!/usr/bin/env python3

import json
import os
import sys
from collections import Counter, defaultdict
from urllib.parse import urlparse


SPECIAL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "net.cn", "org.cn",
    "com.hk", "com.tw", "com.sg", "com.my",
    "co.in", "co.nz", "com.mx", "com.tr", "com.ar",
}


COOKIE_INFO = {
    "receive-cookie-deprecation": "Cookie used for browser or ad-tech testing related to third-party cookie deprecation.",
    "__cf_bm": "Cloudflare cookie used for bot management and website security.",
    "_cfuvid": "Cloudflare cookie used for rate limiting, security, and traffic management.",
    "i": "Advertising or analytics identifier cookie used for personalization or measurement.",
    "bh": "Yandex-style cookie commonly used for browser identification, analytics, or advertising synchronization.",
    "_ga": "Google Analytics cookie used to distinguish users and measure site traffic.",
    "_gid": "Google Analytics cookie used to distinguish users for short-term analytics.",
    "_gat": "Google Analytics cookie used to limit request rate.",
    "_gcl_au": "Google advertising cookie used for conversion tracking.",
    "aka_a2": "Akamai cookie used for performance optimization and request acceleration.",
    "a3": "Yahoo advertising cookie used for user identification, personalization, and analytics.",
    "yandexuid": "Yandex cookie used to identify users for analytics and site optimization.",
    "audit": "Advertising cookie used for user matching or cookie synchronization.",
    "audit_p": "Advertising cookie used for user matching or cookie synchronization.",
    "kadusercookie": "PubMatic cookie used as a browser or device identifier for advertising.",
    "test_cookie": "Google DoubleClick cookie used to check whether cookies are enabled.",
    "ide": "Google DoubleClick cookie used for ad delivery, personalization, and measurement.",
    "tmr_lvid": "Top.Mail.Ru analytics cookie used to identify visitors.",
    "tmr_lvidts": "Top.Mail.Ru analytics cookie storing visitor timestamp information.",
    "khaos": "Rubicon/Magnite advertising cookie used for user identification.",
    "khaos_p": "Rubicon/Magnite advertising cookie used for user identification.",
    "act": "Meta/Facebook cookie used for security, login, or advertising-related activity.",
}


COOKIE_PREFIX_INFO = [
    ("_ga_", "Google Analytics cookie used to store page-view information for a specific property."),
    ("_gat_", "Google Analytics cookie used to throttle request rate for a specific property."),
    ("__utm", "Google Analytics cookie used for visitor and traffic-source analytics."),
    ("_ym_", "Yandex.Metrica cookie used for analytics and session tracking."),
    ("_hj", "Hotjar cookie used for behavior analytics or user feedback."),
    ("amcv_", "Adobe Experience Cloud visitor ID cookie used for analytics and marketing services."),
    ("amcvs_", "Adobe Experience Cloud session cookie used with visitor identification services."),
]


def get_host(url):
    try:
        host = urlparse(url).hostname
    except Exception:
        host = None

    if not host:
        return ""

    return host.lower().rstrip(".")


def looks_like_ipv4(host):
    parts = host.split(".")

    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False

        number = int(part)

        if number < 0 or number > 255:
            return False

    return True


def base_domain(host):
    host = host.lower().rstrip(".")

    if host.startswith("www."):
        host = host[4:]

    if not host or looks_like_ipv4(host):
        return host

    pieces = [piece for piece in host.split(".") if piece]

    if len(pieces) <= 2:
        return host

    last_two = ".".join(pieces[-2:])

    if last_two in SPECIAL_SUFFIXES and len(pieces) >= 3:
        return ".".join(pieces[-3:])

    return last_two


def har_entries(data):
    if not isinstance(data, dict):
        return []

    log = data.get("log", {})

    if isinstance(log, dict) and isinstance(log.get("entries"), list):
        return log["entries"]

    if isinstance(data.get("entries"), list):
        return data["entries"]

    return []


def site_from_first_request(entries):
    for entry in entries:
        request = entry.get("request", {}) or {}
        host = get_host(request.get("url", ""))

        if host:
            return base_domain(host)

    return ""


def values_for_header(headers, target):
    answer = []
    target = target.lower()

    for header in headers or []:
        name = str(header.get("name", "")).lower()
        value = str(header.get("value", ""))

        if name == target:
            answer.append(value)

    return answer


def names_from_har_cookie_list(cookies):
    answer = []

    for cookie in cookies or []:
        name = cookie.get("name")

        if name:
            answer.append(str(name).strip().lower())

    return answer


def names_from_cookie_header(value):
    answer = []

    for part in value.split(";"):
        part = part.strip()

        if "=" not in part:
            continue

        name = part.split("=", 1)[0].strip().lower()

        if name:
            answer.append(name)

    return answer


def name_from_set_cookie(value):
    first = str(value or "").split(";", 1)[0].strip()

    if "=" not in first:
        return ""

    return first.split("=", 1)[0].strip().lower()


def request_cookie_names(request):
    names = names_from_har_cookie_list(request.get("cookies", []))

    if names:
        return names

    answer = []

    for value in values_for_header(request.get("headers", []), "cookie"):
        answer.extend(names_from_cookie_header(value))

    return answer


def response_cookie_names(response):
    names = names_from_har_cookie_list(response.get("cookies", []))

    if names:
        return names

    answer = []

    for value in values_for_header(response.get("headers", []), "set-cookie"):
        name = name_from_set_cookie(value)

        if name:
            answer.append(name)

    return answer


def clean_mime(value):
    value = str(value or "").strip().lower()

    if ";" in value:
        value = value.split(";", 1)[0].strip()

    return value


def mime_type(response):
    content = response.get("content", {}) or {}
    mime = clean_mime(content.get("mimeType", ""))

    if mime:
        return mime

    for value in values_for_header(response.get("headers", []), "content-type"):
        mime = clean_mime(value)

        if mime:
            return mime

    return "unknown"


def body_size(response):
    content = response.get("content", {}) or {}

    for value in [response.get("bodySize"), content.get("size")]:
        try:
            size = int(value)
        except Exception:
            continue

        if size >= 0:
            return size

    return 0


def describe_cookie(name):
    key = name.lower()

    if key in COOKIE_INFO:
        return COOKIE_INFO[key]

    for prefix, description in COOKIE_PREFIX_INFO:
        if key.startswith(prefix):
            return description

    return "Third-party cookie used for advertising and analytics and consent security or session functionality depending on the provider"


def skip_file(path):
    parts = path.replace("\\", "/").split("/")
    filename = parts[-1]

    if "__MACOSX" in parts:
        return True

    if filename.startswith("._"):
        return True

    return not filename.lower().endswith(".har")


def load_har_files(directory):
    for root, _, files in os.walk(directory):
        for filename in sorted(files):
            path = os.path.join(root, filename)

            if skip_file(path):
                continue

            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    yield json.load(f)
            except Exception:
                print("read fail", file=sys.stderr)


def add_har_data(data, totals):
    entries = har_entries(data)

    if not entries:
        return

    site = site_from_first_request(entries)

    if not site:
        return

    third_party_requests = 0
    https_requests = 0
    total_requests = 0
    bytes_total = 0

    for entry in entries:
        request = entry.get("request", {}) or {}
        response = entry.get("response", {}) or {}

        url = request.get("url", "")
        host = get_host(url)

        if not host:
            continue

        total_requests += 1

        if urlparse(url).scheme.lower() == "https":
            https_requests += 1

        request_domain = base_domain(host)

        if request_domain != site:
            third_party_requests += 1
            totals["third_party_domains"][request_domain] += 1

            for name in request_cookie_names(request):
                totals["third_party_cookies"][name] += 1

            for name in response_cookie_names(response):
                totals["third_party_cookies"][name] += 1

        totals["content_types"][mime_type(response)] += 1
        bytes_total += body_size(response)

    totals["third_party_by_site"][site] = third_party_requests
    totals["https_by_site"][site] = {
        "https": https_requests,
        "total": total_requests,
    }
    totals["size_by_site"][site] = bytes_total


def top_list(counter, field_name):
    rows = sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:10]
    return [{field_name: name, "count": count} for name, count in rows]


def main():
    if len(sys.argv) != 2:
        print("usage fail", file=sys.stderr)
        raise SystemExit(1)

    har_dir = sys.argv[1]

    totals = {
        "third_party_by_site": defaultdict(int),
        "https_by_site": defaultdict(lambda: {"https": 0, "total": 0}),
        "size_by_site": defaultdict(int),
        "third_party_domains": Counter(),
        "third_party_cookies": Counter(),
        "content_types": Counter(),
    }

    for data in load_har_files(har_dir):
        add_har_data(data, totals)

    https_pct = {}

    for site, counts in totals["https_by_site"].items():
        total = counts["total"]

        if total == 0:
            https_pct[site] = 0.0
        else:
            https_pct[site] = round(100.0 * counts["https"] / total, 1)

    cookie_rows = []
    cookie_counts = sorted(
        totals["third_party_cookies"].items(),
        key=lambda item: (-item[1], item[0]),
    )[:10]

    for name, count in cookie_counts:
        cookie_rows.append({
            "name": name,
            "count": count,
            "description": describe_cookie(name),
        })

    size_rows = sorted(
        totals["size_by_site"].items(),
        key=lambda item: (-item[1], item[0]),
    )[:10]

    answer = {
        "per_site_third_party_counts": dict(sorted(totals["third_party_by_site"].items())),
        "top10_third_party_domains": top_list(totals["third_party_domains"], "domain"),
        "top10_third_party_cookies": cookie_rows,
        "per_site_https_pct": dict(sorted(https_pct.items())),
        "top10_content_types": top_list(totals["content_types"], "content_type"),
        "top10_response_size_sites": [
            {"site": site, "total_bytes": size}
            for site, size in size_rows
        ],
    }

    print(json.dumps(answer, indent=2))


if __name__ == "__main__":
    main()