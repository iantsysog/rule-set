import asyncio
import contextlib
import ipaddress
import re
from collections.abc import Callable, Coroutine, Iterable, Sequence
from typing import Literal, NotRequired, TypedDict, cast
from urllib.parse import unquote

import anyio
import httpx
import orjson
import polars as pl


class SingHeadlessRule(TypedDict):
    domain: NotRequired[list[str]]
    domain_suffix: NotRequired[list[str]]
    domain_keyword: NotRequired[list[str]]
    domain_regex: NotRequired[list[str]]
    ip_cidr: NotRequired[list[str]]
    process_name: NotRequired[list[str]]
    process_path_regex: NotRequired[list[str]]
    process_path: NotRequired[list[str]]
    wifi_ssid: NotRequired[list[str]]
    wifi_bssid: NotRequired[list[str]]
    network_type: NotRequired[list[str]]
    port: NotRequired[int | list[int]]
    source_port: NotRequired[int | list[int]]
    port_range: NotRequired[list[str]]
    source_port_range: NotRequired[list[str]]
    source_ip_cidr: NotRequired[list[str]]


class SingLogicalRule(TypedDict):
    type: Literal["logical"]
    mode: Literal["and", "or"]
    rules: list[SingHeadlessRule]
    invert: bool


class SingRuleSet(TypedDict):
    version: Literal[4]
    rules: list[SingLogicalRule | SingHeadlessRule]


ASN_CACHE: dict[str, list[str]] = {}
HTTP_CLIENT = httpx.AsyncClient(
    timeout=httpx.Timeout(10.0, pool=30.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
    http2=True,
    trust_env=False,
)

REGEX_CHARS = frozenset(r"*+?^${}()|[]\\")
CHAR_MAP = {
    ".": r"\\.",
    "*": r"[\\w.-]*?",
    "?": r"[\\w.-]",
}

SURGE_RULE_TYPES = frozenset(
    {
        "DOMAIN",
        "DOMAIN-SUFFIX",
        "DOMAIN-KEYWORD",
        "DOMAIN-WILDCARD",
        "DOMAIN-SET",
        "IP-CIDR",
        "IP-CIDR6",
        "GEOIP",
        "IP-ASN",
        "USER-AGENT",
        "URL-REGEX",
        "PROCESS-NAME",
        "AND",
        "OR",
        "NOT",
        "SUBNET",
        "DEST-PORT",
        "IN-PORT",
        "SRC-PORT",
        "SRC-IP",
        "PROTOCOL",
        "SCRIPT",
        "CELLULAR-RADIO",
        "CELLULAR-CARRIER",
        "FINAL",
        "DEVICE-NAME",
        "MAC-ADDRESS",
        "HOSTNAME-TYPE",
    },
)

_DOMAIN_REGEX_OPTION3 = re.compile(r"^([^.]+)\.([^.]+)\.([^.]+)\.\(([^)]+)\)$")
_DOMAIN_REGEX_OPTION2 = re.compile(r"^([^.]+)\.([^.]+)\.\(([^)]+)\)$")
_LOGICAL_PARENS = re.compile(r"\(([^()]*)\)")


def validate_regex(pattern: str, /) -> bool:
    if not isinstance(pattern, str) or not pattern:
        return False
    with contextlib.suppress(re.error):
        re.compile(pattern)
        return True
    return False


def mask_regex(pattern: str, /) -> str:
    if not isinstance(pattern, str):
        raise TypeError(pattern)
    masked = pattern.lstrip(".")
    if not masked:
        return "^$"
    return f"^{''.join(CHAR_MAP.get(ch, ch) for ch in masked)}$"


def normalize_cidr(entry: str, /) -> str:
    if "/" in entry:
        return entry
    with contextlib.suppress(ValueError):
        addr = ipaddress.ip_address(entry)
        return f"{entry}/{32 if addr.version == 4 else 128}"
    return entry


def _normalize_port(value: str, /) -> int | None:
    with contextlib.suppress(ValueError):
        port = int(value)
        if 0 <= port <= 65_535:
            return port
    return None


def process_ports(addresses: list[str], /) -> tuple[list[int], list[str]]:
    if not addresses:
        return [], []

    ports: list[int] = []
    ranges: list[str] = []
    for item in addresses:
        token = ":" if ":" in item else "-" if "-" in item else ""
        if token:
            left, sep, right = item.partition(token)
            if not sep:
                continue
            start = _normalize_port(left.strip())
            end = _normalize_port(right.strip())
            if start is None or end is None or start > end:
                continue
            ranges.append(f"{start}:{end}")
            continue

        port = _normalize_port(item.strip())
        if port is not None:
            ports.append(port)

    return ports, ranges


def is_regex_like(value: str, /) -> bool:
    return any(ch in REGEX_CHARS for ch in value) and validate_regex(value)


def is_wildcard_like(value: str, /) -> bool:
    return "*" in value or "?" in value


def is_path_like(value: str, /) -> bool:
    return "/" in value or (len(value) > 1 and value[0].isalpha() and value[1] == ":")


def _logical_rule_parts(addr: str, /) -> list[str]:
    if not (addr.startswith("((") and addr.endswith("))")):
        return []

    inner = addr[2:-2].strip()
    if not inner:
        return []

    matches = [m.group(1).strip() for m in _LOGICAL_PARENS.finditer(inner)]
    if matches:
        return [m for m in matches if m]

    parts = (
        inner.split("),(")
        if "),(" in inner
        else inner.split("), (")
        if "), (" in inner
        else [inner]
    )

    if parts and parts[0].startswith("(") and parts[-1].endswith(")"):
        return [parts[0][1:], *parts[1:-1], parts[-1][:-1]]
    return parts


def _dedupe_preserve_order(values: Iterable[str], /) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _process_rule(address: str, /) -> SingHeadlessRule:
    if not address:
        return {}

    if is_path_like(address):
        if is_wildcard_like(address):
            masked = mask_regex(address)
            return {"process_path_regex": [masked]} if validate_regex(masked) else {}
        if is_regex_like(address):
            return {"process_path_regex": [address]}
        return {"process_path": [address]}

    if is_regex_like(address):
        if match := _DOMAIN_REGEX_OPTION3.match(address):
            prefix, company, app, options = match.groups()
            return {
                "process_name": [
                    f"{prefix}.{company}.{app}.{opt.strip()}"
                    for opt in options.split("|")
                    if opt.strip()
                ],
            }
        if match := _DOMAIN_REGEX_OPTION2.match(address):
            prefix, company, options = match.groups()
            return {
                "process_name": [
                    f"{prefix}.{company}.{opt.strip()}"
                    for opt in options.split("|")
                    if opt.strip()
                ],
            }
        return {}

    return {"process_name": [address]}


def _sing_domain_regex(addresses: Iterable[str], /) -> list[str]:
    return [a for a in addresses if a and validate_regex(a)]


def _sing_domain_wildcard(addresses: Iterable[str], /) -> list[str]:
    converted = (mask_regex(a) for a in addresses if a)
    return [pattern for pattern in converted if validate_regex(pattern)]


def _sing_cidr_rule(cidr_list: Iterable[str], /) -> list[str]:
    return [normalize_cidr(a.removesuffix(",no-resolve")) for a in cidr_list if a]


async def _sing_asn_to_cidrs(asn_list: Sequence[str], /) -> list[str]:
    if not asn_list:
        return []

    merged: list[str] = []
    for asn in asn_list:
        if not asn:
            continue
        if cached := ASN_CACHE.get(asn):
            merged.extend(cached)
            continue

        asn_id = asn.upper().removeprefix("AS").removesuffix("AS")
        if not asn_id.isdigit():
            continue

        urls = (
            f"https://api.bgpview.io/asn/{asn_id}/prefixes",
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_id}",
        )

        cidrs: list[str] = []
        for url in urls:
            with contextlib.suppress(httpx.HTTPError, orjson.JSONDecodeError):
                response = await HTTP_CLIENT.get(url)
                response.raise_for_status()
                body = orjson.loads(response.content)

                if "bgpview" in url:
                    data = body.get("data") or {}
                    ipv4 = data.get("ipv4_prefixes") or []
                    ipv6 = data.get("ipv6_prefixes") or []
                    cidrs = [
                        prefix["prefix"]
                        for prefix in (*ipv4, *ipv6)
                        if isinstance(prefix, dict) and "prefix" in prefix
                    ]
                else:
                    data = body.get("data") or {}
                    prefixes = data.get("prefixes") or []
                    cidrs = [
                        prefix["prefix"]
                        for prefix in prefixes
                        if isinstance(prefix, dict) and "prefix" in prefix
                    ]

                if body.get("status") == "ok" and cidrs:
                    break

        if cidrs:
            unique = _dedupe_preserve_order(cidrs)
            ASN_CACHE[asn] = unique
            merged.extend(unique)

    return _dedupe_preserve_order(merged)


async def compose_sing(frame: pl.DataFrame, cidrs: list[str]) -> SingRuleSet:
    subnet_types = {"WIFI": "wifi", "WIRED": "ethernet", "CELLULAR": "cellular"}

    async def _sing_logical_rule(
        addresses: Sequence[str],
        *,
        mode: Literal["and", "or"],
        invert: bool = False,
    ) -> list[SingLogicalRule]:
        result: list[SingLogicalRule] = []

        for address in addresses:
            sub_rules: list[SingHeadlessRule] = []
            for raw_rule in _logical_rule_parts(address):
                if "," not in raw_rule:
                    continue
                raw_type, raw_value = raw_rule.split(",", 1)
                rule_type = raw_type.strip().upper()
                rule_value = raw_value.strip()
                if not rule_type or not rule_value or rule_type not in SURGE_RULE_TYPES:
                    continue

                sub_rule: SingHeadlessRule | None = None
                match rule_type:
                    case "DOMAIN":
                        sub_rule = {"domain": [rule_value]}
                    case "DOMAIN-SUFFIX":
                        sub_rule = {"domain_suffix": [rule_value]}
                    case "DOMAIN-KEYWORD":
                        sub_rule = {"domain_keyword": [rule_value]}
                    case "DOMAIN-WILDCARD":
                        if patterns := _sing_domain_wildcard([rule_value]):
                            sub_rule = {"domain_regex": patterns}
                    case "IP-CIDR" | "IP-CIDR6":
                        sub_rule = {"ip_cidr": _sing_cidr_rule([rule_value])}
                    case "IP-ASN":
                        asn = rule_value.upper()
                        asn = asn if asn.startswith("AS") else f"AS{asn}"
                        if cidr_list := await _sing_asn_to_cidrs([asn]):
                            sub_rule = {"ip_cidr": cidr_list}
                    case "URL-REGEX":
                        if valid := _sing_domain_regex([rule_value]):
                            sub_rule = {"domain_regex": valid}
                    case "PROCESS-NAME":
                        sub_rule = _process_rule(rule_value)
                    case "SUBNET":
                        upper_value = rule_value.upper()
                        if upper_value in subnet_types:
                            sub_rule = {"network_type": [subnet_types[upper_value]]}
                        elif upper_value == "SSID":
                            sub_rule = {"wifi_ssid": [rule_value]}
                        elif upper_value == "BSSID":
                            sub_rule = {"wifi_bssid": [rule_value]}
                    case "DEST-PORT" | "SRC-PORT" | "IN-PORT":
                        ports, ranges = process_ports([rule_value])
                        prefix = "" if rule_type == "DEST-PORT" else "source_"
                        payload: dict[str, int | list[int] | list[str]] = {}
                        if ports:
                            payload[f"{prefix}port"] = (
                                ports[0] if len(ports) == 1 else ports
                            )
                        if ranges:
                            payload[f"{prefix}port_range"] = ranges
                        if payload:
                            sub_rule = cast("SingHeadlessRule", payload)
                    case "SRC-IP":
                        sub_rule = {"source_ip_cidr": _sing_cidr_rule([rule_value])}

                if sub_rule:
                    sub_rules.append(sub_rule)

            if sub_rules:
                result.append(
                    {
                        "type": "logical",
                        "mode": mode,
                        "rules": sub_rules,
                        "invert": invert,
                    },
                )

        return result

    grouped = frame.group_by("pattern").agg(pl.col("address"))
    rule_groups = {
        row["pattern"]: row["address"]
        for row in grouped.iter_rows(named=True)
        if row["pattern"]
    }

    logical_rules: list[SingLogicalRule] = []
    if addresses := rule_groups.get("AND"):
        logical_rules.extend(await _sing_logical_rule(addresses, mode="and"))
    if addresses := rule_groups.get("OR"):
        logical_rules.extend(await _sing_logical_rule(addresses, mode="or"))
    if addresses := rule_groups.get("NOT"):
        logical_rules.extend(
            await _sing_logical_rule(addresses, mode="and", invert=True),
        )

    regular_rule: dict[str, object] = {}

    for rule_type in SURGE_RULE_TYPES:
        addresses = rule_groups.get(rule_type)
        if not addresses:
            continue

        match rule_type:
            case "DOMAIN":
                cast("list[str]", regular_rule.setdefault("domain", [])).extend(
                    addresses,
                )
            case "DOMAIN-SUFFIX":
                cast("list[str]", regular_rule.setdefault("domain_suffix", [])).extend(
                    addresses,
                )
            case "DOMAIN-KEYWORD":
                cast("list[str]", regular_rule.setdefault("domain_keyword", [])).extend(
                    addresses,
                )
            case "DOMAIN-WILDCARD":
                if patterns := _sing_domain_wildcard(addresses):
                    cast(
                        "list[str]",
                        regular_rule.setdefault("domain_regex", []),
                    ).extend(
                        patterns,
                    )
            case "IP-ASN":
                asns = [
                    a.upper() if a.upper().startswith("AS") else f"AS{a.upper()}"
                    for a in addresses
                    if a
                ]
                if cidr_list := await _sing_asn_to_cidrs(asns):
                    cast("list[str]", regular_rule.setdefault("ip_cidr", [])).extend(
                        cidr_list,
                    )
            case "SUBNET":
                upper = {a.upper() for a in addresses if a}
                if "SSID" in upper:
                    ssids = [a for a in addresses if a and a.upper() != "SSID"]
                    if ssids:
                        cast(
                            "list[str]",
                            regular_rule.setdefault("wifi_ssid", []),
                        ).extend(ssids)
                if "BSSID" in upper:
                    bssids = [a for a in addresses if a and a.upper() != "BSSID"]
                    if bssids:
                        cast(
                            "list[str]",
                            regular_rule.setdefault("wifi_bssid", []),
                        ).extend(bssids)

                types = [
                    subnet_types[a.upper()]
                    for a in addresses
                    if a and a.upper() in subnet_types
                ]
                if types:
                    cast(
                        "list[str]",
                        regular_rule.setdefault("network_type", []),
                    ).extend(
                        types,
                    )
            case "IP-CIDR" | "IP-CIDR6":
                cast("list[str]", regular_rule.setdefault("ip_cidr", [])).extend(
                    _sing_cidr_rule(addresses),
                )
            case "SRC-IP":
                cast("list[str]", regular_rule.setdefault("source_ip_cidr", [])).extend(
                    _sing_cidr_rule(addresses),
                )
            case "DEST-PORT" | "IN-PORT" | "SRC-PORT":
                ports, ranges = process_ports(addresses)
                prefix = "" if rule_type == "DEST-PORT" else "source_"
                if ports:
                    regular_rule[f"{prefix}port"] = (
                        ports[0] if len(ports) == 1 else ports
                    )
                if ranges:
                    cast(
                        "list[str]",
                        regular_rule.setdefault(f"{prefix}port_range", []),
                    ).extend(ranges)
            case "PROCESS-NAME":
                for address in addresses:
                    process_rule = _process_rule(address)
                    for key, value in process_rule.items():
                        if isinstance(value, list):
                            typed_values = [
                                item for item in value if isinstance(item, str)
                            ]
                            if len(typed_values) == len(value):
                                cast(
                                    "list[str]",
                                    regular_rule.setdefault(key, []),
                                ).extend(
                                    typed_values,
                                )
            case "URL-REGEX":
                if valid := _sing_domain_regex(addresses):
                    cast(
                        "list[str]",
                        regular_rule.setdefault("domain_regex", []),
                    ).extend(
                        valid,
                    )

    if cidrs:
        cast("list[str]", regular_rule.setdefault("ip_cidr", [])).extend(
            _sing_cidr_rule(cidrs),
        )

    deduplicated: dict[str, object] = {}
    for key, value in regular_rule.items():
        if not value:
            continue
        if isinstance(value, list):
            ordered = _dedupe_preserve_order(str(v) for v in value)
            if key in {"port", "source_port"}:
                ordered.sort(key=lambda item: int(item) if item.isdigit() else 0)
            deduplicated[key] = ordered
        else:
            deduplicated[key] = value

    final_rules: list[SingLogicalRule | SingHeadlessRule] = [*logical_rules]
    if deduplicated:
        final_rules.append(cast("SingHeadlessRule", deduplicated))

    return {"version": 4, "rules": final_rules}


def compose_meta(
    frame: pl.DataFrame,
    cidrs: list[str],
    category: str,
    /,
) -> list[str] | None:
    def _meta_no_resolve(value: str, /) -> tuple[str, bool]:
        clean = value.removesuffix(",no-resolve")
        return clean, clean != value

    def _meta_cidr_rule(value: str, /, *, src: bool = False) -> str:
        clean, has_no_resolve = _meta_no_resolve(value)
        prefix = "SRC-IP-CIDR" if src else "IP-CIDR"
        suffix = ",no-resolve" if has_no_resolve else ""
        return f"{prefix},{normalize_cidr(clean)}{suffix}"

    def _meta_domain_rule(
        addresses: Sequence[str],
        rule_type: str,
        /,
        *,
        transform: Callable[[str], str] | None = None,
        allow_empty: bool = True,
    ) -> list[str]:
        mapper = transform if transform is not None else (lambda value: value)
        return [
            f"{rule_type},{mapped}"
            for addr in addresses
            if (mapped := mapper(addr)) or allow_empty
        ]

    def _meta_generic_rule(addresses: Sequence[str], rule_type: str, /) -> list[str]:
        return [
            f"{rule_type},{clean}{',no-resolve' if has_no_resolve else ''}"
            for addr in addresses
            for clean, has_no_resolve in (_meta_no_resolve(addr),)
        ]

    def _meta_regex_rule(addresses: Sequence[str], /) -> list[str]:
        results: list[str] = []
        for addr in addresses:
            if validate_regex(addr):
                results.append(f"DOMAIN-REGEX,{addr}")
                continue
            masked = mask_regex(addr)
            if validate_regex(masked):
                results.append(f"DOMAIN-REGEX,{masked}")
        return results

    def _meta_process_rule(addresses: Sequence[str], /) -> list[str]:
        return [
            f"{'PROCESS-PATH' if is_path_like(addr) else 'PROCESS-NAME'}"
            f"{'-WILDCARD' if is_wildcard_like(addr) else '-REGEX' if is_regex_like(addr) else ''}"
            f",{addr}"
            for addr in addresses
        ]

    def _meta_port_rule(
        addresses: Sequence[str],
        label: str,
        /,
        *,
        prefix: str | None = None,
    ) -> list[str]:
        ports, ranges = process_ports(list(addresses))
        if not ports and not ranges:
            return []
        header = f"{prefix},{label}" if prefix else label
        return [f"{header},{port}" for port in ports] + [
            f"{header},{port_range}" for port_range in ranges
        ]

    def _meta_protocol_rule(addresses: Sequence[str], /) -> list[str]:
        return [
            f"NETWORK,{upper}"
            for addr in addresses
            if (upper := addr.upper()) in {"TCP", "UDP"}
        ]

    def _meta_sub_rule(sub_pattern: str, sub_addr: str, /) -> list[str]:
        sub_pattern_upper = sub_pattern.upper()
        if sub_pattern_upper not in SURGE_RULE_TYPES:
            return []

        match sub_pattern_upper:
            case "DOMAIN":
                return [f"DOMAIN,{sub_addr}"]
            case "DOMAIN-SUFFIX":
                return [f"DOMAIN-SUFFIX,{sub_addr.lstrip('.')}"]
            case "DOMAIN-KEYWORD":
                return [f"DOMAIN-KEYWORD,{sub_addr}"]
            case "DOMAIN-WILDCARD":
                return [f"DOMAIN-WILDCARD,{sub_addr}"]
            case "URL-REGEX":
                return _meta_regex_rule([sub_addr])
            case "IP-CIDR" | "IP-CIDR6":
                return [_meta_cidr_rule(sub_addr)]
            case "SRC-IP":
                return [_meta_cidr_rule(sub_addr, src=True)]
            case "DEST-PORT":
                return _meta_port_rule([sub_addr], "DST-PORT")
            case "SRC-PORT" | "IN-PORT":
                return _meta_port_rule([sub_addr], "SRC-PORT")
            case "PROCESS-NAME":
                return _meta_process_rule([sub_addr])
            case "GEOIP":
                return _meta_generic_rule([sub_addr], "GEOIP")
            case "IP-ASN":
                return _meta_generic_rule([sub_addr], "IP-ASN")
            case "PROTOCOL":
                return _meta_protocol_rule([sub_addr])
            case "FINAL":
                return ["MATCH"]
            case (
                "DEVICE-NAME"
                | "MAC-ADDRESS"
                | "HOSTNAME-TYPE"
                | "SCRIPT"
                | "CELLULAR-RADIO"
                | "CELLULAR-CARRIER"
                | "SUBNET"
                | "USER-AGENT"
            ):
                return []
        return []

    def _meta_logical_rule(pattern: str, addresses: Sequence[str], /) -> list[str]:
        results: list[str] = []

        for addr in addresses:
            if not addr:
                continue
            if addr.startswith("((") and addr.endswith("))"):
                sub_results: list[str] = []
                for item in _logical_rule_parts(addr):
                    if "," not in item:
                        continue
                    sub_pattern, sub_addr = item.split(",", 1)
                    clean_pattern = sub_pattern.strip()
                    clean_addr = sub_addr.strip()
                    if not clean_pattern or not clean_addr:
                        continue
                    sub_results.extend(_meta_sub_rule(clean_pattern, clean_addr))
                if sub_results:
                    results.append(f"{pattern},(({'),('.join(sub_results)}))")
                continue

            if "," not in addr:
                results.append(f"{pattern},{addr.strip()}")
                continue

            sub_pattern, sub_addr = addr.split(",", 1)
            clean_pattern = sub_pattern.strip().upper()
            clean_addr = sub_addr.strip()
            if (
                not clean_pattern
                or not clean_addr
                or clean_pattern not in SURGE_RULE_TYPES
            ):
                continue

            match clean_pattern:
                case "PROCESS-NAME":
                    results.extend(_meta_process_rule([clean_addr]))
                case "IP-CIDR" | "IP-CIDR6":
                    results.append(f"{pattern},{_meta_cidr_rule(clean_addr)}")
                case "DEST-PORT":
                    results.extend(
                        _meta_port_rule([clean_addr], "DST-PORT", prefix=pattern),
                    )
                case "SRC-PORT" | "IN-PORT":
                    results.extend(
                        _meta_port_rule([clean_addr], "SRC-PORT", prefix=pattern),
                    )
                case _:
                    results.append(f"{pattern},{clean_pattern},{clean_addr}")

        return results

    def _meta_rules(pattern: str, addresses: Sequence[str], /) -> list[str]:
        match pattern:
            case "DOMAIN":
                return _meta_domain_rule(addresses, "DOMAIN")
            case "DOMAIN-SUFFIX":
                return _meta_domain_rule(
                    addresses,
                    "DOMAIN-SUFFIX",
                    transform=lambda value: value.lstrip("."),
                )
            case "DOMAIN-KEYWORD":
                return _meta_domain_rule(addresses, "DOMAIN-KEYWORD")
            case "DOMAIN-WILDCARD":
                return _meta_domain_rule(
                    addresses,
                    "DOMAIN-WILDCARD",
                    allow_empty=False,
                )
            case "DOMAIN-SET":
                return [f"RULE-SET,{addr}" for addr in addresses]
            case "IP-CIDR" | "IP-CIDR6":
                return [_meta_cidr_rule(addr) for addr in addresses]
            case "GEOIP":
                return _meta_generic_rule(addresses, "GEOIP")
            case "IP-ASN":
                return _meta_generic_rule(addresses, "IP-ASN")
            case "URL-REGEX":
                return _meta_regex_rule(addresses)
            case "PROCESS-NAME":
                return _meta_process_rule(addresses)
            case "DEST-PORT":
                return _meta_port_rule(addresses, "DST-PORT")
            case "SRC-PORT" | "IN-PORT":
                return _meta_port_rule(addresses, pattern)
            case "SRC-IP":
                return [_meta_cidr_rule(addr, src=True) for addr in addresses]
            case "PROTOCOL":
                return _meta_protocol_rule(addresses)
            case "FINAL":
                return ["MATCH"]
            case (
                "DEVICE-NAME"
                | "MAC-ADDRESS"
                | "HOSTNAME-TYPE"
                | "SCRIPT"
                | "CELLULAR-RADIO"
                | "CELLULAR-CARRIER"
                | "SUBNET"
                | "USER-AGENT"
            ):
                return []
            case "AND" | "OR" | "NOT":
                return _meta_logical_rule(pattern, addresses)
        return []

    grouped = frame.group_by("pattern").agg(pl.col("address"))
    grouped_rows = tuple(grouped.iter_rows(named=True))
    patterns = {
        row["pattern"]: row["address"] for row in grouped_rows if row["pattern"]
    }

    if category == "domainset":
        rules = [
            f"+{addr}" if addr.startswith(".") else addr
            for row in grouped_rows
            for addr in row["address"]
            if addr
        ]
    else:
        rules = [
            rule
            for pattern in SURGE_RULE_TYPES
            if (addresses := patterns.get(pattern))
            for rule in _meta_rules(pattern, addresses)
        ]

    if cidrs:
        rules.extend(f"IP-CIDR,{normalize_cidr(cidr)}" for cidr in cidrs)

    return rules or None


async def prepare_frame(url: str, /) -> tuple[pl.DataFrame, list[str]] | None:
    if url.startswith("file://"):
        source = unquote(url.removeprefix("file://"))
        async with await anyio.Path(source).open("r", encoding="utf-8") as handle:
            payload = await handle.read()
    else:
        response = await HTTP_CLIENT.get(url)
        response.raise_for_status()
        payload = response.text

    lines = [
        line
        for raw in payload.splitlines()
        if (line := raw.strip()) and not line.startswith("#")
    ]

    def _parse_line(line: str, /) -> dict[str, str]:
        if "," in line:
            parts = [part.strip() for part in line.split(",", 2)]
            if len(parts) == 1:
                return {"pattern": parts[0], "address": ""}
            if len(parts) == 2:
                return {"pattern": parts[0], "address": parts[1]}
            address = parts[1] if not parts[2] else f"{parts[1]},{parts[2]}"
            return {"pattern": parts[0], "address": address}

        entry = line.strip("'\"")
        with contextlib.suppress(ValueError):
            ipaddress.ip_network(entry, strict=False)
            return {"pattern": "IP-CIDR", "address": entry}

        is_plus = entry.startswith("+")
        return {
            "pattern": "DOMAIN-SUFFIX" if is_plus else "DOMAIN",
            "address": entry.removeprefix("+").lstrip(".") if is_plus else entry,
        }

    frame = pl.DataFrame(_parse_line(line) for line in lines)
    if frame.is_empty() or not frame.columns:
        return None

    excluded_addresses = {
        "",
        "#",
        "th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe",
        "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
    }

    frame = frame.filter(
        ~pl.col("pattern").str.contains("#")
        & ~pl.col("address").is_in(excluded_addresses),
    )

    if frame.is_empty():
        return None

    return frame, []


async def emit_meta_file(
    url: str,
    directory: str,
    category: str,
    /,
) -> anyio.Path | None:
    result = await prepare_frame(url)
    if result is None:
        return None

    frame, cidrs = result

    output_dir = anyio.Path(directory)
    await output_dir.mkdir(exist_ok=True, parents=True)

    filename = anyio.Path(url).stem.replace("_", "-")
    source_path = unquote(url.removeprefix("file://"))

    if source_path.endswith(("china_ip.conf", "china_ip_ipv6.conf")):
        ip_addresses = [
            row["address"].removeprefix("IP-CIDR,").removeprefix("IP-CIDR6,")
            for row in frame.iter_rows(named=True)
            if row["pattern"] in {"IP-CIDR", "IP-CIDR6"}
        ]
        if not ip_addresses:
            return None

        file_path = output_dir / f"{filename}.{category}.txt"
        async with await file_path.open("w", encoding="utf-8", newline="\n") as handle:
            await handle.write("\n".join(ip_addresses))
        return file_path

    rules = compose_meta(frame, cidrs, category)
    if not rules:
        return None

    file_path = output_dir / f"{filename}.{category}.txt"
    async with await file_path.open("w", encoding="utf-8", newline="\n") as handle:
        await handle.write("\n".join(rules))

    return file_path


async def emit_sing_file(
    url: str,
    directory: str,
    category: str,
    /,
) -> anyio.Path | None:
    result = await prepare_frame(url)
    if result is None:
        return None

    frame, cidrs = result

    output_dir = anyio.Path(directory)
    await output_dir.mkdir(exist_ok=True, parents=True)

    rules = await compose_sing(frame, cidrs)
    if not rules.get("rules"):
        return None

    filename = anyio.Path(url).stem.replace("_", "-")
    file_path = output_dir / f"{filename}.{category}.json"
    async with await file_path.open("wb") as handle:
        await handle.write(orjson.dumps(rules, option=orjson.OPT_INDENT_2))

    return file_path


async def find_directory(*paths: str) -> anyio.Path | None:
    for path in paths:
        path_obj = anyio.Path(path)
        if await path_obj.exists():
            return path_obj
    return None


async def ensure_directories(
    base_dirs: Sequence[anyio.Path],
    subdirs: frozenset[str],
    /,
) -> None:
    await asyncio.gather(
        *[
            (base / subdir).mkdir(exist_ok=True, parents=True)
            for base in base_dirs
            for subdir in subdirs
        ],
    )


async def collect_files(
    list_dir: anyio.Path,
    categories: frozenset[str],
    /,
) -> list[tuple[anyio.Path, str]]:
    files: list[tuple[anyio.Path, str]] = []
    for category in categories:
        category_dir = list_dir / category
        if not await category_dir.exists():
            continue
        files.extend([(file, category) async for file in category_dir.glob("*.conf")])
    return files


async def create_tasks(
    conf_files: Sequence[tuple[anyio.Path, str]],
    base_dir: anyio.Path,
    emit_func: Callable[[str, str, str], Coroutine[object, object, anyio.Path | None]],
    /,
) -> list[asyncio.Task[anyio.Path | None]]:
    tasks: list[asyncio.Task[anyio.Path | None]] = []
    for file, category in conf_files:
        absolute = await file.absolute()
        task = asyncio.create_task(
            emit_func(f"file://{absolute}", str(base_dir / category), category),
        )
        tasks.append(task)
    return tasks


async def main() -> None:
    text_json_subdirs = frozenset({"domainset", "ip", "non_ip", "dns"})
    categories = frozenset({"domainset", "ip", "non_ip"})

    list_dir = await find_directory("List", "../List")
    if list_dir is None:
        await HTTP_CLIENT.aclose()
        return

    sing_json_base = anyio.Path("sing-box/json")
    meta_text_base = anyio.Path("mihomo/text")

    try:
        await ensure_directories((sing_json_base, meta_text_base), text_json_subdirs)

        conf_files = await collect_files(list_dir, categories)

        sing_tasks = await create_tasks(conf_files, sing_json_base, emit_sing_file)
        meta_tasks = await create_tasks(conf_files, meta_text_base, emit_meta_file)

        modules_dir = await find_directory(
            "Modules/Rules/sukka_local_dns_mapping",
            "../Modules/Rules/sukka_local_dns_mapping",
        )
        if modules_dir is not None:
            dns_files = [(file, "dns") async for file in modules_dir.glob("*.conf")]
            sing_tasks.extend(
                await create_tasks(dns_files, sing_json_base, emit_sing_file),
            )
            meta_tasks.extend(
                await create_tasks(dns_files, meta_text_base, emit_meta_file),
            )

        all_tasks = [*sing_tasks, *meta_tasks]
        if all_tasks:
            await asyncio.gather(*all_tasks)
    finally:
        await HTTP_CLIENT.aclose()


if __name__ == "__main__":
    asyncio.run(main())
