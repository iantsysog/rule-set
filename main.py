import asyncio
import contextlib
import ipaddress
import re
from collections.abc import Callable, Coroutine, Iterable, Sequence
from typing import Final, Literal, NotRequired, TypedDict, cast
from urllib.parse import unquote, urlparse

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


SURGE_RULE_TYPES: Final[tuple[str, ...]] = (
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
)
SURGE_RULE_TYPES_SET: Final[frozenset[str]] = frozenset(SURGE_RULE_TYPES)

REGEX_CHARS: Final[frozenset[str]] = frozenset(r"*+?^${}()|[]\\")
CHAR_MAP: Final[dict[str, str]] = {
    ".": r"\\.",
    "*": r"[\\w.-]*?",
    "?": r"[\\w.-]",
}

DOMAIN_REGEX_OPTION3: Final[re.Pattern[str]] = re.compile(
    r"^([^.]+)\.([^.]+)\.([^.]+)\.\(([^)]+)\)$"
)
DOMAIN_REGEX_OPTION2: Final[re.Pattern[str]] = re.compile(
    r"^([^.]+)\.([^.]+)\.\(([^)]+)\)$"
)
LOGICAL_PARENS: Final[re.Pattern[str]] = re.compile(r"\(([^()]*)\)")

SUBNET_TYPES: Final[dict[str, str]] = {
    "WIFI": "wifi",
    "WIRED": "ethernet",
    "CELLULAR": "cellular",
}
NETWORK_PROTOCOLS: Final[frozenset[str]] = frozenset({"TCP", "UDP"})

EXCLUDED_ADDRESSES: Final[frozenset[str]] = frozenset(
    {
        "",
        "#",
        "th1s_rule5et_1s_m4d3_by_5ukk4w_ruleset.skk.moe",
        "7h1s_rul35et_i5_mad3_by_5ukk4w-ruleset.skk.moe",
    },
)

HTTP_CLIENT = httpx.AsyncClient(
    timeout=httpx.Timeout(10.0, pool=30.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
    follow_redirects=True,
    http2=True,
    trust_env=False,
)

_ASN_CACHE: dict[str, list[str]] = {}
_ASN_LOCK = asyncio.Lock()


def validate_regex(pattern: str, /) -> bool:
    if not pattern:
        return False
    with contextlib.suppress(re.error):
        re.compile(pattern)
        return True
    return False


def mask_regex(pattern: str, /) -> str:
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


def process_ports(addresses: Iterable[str], /) -> tuple[list[int], list[str]]:
    ports: list[int] = []
    ranges: list[str] = []

    for raw in addresses:
        item = raw.strip()
        if not item:
            continue
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

        port = _normalize_port(item)
        if port is not None:
            ports.append(port)

    return ports, ranges


def is_regex_like(value: str, /) -> bool:
    return any(ch in REGEX_CHARS for ch in value) and validate_regex(value)


def is_wildcard_like(value: str, /) -> bool:
    return "*" in value or "?" in value


def is_path_like(value: str, /) -> bool:
    return "/" in value or (len(value) > 1 and value[0].isalpha() and value[1] == ":")


def _logical_rule_parts(address: str, /) -> list[str]:
    if not (address.startswith("((") and address.endswith("))")):
        return []

    inner = address[2:-2].strip()
    if not inner:
        return []

    matches = [match.group(1).strip() for match in LOGICAL_PARENS.finditer(inner)]
    if matches:
        return [match for match in matches if match]

    if "),(" in inner:
        parts = inner.split("),(")
    elif "), (" in inner:
        parts = inner.split("), (")
    else:
        parts = [inner]

    if parts and parts[0].startswith("(") and parts[-1].endswith(")"):
        return [parts[0][1:], *parts[1:-1], parts[-1][:-1]]
    return parts


def _dedupe_preserve_order(values: Iterable[str], /) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


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
        if match := DOMAIN_REGEX_OPTION3.match(address):
            prefix, company, app, options = match.groups()
            process_names = [
                f"{prefix}.{company}.{app}.{option.strip()}"
                for option in options.split("|")
                if option.strip()
            ]
            return {"process_name": process_names} if process_names else {}

        if match := DOMAIN_REGEX_OPTION2.match(address):
            prefix, company, options = match.groups()
            process_names = [
                f"{prefix}.{company}.{option.strip()}"
                for option in options.split("|")
                if option.strip()
            ]
            return {"process_name": process_names} if process_names else {}

        return {}

    return {"process_name": [address]}


def _sing_domain_regex(addresses: Iterable[str], /) -> list[str]:
    return [address for address in addresses if address and validate_regex(address)]


def _sing_domain_wildcard(addresses: Iterable[str], /) -> list[str]:
    patterns = (mask_regex(address) for address in addresses if address)
    return [pattern for pattern in patterns if validate_regex(pattern)]


def _strip_no_resolve(value: str, /) -> tuple[str, bool]:
    clean = value.removesuffix(",no-resolve")
    return clean, clean != value


def _sing_cidr_rule(cidr_list: Iterable[str], /) -> list[str]:
    return [
        normalize_cidr(address.removesuffix(",no-resolve"))
        for address in cidr_list
        if address
    ]


async def _fetch_asn_cidrs(asn_id: str, /) -> list[str]:
    urls = (
        f"https://api.bgpview.io/asn/{asn_id}/prefixes",
        f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_id}",
    )

    for url in urls:
        with contextlib.suppress(httpx.HTTPError, orjson.JSONDecodeError):
            response = await HTTP_CLIENT.get(url)
            response.raise_for_status()
            payload = orjson.loads(response.content)

            if "bgpview" in url:
                data = payload.get("data") or {}
                prefixes = [
                    prefix.get("prefix")
                    for prefix in [
                        *(data.get("ipv4_prefixes") or []),
                        *(data.get("ipv6_prefixes") or []),
                    ]
                    if isinstance(prefix, dict)
                ]
            else:
                data = payload.get("data") or {}
                prefixes = [
                    prefix.get("prefix")
                    for prefix in (data.get("prefixes") or [])
                    if isinstance(prefix, dict)
                ]

            cidrs = [
                prefix for prefix in prefixes if isinstance(prefix, str) and prefix
            ]
            if payload.get("status") == "ok" and cidrs:
                return _dedupe_preserve_order(cidrs)

    return []


async def _sing_asn_to_cidrs(asn_list: Sequence[str], /) -> list[str]:
    if not asn_list:
        return []

    merged: list[str] = []
    for asn in asn_list:
        if not asn:
            continue
        normalized_asn = asn.upper().removeprefix("AS").removesuffix("AS")
        if not normalized_asn.isdigit():
            continue
        cache_key = f"AS{normalized_asn}"

        cached = _ASN_CACHE.get(cache_key)
        if cached is not None:
            merged.extend(cached)
            continue

        cidrs = await _fetch_asn_cidrs(normalized_asn)
        if cidrs:
            async with _ASN_LOCK:
                _ASN_CACHE.setdefault(cache_key, cidrs)
            merged.extend(cidrs)

    return _dedupe_preserve_order(merged)


def _append_rule_values(
    target: dict[str, object], key: str, values: Iterable[str], /
) -> None:
    typed = cast("list[str]", target.setdefault(key, []))
    typed.extend(value for value in values if value)


def _as_single_or_list(values: list[int], /) -> int | list[int]:
    return values[0] if len(values) == 1 else values


def _to_filename_stem(url: str, /) -> str:
    parsed = urlparse(url)
    raw_path = parsed.path if parsed.scheme else url
    stem = anyio.Path(unquote(raw_path)).stem
    return stem.replace("_", "-")


def _file_url_to_source(url: str, /) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "file":
        return ""
    host = f"//{parsed.netloc}" if parsed.netloc else ""
    return unquote(f"{host}{parsed.path}")


async def compose_sing(frame: pl.DataFrame, cidrs: list[str]) -> SingRuleSet:
    async def build_logical_rules(
        addresses: Sequence[str],
        *,
        mode: Literal["and", "or"],
        invert: bool = False,
    ) -> list[SingLogicalRule]:
        results: list[SingLogicalRule] = []

        for address in addresses:
            sub_rules: list[SingHeadlessRule] = []
            for raw in _logical_rule_parts(address):
                if "," not in raw:
                    continue
                raw_type, raw_value = raw.split(",", 1)
                rule_type = raw_type.strip().upper()
                rule_value = raw_value.strip()
                if (
                    not rule_type
                    or not rule_value
                    or rule_type not in SURGE_RULE_TYPES_SET
                ):
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
                        if normalized := _sing_cidr_rule([rule_value]):
                            sub_rule = {"ip_cidr": normalized}
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
                        if upper_value in SUBNET_TYPES:
                            sub_rule = {"network_type": [SUBNET_TYPES[upper_value]]}
                        elif upper_value == "SSID":
                            sub_rule = {"wifi_ssid": [rule_value]}
                        elif upper_value == "BSSID":
                            sub_rule = {"wifi_bssid": [rule_value]}
                    case "DEST-PORT" | "SRC-PORT" | "IN-PORT":
                        ports, ranges = process_ports([rule_value])
                        prefix = "" if rule_type == "DEST-PORT" else "source_"
                        payload: dict[str, int | list[int] | list[str]] = {}
                        if ports:
                            payload[f"{prefix}port"] = _as_single_or_list(ports)
                        if ranges:
                            payload[f"{prefix}port_range"] = ranges
                        if payload:
                            sub_rule = cast("SingHeadlessRule", payload)
                    case "SRC-IP":
                        if normalized := _sing_cidr_rule([rule_value]):
                            sub_rule = {"source_ip_cidr": normalized}

                if sub_rule:
                    sub_rules.append(sub_rule)

            if sub_rules:
                results.append(
                    {
                        "type": "logical",
                        "mode": mode,
                        "rules": sub_rules,
                        "invert": invert,
                    },
                )

        return results

    grouped = frame.group_by("pattern").agg(pl.col("address"))
    grouped_map: dict[str, list[str]] = {
        cast("str", row["pattern"]): cast("list[str]", row["address"])
        for row in grouped.iter_rows(named=True)
        if row["pattern"]
    }

    logical_rules: list[SingLogicalRule] = []
    if addresses := grouped_map.get("AND"):
        logical_rules.extend(await build_logical_rules(addresses, mode="and"))
    if addresses := grouped_map.get("OR"):
        logical_rules.extend(await build_logical_rules(addresses, mode="or"))
    if addresses := grouped_map.get("NOT"):
        logical_rules.extend(
            await build_logical_rules(addresses, mode="and", invert=True)
        )

    regular: dict[str, object] = {}

    for rule_type in SURGE_RULE_TYPES:
        addresses = grouped_map.get(rule_type)
        if not addresses:
            continue

        match rule_type:
            case "DOMAIN":
                _append_rule_values(regular, "domain", addresses)
            case "DOMAIN-SUFFIX":
                _append_rule_values(regular, "domain_suffix", addresses)
            case "DOMAIN-KEYWORD":
                _append_rule_values(regular, "domain_keyword", addresses)
            case "DOMAIN-WILDCARD":
                _append_rule_values(
                    regular, "domain_regex", _sing_domain_wildcard(addresses)
                )
            case "IP-ASN":
                asns = [
                    address.upper()
                    if address.upper().startswith("AS")
                    else f"AS{address.upper()}"
                    for address in addresses
                    if address
                ]
                _append_rule_values(regular, "ip_cidr", await _sing_asn_to_cidrs(asns))
            case "SUBNET":
                upper = {address.upper() for address in addresses if address}
                if "SSID" in upper:
                    _append_rule_values(
                        regular,
                        "wifi_ssid",
                        (
                            address
                            for address in addresses
                            if address and address.upper() != "SSID"
                        ),
                    )
                if "BSSID" in upper:
                    _append_rule_values(
                        regular,
                        "wifi_bssid",
                        (
                            address
                            for address in addresses
                            if address and address.upper() != "BSSID"
                        ),
                    )
                _append_rule_values(
                    regular,
                    "network_type",
                    (
                        SUBNET_TYPES[address.upper()]
                        for address in addresses
                        if address and address.upper() in SUBNET_TYPES
                    ),
                )
            case "IP-CIDR" | "IP-CIDR6":
                _append_rule_values(regular, "ip_cidr", _sing_cidr_rule(addresses))
            case "SRC-IP":
                _append_rule_values(
                    regular, "source_ip_cidr", _sing_cidr_rule(addresses)
                )
            case "DEST-PORT" | "IN-PORT" | "SRC-PORT":
                ports, ranges = process_ports(addresses)
                prefix = "" if rule_type == "DEST-PORT" else "source_"
                if ports:
                    regular[f"{prefix}port"] = _as_single_or_list(ports)
                if ranges:
                    _append_rule_values(regular, f"{prefix}port_range", ranges)
            case "PROCESS-NAME":
                for address in addresses:
                    process_rule = _process_rule(address)
                    for key, value in process_rule.items():
                        if isinstance(value, list):
                            _append_rule_values(
                                regular,
                                key,
                                (item for item in value if isinstance(item, str)),
                            )
            case "URL-REGEX":
                _append_rule_values(
                    regular, "domain_regex", _sing_domain_regex(addresses)
                )

    _append_rule_values(regular, "ip_cidr", _sing_cidr_rule(cidrs))

    deduplicated: dict[str, object] = {}
    for key, value in regular.items():
        if isinstance(value, list):
            deduped = _dedupe_preserve_order(str(item) for item in value)
            if not deduped:
                continue
            if key in {"port", "source_port"}:
                deduped.sort(key=lambda item: int(item) if item.isdigit() else 0)
            deduplicated[key] = deduped
        elif value:
            deduplicated[key] = value

    all_rules: list[SingLogicalRule | SingHeadlessRule] = [*logical_rules]
    if deduplicated:
        all_rules.append(cast("SingHeadlessRule", deduplicated))

    return {"version": 4, "rules": all_rules}


def compose_meta(
    frame: pl.DataFrame, cidrs: list[str], category: str, /
) -> list[str] | None:
    def cidr_rule(value: str, /, *, src: bool = False) -> str:
        clean, has_no_resolve = _strip_no_resolve(value)
        prefix = "SRC-IP-CIDR" if src else "IP-CIDR"
        suffix = ",no-resolve" if has_no_resolve else ""
        return f"{prefix},{normalize_cidr(clean)}{suffix}"

    def domain_rule(
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
            for address in addresses
            if (mapped := mapper(address)) or allow_empty
        ]

    def generic_rule(addresses: Sequence[str], rule_type: str, /) -> list[str]:
        return [
            f"{rule_type},{clean}{',no-resolve' if has_no_resolve else ''}"
            for address in addresses
            for clean, has_no_resolve in (_strip_no_resolve(address),)
        ]

    def regex_rule(addresses: Sequence[str], /) -> list[str]:
        results: list[str] = []
        for address in addresses:
            if validate_regex(address):
                results.append(f"DOMAIN-REGEX,{address}")
                continue
            masked = mask_regex(address)
            if validate_regex(masked):
                results.append(f"DOMAIN-REGEX,{masked}")
        return results

    def process_rule(addresses: Sequence[str], /) -> list[str]:
        return [
            f"{'PROCESS-PATH' if is_path_like(address) else 'PROCESS-NAME'}"
            f"{'-WILDCARD' if is_wildcard_like(address) else '-REGEX' if is_regex_like(address) else ''}"
            f",{address}"
            for address in addresses
        ]

    def port_rule(
        addresses: Sequence[str],
        label: str,
        /,
        *,
        prefix: str | None = None,
    ) -> list[str]:
        ports, ranges = process_ports(addresses)
        if not ports and not ranges:
            return []
        header = f"{prefix},{label}" if prefix else label
        return [f"{header},{port}" for port in ports] + [
            f"{header},{port_range}" for port_range in ranges
        ]

    def protocol_rule(addresses: Sequence[str], /) -> list[str]:
        return [
            f"NETWORK,{upper}"
            for address in addresses
            if (upper := address.upper()) in NETWORK_PROTOCOLS
        ]

    def sub_rule(sub_pattern: str, sub_address: str, /) -> list[str]:
        rule_type = sub_pattern.upper()
        if rule_type not in SURGE_RULE_TYPES_SET:
            return []

        match rule_type:
            case "DOMAIN":
                return [f"DOMAIN,{sub_address}"]
            case "DOMAIN-SUFFIX":
                return [f"DOMAIN-SUFFIX,{sub_address.lstrip('.')}"]
            case "DOMAIN-KEYWORD":
                return [f"DOMAIN-KEYWORD,{sub_address}"]
            case "DOMAIN-WILDCARD":
                return [f"DOMAIN-WILDCARD,{sub_address}"]
            case "URL-REGEX":
                return regex_rule([sub_address])
            case "IP-CIDR" | "IP-CIDR6":
                return [cidr_rule(sub_address)]
            case "SRC-IP":
                return [cidr_rule(sub_address, src=True)]
            case "DEST-PORT":
                return port_rule([sub_address], "DST-PORT")
            case "SRC-PORT" | "IN-PORT":
                return port_rule([sub_address], "SRC-PORT")
            case "PROCESS-NAME":
                return process_rule([sub_address])
            case "GEOIP":
                return generic_rule([sub_address], "GEOIP")
            case "IP-ASN":
                return generic_rule([sub_address], "IP-ASN")
            case "PROTOCOL":
                return protocol_rule([sub_address])
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

    def logical_rule(pattern: str, addresses: Sequence[str], /) -> list[str]:
        results: list[str] = []

        for address in addresses:
            if not address:
                continue
            if address.startswith("((") and address.endswith("))"):
                sub_results: list[str] = []
                for item in _logical_rule_parts(address):
                    if "," not in item:
                        continue
                    sub_pattern, sub_address = item.split(",", 1)
                    clean_pattern = sub_pattern.strip()
                    clean_address = sub_address.strip()
                    if not clean_pattern or not clean_address:
                        continue
                    sub_results.extend(sub_rule(clean_pattern, clean_address))
                if sub_results:
                    results.append(f"{pattern},(({'),('.join(sub_results)}))")
                continue

            if "," not in address:
                results.append(f"{pattern},{address.strip()}")
                continue

            sub_pattern, sub_address = address.split(",", 1)
            clean_pattern = sub_pattern.strip().upper()
            clean_address = sub_address.strip()
            if (
                not clean_pattern
                or not clean_address
                or clean_pattern not in SURGE_RULE_TYPES_SET
            ):
                continue

            match clean_pattern:
                case "PROCESS-NAME":
                    results.extend(process_rule([clean_address]))
                case "IP-CIDR" | "IP-CIDR6":
                    results.append(f"{pattern},{cidr_rule(clean_address)}")
                case "DEST-PORT":
                    results.extend(
                        port_rule([clean_address], "DST-PORT", prefix=pattern)
                    )
                case "SRC-PORT" | "IN-PORT":
                    results.extend(
                        port_rule([clean_address], "SRC-PORT", prefix=pattern)
                    )
                case _:
                    results.append(f"{pattern},{clean_pattern},{clean_address}")

        return results

    def rules_for(pattern: str, addresses: Sequence[str], /) -> list[str]:
        match pattern:
            case "DOMAIN":
                return domain_rule(addresses, "DOMAIN")
            case "DOMAIN-SUFFIX":
                return domain_rule(
                    addresses,
                    "DOMAIN-SUFFIX",
                    transform=lambda value: value.lstrip("."),
                )
            case "DOMAIN-KEYWORD":
                return domain_rule(addresses, "DOMAIN-KEYWORD")
            case "DOMAIN-WILDCARD":
                return domain_rule(addresses, "DOMAIN-WILDCARD", allow_empty=False)
            case "DOMAIN-SET":
                return [f"RULE-SET,{address}" for address in addresses]
            case "IP-CIDR" | "IP-CIDR6":
                return [cidr_rule(address) for address in addresses]
            case "GEOIP":
                return generic_rule(addresses, "GEOIP")
            case "IP-ASN":
                return generic_rule(addresses, "IP-ASN")
            case "URL-REGEX":
                return regex_rule(addresses)
            case "PROCESS-NAME":
                return process_rule(addresses)
            case "DEST-PORT":
                return port_rule(addresses, "DST-PORT")
            case "SRC-PORT" | "IN-PORT":
                return port_rule(addresses, pattern)
            case "SRC-IP":
                return [cidr_rule(address, src=True) for address in addresses]
            case "PROTOCOL":
                return protocol_rule(addresses)
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
                return logical_rule(pattern, addresses)
        return []

    grouped = frame.group_by("pattern").agg(pl.col("address"))
    rows = tuple(grouped.iter_rows(named=True))
    patterns: dict[str, list[str]] = {
        cast("str", row["pattern"]): cast("list[str]", row["address"])
        for row in rows
        if row["pattern"]
    }

    if category == "domainset":
        rules = [
            f"+{address}" if address.startswith(".") else address
            for row in rows
            for address in cast("list[str]", row["address"])
            if address
        ]
    else:
        rules = [
            rule
            for pattern in SURGE_RULE_TYPES
            if (addresses := patterns.get(pattern))
            for rule in rules_for(pattern, addresses)
        ]

    if cidrs:
        rules.extend(f"IP-CIDR,{normalize_cidr(cidr)}" for cidr in cidrs if cidr)

    return rules or None


async def prepare_frame(url: str, /) -> tuple[pl.DataFrame, list[str]] | None:
    parsed = urlparse(url)
    if parsed.scheme == "file":
        source = _file_url_to_source(url)
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

    def parse_line(line: str, /) -> dict[str, str]:
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

    frame = pl.DataFrame(parse_line(line) for line in lines)
    if frame.is_empty() or not frame.columns:
        return None

    frame = frame.filter(
        ~pl.col("pattern").str.contains("#", literal=True)
        & ~pl.col("address").is_in(EXCLUDED_ADDRESSES),
    )

    if frame.is_empty():
        return None

    return frame, []


async def emit_meta_file(
    url: str, directory: str, category: str, /
) -> anyio.Path | None:
    result = await prepare_frame(url)
    if result is None:
        return None

    frame, cidrs = result

    output_dir = anyio.Path(directory)
    await output_dir.mkdir(exist_ok=True, parents=True)

    filename = _to_filename_stem(url)
    source_path = _file_url_to_source(url)

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
    url: str, directory: str, category: str, /
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

    filename = _to_filename_stem(url)
    file_path = output_dir / f"{filename}.{category}.json"
    async with await file_path.open("wb") as handle:
        await handle.write(orjson.dumps(rules, option=orjson.OPT_INDENT_2))

    return file_path


async def find_directory(*paths: str) -> anyio.Path | None:
    for path in paths:
        candidate = anyio.Path(path)
        if await candidate.exists():
            return candidate
    return None


async def ensure_directories(
    base_dirs: Sequence[anyio.Path], subdirs: frozenset[str], /
) -> None:
    await asyncio.gather(
        *(
            (base / subdir).mkdir(exist_ok=True, parents=True)
            for base in base_dirs
            for subdir in subdirs
        ),
    )


async def collect_files(
    list_dir: anyio.Path, categories: frozenset[str], /
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
        tasks.append(
            asyncio.create_task(
                emit_func(f"file://{absolute}", str(base_dir / category), category),
            ),
        )
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
                await create_tasks(dns_files, sing_json_base, emit_sing_file)
            )
            meta_tasks.extend(
                await create_tasks(dns_files, meta_text_base, emit_meta_file)
            )

        all_tasks = [*sing_tasks, *meta_tasks]
        if all_tasks:
            await asyncio.gather(*all_tasks)
    finally:
        await HTTP_CLIENT.aclose()


if __name__ == "__main__":
    asyncio.run(main())
