"""Cedar value model (stdlib only).

Cedar has Bool, Long (i64), String, Set, Record, Entity references and four extension
types: decimal, datetime, duration and ipaddr. Python primitives are used where they
match (``bool``, ``int``, ``str``); everything else is a small frozen class so that
values are hashable (temporal evaluation keeps relational rows in sets).
"""

from __future__ import annotations

import datetime as _dt
import decimal as _decimal
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, Mapping, Tuple

from .errors import EvalError

I64_MIN = -(2**63)
I64_MAX = 2**63 - 1


def check_long(n: int, what: str = "integer") -> int:
    """Return ``n`` if it fits a Cedar Long (signed 64-bit), else raise EvalError."""
    if not (I64_MIN <= n <= I64_MAX):
        raise EvalError(f"{what} overflow: {n} does not fit a 64-bit Long")
    return n


def escape_string(s: str) -> str:
    """Render ``s`` as a Cedar string literal body (inverse of the lexer's unescape)."""
    out = []
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\0":
            out.append("\\0")
        else:
            out.append(ch)
    return "".join(out)


@dataclass(frozen=True)
class EntityRef:
    """An entity reference ``Ns::Type::"id"``. ``type`` is the full ``::`` path."""

    type: str
    id: str

    def __str__(self) -> str:
        return f'{self.type}::"{escape_string(self.id)}"'

    @property
    def namespace(self) -> str:
        head, _, _ = self.type.rpartition("::")
        return head

    @property
    def base_type(self) -> str:
        return self.type.rpartition("::")[2]


class SetValue:
    """A Cedar Set: unordered, duplicate-free, compared by membership."""

    __slots__ = ("_items",)

    def __init__(self, items: Iterable[Any] = ()):
        uniq: list = []
        for it in items:
            if not any(values_equal(it, u) for u in uniq):
                uniq.append(it)
        self._items = tuple(uniq)

    @property
    def items(self) -> Tuple[Any, ...]:
        return self._items

    def __iter__(self) -> Iterator[Any]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def contains(self, v: Any) -> bool:
        return any(values_equal(v, u) for u in self._items)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SetValue):
            return NotImplemented
        return len(self) == len(other) and all(other.contains(v) for v in self._items)

    def __hash__(self) -> int:
        return hash(frozenset(hash_key(v) for v in self._items))

    def __repr__(self) -> str:
        return "[" + ", ".join(render(v) for v in self._items) + "]"


class Record(Mapping[str, Any]):
    """A Cedar Record: an immutable string-keyed mapping."""

    __slots__ = ("_d",)

    def __init__(self, d: Mapping[str, Any] | Iterable[Tuple[str, Any]] = ()):
        self._d = dict(d)

    def __getitem__(self, k: str) -> Any:
        return self._d[k]

    def __iter__(self) -> Iterator[str]:
        return iter(self._d)

    def __len__(self) -> int:
        return len(self._d)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Mapping):
            return NotImplemented
        return set(self._d) == set(other) and all(
            values_equal(self._d[k], other[k]) for k in self._d
        )

    def __hash__(self) -> int:
        return hash(tuple(sorted((k, hash_key(v)) for k, v in self._d.items())))

    def __repr__(self) -> str:
        return "{" + ", ".join(f"{k}: {render(v)}" for k, v in self._d.items()) + "}"


# --------------------------------------------------------------------------- decimal
_DECIMAL_RE = re.compile(r"^-?\d+\.\d{1,4}$")
_DECIMAL_MAX = _decimal.Decimal("922337203685477.5807")


@dataclass(frozen=True)
class Decimal:
    """Cedar ``decimal("...")``: fixed point, 1 to 4 fractional digits, i64/10^4 range."""

    value: _decimal.Decimal

    @classmethod
    def parse(cls, text: str) -> "Decimal":
        if not _DECIMAL_RE.match(text):
            raise EvalError(f'`decimal("{text}")` is not a valid decimal literal')
        d = _decimal.Decimal(text)
        if d > _DECIMAL_MAX or d < -_DECIMAL_MAX - _decimal.Decimal("0.0001"):
            raise EvalError(f'`decimal("{text}")` is out of range')
        return cls(d)

    def __str__(self) -> str:
        return f'decimal("{self.value}")'


# --------------------------------------------------------------------------- duration
_DURATION_RE = re.compile(r"^(-)?((\d+)d)?((\d+)h)?((\d+)m)?((\d+)s)?((\d+)ms)?$")


@dataclass(frozen=True)
class Duration:
    """Cedar ``duration("1h30m")`` in milliseconds."""

    ms: int

    @classmethod
    def parse(cls, text: str) -> "Duration":
        m = _DURATION_RE.match(text)
        if not m or text in ("", "-"):
            raise EvalError(f'`duration("{text}")` is not a valid duration literal')
        total = 0
        for group, factor in ((3, 86_400_000), (5, 3_600_000), (7, 60_000), (9, 1_000), (11, 1)):
            if m.group(group) is not None:
                total += int(m.group(group)) * factor
        if m.group(1):
            total = -total
        return cls(check_long(total, "duration"))

    def __str__(self) -> str:
        return f'duration("{self.ms}ms")'


# --------------------------------------------------------------------------- datetime
_DATETIME_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})" r"(?:T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?(Z|[+-]\d{4}))?$"
)


@dataclass(frozen=True)
class DateTime:
    """Cedar ``datetime("2024-01-01T00:00:00Z")`` as milliseconds since the Unix epoch."""

    ms: int

    @classmethod
    def parse(cls, text: str) -> "DateTime":
        m = _DATETIME_RE.match(text)
        if not m:
            raise EvalError(f'`datetime("{text}")` is not a valid datetime literal')
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
        hh, mi, ss = int(m.group(4) or 0), int(m.group(5) or 0), int(m.group(6) or 0)
        frac = int(m.group(7) or 0)
        try:
            base = _dt.datetime(y, mo, d, hh, mi, ss, tzinfo=_dt.timezone.utc)
        except ValueError as exc:
            raise EvalError(
                f'`datetime("{text}")` is not a valid datetime literal: {exc}'
            ) from None
        ms = int(base.timestamp()) * 1000 + frac
        tz = m.group(8)
        if tz and tz != "Z":
            sign = -1 if tz[0] == "+" else 1
            offset = int(tz[1:3]) * 60 + int(tz[3:5])
            if int(tz[1:3]) > 23 or int(tz[3:5]) > 59:
                raise EvalError(f'`datetime("{text}")` has an invalid UTC offset')
            ms += sign * offset * 60_000
        return cls(check_long(ms, "datetime"))

    def to_date(self) -> "DateTime":
        return DateTime(self.ms - (self.ms % 86_400_000))

    def to_time(self) -> Duration:
        return Duration(self.ms % 86_400_000)

    def __str__(self) -> str:
        dt = _dt.datetime.fromtimestamp(self.ms // 1000, tz=_dt.timezone.utc)
        return f'datetime("{dt.strftime("%Y-%m-%dT%H:%M:%S")}.{self.ms % 1000:03d}Z")'


# --------------------------------------------------------------------------- ipaddr
@dataclass(frozen=True)
class IpAddr:
    """Cedar ``ip("10.0.0.1")`` or ``ip("10.0.0.0/24")``."""

    net: Any  # ipaddress.IPv4Network | ipaddress.IPv6Network

    @classmethod
    def parse(cls, text: str) -> "IpAddr":
        try:
            if "/" in text:
                return cls(ipaddress.ip_network(text, strict=False))
            return cls(ipaddress.ip_network(text))
        except ValueError:
            raise EvalError(f'`ip("{text}")` is not a valid IP address or CIDR') from None

    @property
    def is_ipv4(self) -> bool:
        return bool(self.net.version == 4)

    @property
    def is_ipv6(self) -> bool:
        return bool(self.net.version == 6)

    @property
    def is_loopback(self) -> bool:
        return bool(self.net.network_address.is_loopback)

    @property
    def is_multicast(self) -> bool:
        return bool(self.net.network_address.is_multicast)

    def in_range(self, other: "IpAddr") -> bool:
        if self.net.version != other.net.version:
            return False
        return bool(self.net.subnet_of(other.net))

    def __str__(self) -> str:
        return f'ip("{self.net}")'


# --------------------------------------------------------------------------- helpers
def type_name(v: Any) -> str:
    """The Cedar type name of a runtime value (for error messages and checks)."""
    if isinstance(v, bool):
        return "Bool"
    if isinstance(v, int):
        return "Long"
    if isinstance(v, str):
        return "String"
    if isinstance(v, SetValue):
        return "Set"
    if isinstance(v, Record):
        return "Record"
    if isinstance(v, EntityRef):
        return "Entity"
    if isinstance(v, Decimal):
        return "decimal"
    if isinstance(v, DateTime):
        return "datetime"
    if isinstance(v, Duration):
        return "duration"
    if isinstance(v, IpAddr):
        return "ipaddr"
    return type(v).__name__


def values_equal(a: Any, b: Any) -> bool:
    """Cedar ``==``: same type and same value; ``true == 1`` is false."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, int) and isinstance(b, int):
        return bool(a == b)
    if type(a) is not type(b):
        return False
    return bool(a == b)


def hash_key(v: Any) -> Any:
    """A hashable stand-in for ``v`` consistent with :func:`values_equal`."""
    if isinstance(v, (bool, int, str, EntityRef, Decimal, DateTime, Duration, IpAddr)):
        return (type_name(v), v)
    if isinstance(v, (SetValue, Record)):
        return (type_name(v), hash(v))
    return (type(v).__name__, repr(v))


def render(v: Any) -> str:
    """Render a value in Cedar surface syntax (used by the trace writer and messages)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return f'"{escape_string(v)}"'
    if isinstance(v, (SetValue, Record)):
        return repr(v)
    return str(v)
