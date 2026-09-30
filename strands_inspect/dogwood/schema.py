"""Minimal Cedar ``.cedarschema`` reader.

Dogwood adds no schema syntax of its own, so this is a subset of Cedar's human
schema format: ``namespace``, ``type`` aliases, ``entity`` (attributes, ``tags``,
``in [..]``, ``enum [..]``), and ``action "X" [in [..]] appliesTo { principal,
resource, context }``. It records enough to answer the questions the authorizer
asks: which actions exist and how they group, which entity types exist, what
enum ids an entity type admits, and the declared ``context`` record of an action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .errors import SchemaError
from .lexer import EOF_KIND, IDENT, OP, STRING, Token, tokenize, unescape
from .values import EntityRef

# Type descriptors: ("prim", name) | ("set", elem) | ("record", {attr: (type, required)})
#                   | ("entity", full name) | ("ext", name) | ("named", path)  (unresolved alias)
TypeDesc = Tuple[Any, ...]

_PRIMS = {"String", "Long", "Bool", "Boolean"}
_EXTS = {"decimal", "datetime", "duration", "ipaddr"}


@dataclass
class EntityDecl:
    name: str  # fully qualified
    attrs: Dict[str, Tuple[TypeDesc, bool]] = field(default_factory=dict)
    parents: List[str] = field(default_factory=list)  # member-of types
    tags: Optional[TypeDesc] = None
    enum: Optional[List[str]] = None


@dataclass
class ActionDecl:
    ref: EntityRef  # Ns::Action::"id"
    parents: List[EntityRef] = field(default_factory=list)
    principal_types: List[str] = field(default_factory=list)
    resource_types: List[str] = field(default_factory=list)
    context: Optional[TypeDesc] = None


@dataclass
class Schema:
    entities: Dict[str, EntityDecl] = field(default_factory=dict)
    actions: Dict[EntityRef, ActionDecl] = field(default_factory=dict)
    types: Dict[str, TypeDesc] = field(default_factory=dict)
    source: str = ""

    # ------------------------------------------------------------ queries
    def action_ancestors(self, ref: EntityRef) -> Set[EntityRef]:
        """Transitive action-group parents of ``ref`` (empty when unknown)."""
        seen: Set[EntityRef] = set()
        todo = [ref]
        while todo:
            cur = todo.pop()
            decl = self.actions.get(cur)
            if decl is None:
                continue
            for p in decl.parents:
                if p not in seen:
                    seen.add(p)
                    todo.append(p)
        return seen

    def action_in(self, action: EntityRef, group: EntityRef) -> bool:
        return action == group or group in self.action_ancestors(action)

    def members_of(self, group: EntityRef) -> List[EntityRef]:
        """Every declared action that is (transitively) in ``group``."""
        return [a for a in self.actions if self.action_in(a, group)]

    def has_entity_type(self, name: str) -> bool:
        return name in self.entities

    def enum_ids(self, entity_type: str) -> Optional[List[str]]:
        d = self.entities.get(entity_type)
        return d.enum if d else None

    def context_type(self, action: EntityRef) -> Optional[TypeDesc]:
        d = self.actions.get(action)
        return self.resolve(d.context) if d and d.context else None

    def resolve(self, t: TypeDesc, depth: int = 0) -> TypeDesc:
        """Follow ``("named", path)`` aliases to a concrete descriptor."""
        if depth > 32:
            raise SchemaError("type alias cycle in schema", source=self.source)
        if t[0] == "named":
            name = t[1]
            if name in self.types:
                return self.resolve(self.types[name], depth + 1)
            if name in self.entities:
                return ("entity", name)
            raise SchemaError(f"unknown type `{name}` in schema", source=self.source)
        if t[0] == "set":
            return ("set", self.resolve(t[1], depth + 1))
        if t[0] == "record":
            return ("record", {k: (self.resolve(v[0], depth + 1), v[1]) for k, v in t[1].items()})
        return t

    def record_path(self, action: EntityRef, path: List[str]) -> Optional[TypeDesc]:
        """The declared type at ``context.<path>`` for ``action``; None when undeclared."""
        cur = self.context_type(action)
        for seg in path:
            if cur is None or cur[0] != "record" or seg not in cur[1]:
                return None
            cur = self.resolve(cur[1][seg][0])
        return cur


class _SchemaParser:
    def __init__(self, text: str, source: str):
        self.toks: List[Token] = tokenize(text.lstrip("\ufeff"), source)
        self.i = 0
        self.source = source
        self.ns: List[str] = []
        self.schema = Schema(source=source)

    @property
    def tok(self) -> Token:
        return self.toks[self.i]

    def peek(self, k: int = 1) -> Token:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def err(self, msg: str, t: Optional[Token] = None) -> SchemaError:
        t = t or self.tok
        return SchemaError(msg, t.line, t.col, self.source)

    def advance(self) -> Token:
        t = self.tok
        if t.kind != EOF_KIND:
            self.i += 1
        return t

    def at(self, kind: str, value: Optional[str] = None) -> bool:
        return self.tok.kind == kind and (value is None or self.tok.value == value)

    def expect(self, kind: str, value: Optional[str] = None, what: str = "") -> Token:
        if not self.at(kind, value):
            found = self.tok.value if self.tok.kind != EOF_KIND else "end of input"
            raise self.err(f"expected {what or value or kind}, found `{found}`")
        return self.advance()

    def string(self) -> str:
        t = self.expect(STRING, what="a string")
        return unescape(t.value, t.line, t.col)

    def qualify(self, parts: List[str]) -> str:
        if len(parts) == 1 and parts[0] in _PRIMS | _EXTS:
            return parts[0]
        if len(parts) > 1 and parts[0] == "__cedar":
            return parts[-1]
        if len(parts) == 1 and self.ns:
            return "::".join(self.ns + parts)
        return "::".join(parts)

    def path(self) -> List[str]:
        parts = [self.expect(IDENT, what="a name").value]
        while self.at(OP, "::") and self.peek().kind == IDENT:
            self.advance()
            parts.append(self.advance().value)
        return parts

    # ------------------------------------------------------------ grammar
    def parse(self) -> Schema:
        while not self.at(EOF_KIND):
            self.decl()
        return self.schema

    def decl(self) -> None:
        if self.at(IDENT, "namespace"):
            self.advance()
            self.ns = self.path()
            self.expect(OP, "{")
            while not self.at(OP, "}"):
                if self.at(EOF_KIND):
                    raise self.err("unterminated namespace block")
                self.decl()
            self.advance()
            self.ns = []
            return
        if self.at(IDENT, "type"):
            self.advance()
            name = self.qualify([self.expect(IDENT, what="a type name").value])
            self.expect(OP, "=")
            self.schema.types[name] = self.type_expr()
            self.expect(OP, ";")
            return
        if self.at(IDENT, "entity"):
            self.entity_decl()
            return
        if self.at(IDENT, "action"):
            self.action_decl()
            return
        if self.at(OP, "@"):  # annotations on declarations: skip
            self.advance()
            self.expect(IDENT)
            if self.at(OP, "("):
                self.advance()
                self.string()
                self.expect(OP, ")")
            return
        raise self.err(
            f"expected `namespace`, `type`, `entity` or `action`, found `{self.tok.value}`"
        )

    def entity_decl(self) -> None:
        self.advance()
        names = [self.qualify([self.expect(IDENT, what="an entity name").value])]
        while self.at(OP, ","):
            self.advance()
            names.append(self.qualify([self.expect(IDENT, what="an entity name").value]))
        decls = [EntityDecl(n) for n in names]
        if self.at(IDENT, "enum"):
            self.advance()
            self.expect(OP, "[")
            ids: List[str] = []
            while not self.at(OP, "]"):
                ids.append(self.string())
                if self.at(OP, ","):
                    self.advance()
            self.advance()
            for d in decls:
                d.enum = ids
        else:
            if self.at(IDENT, "in"):
                self.advance()
                parents = self.type_list()
                for d in decls:
                    d.parents = parents
            if self.at(OP, "=") or self.at(OP, "{"):
                if self.at(OP, "="):
                    self.advance()
                rec = self.type_expr()
                if rec[0] != "record":
                    raise self.err("entity attributes must be a record type `{ ... }`")
                for d in decls:
                    d.attrs = dict(rec[1])
            if self.at(IDENT, "tags"):
                self.advance()
                t = self.type_expr()
                for d in decls:
                    d.tags = t
        self.expect(OP, ";", what="`;` after the entity declaration")
        for d in decls:
            self.schema.entities[d.name] = d

    def type_list(self) -> List[str]:
        """``[A, B::C]`` or a single name -> fully qualified entity type names."""
        names: List[str] = []
        if self.at(OP, "["):
            self.advance()
            while not self.at(OP, "]"):
                names.append(self.qualify(self.path()))
                if self.at(OP, ","):
                    self.advance()
            self.advance()
        else:
            names.append(self.qualify(self.path()))
        return names

    def action_ref(self) -> EntityRef:
        """``Action::"x"`` or ``Ns::Action::"x"`` or a bare ``"x"`` (current namespace)."""
        if self.at(STRING):
            return EntityRef(self.qualify(["Action"]), self.string())
        parts = self.path()
        if not self.at(OP, "::"):  # bare `in Login`
            if len(parts) == 1:
                return EntityRef(self.qualify(["Action"]), parts[0])
            raise self.err("expected an action reference")
        self.advance()
        eid = self.string() if self.at(STRING) else self.expect(IDENT, what="an action id").value
        if len(parts) == 1 and parts[0] == "Action":
            return EntityRef(self.qualify(["Action"]), eid)
        return EntityRef("::".join(parts), eid)

    def action_name(self) -> EntityRef:
        if self.at(STRING):
            return EntityRef(self.qualify(["Action"]), self.string())
        return EntityRef(self.qualify(["Action"]), self.expect(IDENT, what="an action name").value)

    def action_decl(self) -> None:
        self.advance()
        refs = [self.action_name()]
        while self.at(OP, ","):
            self.advance()
            refs.append(self.action_name())
        decls = [ActionDecl(r) for r in refs]
        if self.at(IDENT, "in"):
            self.advance()
            parents: List[EntityRef] = []
            if self.at(OP, "["):
                self.advance()
                while not self.at(OP, "]"):
                    parents.append(self.action_ref())
                    if self.at(OP, ","):
                        self.advance()
                self.advance()
            else:
                parents.append(self.action_ref())
            for d in decls:
                d.parents = parents
        if self.at(IDENT, "appliesTo"):
            self.advance()
            self.expect(OP, "{")
            while not self.at(OP, "}"):
                key = self.expect(IDENT, what="`principal`, `resource` or `context`").value
                self.expect(OP, ":")
                if key == "principal":
                    v = self.type_list()
                    for d in decls:
                        d.principal_types = v
                elif key == "resource":
                    v = self.type_list()
                    for d in decls:
                        d.resource_types = v
                elif key == "context":
                    t = self.type_expr()
                    for d in decls:
                        d.context = t
                else:
                    raise self.err(f"unknown appliesTo key `{key}`")
                if self.at(OP, ","):
                    self.advance()
            self.advance()
        self.expect(OP, ";", what="`;` after the action declaration")
        for d in decls:
            self.schema.actions[d.ref] = d
            # make sure every referenced group exists as an action entity
            for p in d.parents:
                self.schema.actions.setdefault(p, ActionDecl(p))

    def type_expr(self) -> TypeDesc:
        if self.at(OP, "{"):
            self.advance()
            attrs: Dict[str, Tuple[TypeDesc, bool]] = {}
            while not self.at(OP, "}"):
                if self.at(STRING):
                    name = self.string()
                else:
                    name = self.expect(IDENT, what="an attribute name").value
                required = True
                if self.at(OP, "?"):
                    self.advance()
                    required = False
                self.expect(OP, ":")
                attrs[name] = (self.type_expr(), required)
                if self.at(OP, ","):
                    self.advance()
                elif not self.at(OP, "}"):
                    raise self.err("expected `,` or `}` in the record type")
            self.advance()
            return ("record", attrs)
        if self.at(IDENT, "Set") and self.peek().is_op("<"):
            self.advance()
            self.advance()
            elem = self.type_expr()
            self.expect(OP, ">")
            return ("set", elem)
        parts = self.path()
        name = self.qualify(parts)
        if name in _PRIMS:
            return ("prim", "Bool" if name == "Boolean" else name)
        if name in _EXTS:
            return ("ext", name)
        return ("named", name)


def parse_schema(text: str, source: str = "") -> Schema:
    """Parse a ``.cedarschema`` text."""
    return _SchemaParser(text, source).parse()
