"""Guard against drift between the compiled extension and its type stub.

The native ``_lkrequest`` module is the source of truth. Every public class,
module-level function, and public (non-dunder) method/attribute it exposes must
be declared in ``_lkrequest.pyi``. This fails fast when an API is added in Rust
but the stub is not updated (e.g. a new ``StreamingResponse.chunk_decoded`` or a
new ``HttpVersion`` variant), which type checkers and IDEs would otherwise miss.

The check is one-directional (module -> stub). Symbols that appear only in the
stub are tolerated, because feature-gated items (``QuicProfile`` with
``quic-h3``) are absent from a default build.
"""

import ast
import inspect
from pathlib import Path

import lkrequest._lkrequest as native

STUB_PATH = Path(native.__file__).with_name("_lkrequest.pyi")

# Most dunders are pyo3 machinery the stub does not (and need not) declare. Only
# the protocol dunders the stubs actually spell out are worth checking; the rest
# of the "_" names are treated as private. (__init__ is excluded on purpose:
# pyo3 synthesises one for every class, but the stub only declares it for types
# meant to be constructed directly, so its absence is not drift.)
_CHECKED_DUNDERS = {
    "__iter__",
    "__next__",
    "__aiter__",
    "__anext__",
    "__enter__",
    "__exit__",
    "__aenter__",
    "__aexit__",
    "__getitem__",
    "__contains__",
    "__len__",
}


def _parse_stub():
    tree = ast.parse(STUB_PATH.read_text(encoding="utf-8"))
    module_names: set[str] = set()
    class_members: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            module_names.add(node.name)
        elif isinstance(node, ast.ClassDef):
            module_names.add(node.name)
            members: set[str] = set()
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    members.add(item.name)
                elif isinstance(item, ast.ClassDef):
                    members.add(item.name)  # nested complex-enum variant types
                elif isinstance(item, ast.AnnAssign) and isinstance(
                    item.target, ast.Name
                ):
                    members.add(item.target.id)
                elif isinstance(item, ast.Assign):
                    for target in item.targets:
                        if isinstance(target, ast.Name):
                            members.add(target.id)
            class_members[node.name] = members
    return module_names, class_members


STUB_MODULE_NAMES, STUB_CLASS_MEMBERS = _parse_stub()


def _is_relevant(name: str) -> bool:
    if name.startswith("_") and name not in _CHECKED_DUNDERS:
        return False
    return True


def _owned_members(obj):
    """Members defined on the class itself, excluding anything inherited (from
    ``object`` for plain pyclasses, or ``Exception``/``BaseException`` for the
    exception types whose stubs are intentionally empty)."""
    inherited: set[str] = set()
    for base in obj.__mro__[1:]:
        inherited |= set(dir(base))
    return [m for m in dir(obj) if m not in inherited and _is_relevant(m)]


def _module_exports():
    for name in dir(native):
        if name.startswith("_"):
            continue
        obj = getattr(native, name)
        if inspect.isclass(obj) or callable(obj):
            yield name, obj


def test_module_symbols_declared_in_stub():
    """Every public class/function in the module must be declared in the stub."""
    missing = sorted(
        name for name, _ in _module_exports() if name not in STUB_MODULE_NAMES
    )
    assert not missing, (
        "Public symbols exist in the compiled module but are missing from "
        f"_lkrequest.pyi: {missing}"
    )


def test_class_members_declared_in_stub():
    """Every public member of each module class must be declared in the stub."""
    problems: dict[str, list[str]] = {}
    for name, obj in _module_exports():
        if not inspect.isclass(obj):
            continue
        declared = STUB_CLASS_MEMBERS.get(name)
        if declared is None:
            continue  # class-presence is covered by the other test
        missing = sorted(
            member for member in _owned_members(obj) if member not in declared
        )
        if missing:
            problems[name] = missing
    assert not problems, (
        "Public members exist in the compiled module but are missing from "
        f"_lkrequest.pyi: {problems}"
    )
