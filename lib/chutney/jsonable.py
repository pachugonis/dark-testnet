from __future__ import annotations

import json

from abc import ABC, abstractmethod
from collections.abc import Collection, Mapping
from enum import Enum
from pathlib import Path
from typing import Union, TypeAlias
from typing_extensions import Self, override, assert_never

from chutney.errors import ChutneyUnimplementedError

# Types that `CustomEncoder` can handle
CustomJsonable: TypeAlias = Union[
    # Primitive types that the json module can encode directly.
    None,
    bool,
    str,
    int,
    float,
    # The json module supports `dict`; we expand this to `Mapping`
    # primarily to make it covariant.
    Mapping[str, "CustomJsonable"],
    # The json module supports `list` and `tuple`; we expand to `Collection`
    # primarily to make it covariant.
    Collection["CustomJsonable"],
    # Knows how to convert itself; see below.
    "ToCustomJsonable",
    # We convert to str.
    Path,
    # We use the enumerator name.
    Enum,
]


class ToCustomJsonable(ABC):
    """Can be converted to an object encodable by CustomEncoder"""

    @abstractmethod
    def to_custom_jsonable(self) -> CustomJsonable:
        """Convert to a json-encodable object."""
        ...


# We can't inherit from ABC without making incompatible with enum classes, since
# both Enum and ABC try to use a custom metaclass. We similarly also can't inherit
# from ToCustomJsonable since it inherits from ABC.
class FromDecodedJson:
    """Object that can be reconstituted from a json-loaded object."""

    @classmethod
    def from_decoded_json(cls, obj: object) -> Self:
        # Re the type of `obj`: while the documentation of the json module
        # describes the types that its decoder may return at
        # <https://docs.python.org/3/library/json.html#json-to-py-table>, the
        # typeshed annotations for the return type of e.g. `json.loads` is `Any`
        # <https://github.com/python/typeshed/blob/8d96801533918957fb194e101cb321bfe1f836f8/stdlib/json/__init__.pyi#L49>.
        # It seems unwise to make stronger assumptions than what they annotate there.
        # Trying to be more specific would be of limited value anyway, since
        # implementations would usually still need to dynamically check the type
        # of `obj` to handle the case where it's not the more-specific expected
        # type (e.g. a `str` when a `float` was expected).
        """Reconstitute an instance from a json-loaded object.

        Example:
        ```
        x = T(...)
        json_str = json.dumps(x.to_custom_jsonable(), cls=CustomEncoder)
        y = T.from_decoded_json(json.loads(json_str))
        ```

        `y` should be "morally equivalent" to `x`, if not equal.
        """
        # we can't use `...` here without inheriting from ABC;
        # see class-comment.
        raise ChutneyUnimplementedError()


class CustomEncoder(json.JSONEncoder):
    """A `JSONEncoder` that handles `CustomJsonable` objects.

    For use with the `json` module. e.g.:
    `json.dumps(x, cls=CustomEncoder)`
    """

    @override
    def default(self, obj: CustomJsonable) -> object:
        assert obj is not None and not isinstance(
            obj, (int, bool, float, str, list, tuple, dict)
        ), "Base encoder should have handled"
        if isinstance(obj, ToCustomJsonable):
            return obj.to_custom_jsonable()
        elif isinstance(obj, Mapping):
            return {k: v for k, v in obj.items()}
        elif isinstance(obj, Collection):
            return [x for x in obj]
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, Enum):
            return obj.name
        else:
            assert_never(obj)
