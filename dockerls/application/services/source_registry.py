"""Named image sources, resolved from a selection instead of a branch.

`recommend` and `search` both need to answer "which catalogues should this
run look at", and the answer comes from three places at once: the config
file, the legacy `--no-hardened` flag, and the new `--source`/`--all-sources`
options. Written as conditionals that ask `if source == "dhi"`, that logic
would have to be repeated in every command and extended in every command
each time a catalogue is added.

So the catalogues register themselves here, and a command asks for a
*selection*. Adding a provider is one `register()` call in the wiring layer;
no command changes, and no branch anywhere grows a new arm.

The registry deliberately knows nothing about HTTP, registries or scanners:
a `SourceSpec` carries a name, a label and a coroutine that builds the
repository. That keeps the application layer free of `httpx` while still
letting the CLI enumerate what exists (`--source` help text, `doctor`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterable, Sequence

    from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface

    SourceBuilder = Callable[[], Awaitable[ImageRepositoryInterface]]

#: `--source all` and `--all-sources` mean the same thing; accepting the
#: token as well keeps `--source` self-sufficient in scripts.
ALL_SOURCES = "all"


class UnknownSourceError(ValueError):
    """Raised for a `--source` value no provider is registered under.

    Carries the valid names so the CLI can say what *is* available instead
    of only what is not.
    """

    def __init__(self, unknown: Iterable[str], available: Iterable[str]):
        self.unknown = sorted(set(unknown))
        self.available = list(available)
        super().__init__(
            f"unknown source(s): {', '.join(self.unknown)}. "
            f"Available: {', '.join([*self.available, ALL_SOURCES])}"
        )


@dataclass(frozen=True)
class SourceSpec:
    """One catalogue DockerLs can discover candidates in."""

    #: CLI token, lowercase and stable: this is what `--source` accepts.
    name: str
    #: Human label carried on every `DockerImage` this source produces, and
    #: shown in the results table. Must match what the repository sets, or
    #: the table would credit a candidate to the wrong catalogue.
    label: str
    #: Builds the repository. Async because some sources authenticate.
    build: SourceBuilder
    #: The source that sets the bulk of the candidate list. Exactly one
    #: should be primary; it receives the full `--limit` while the others
    #: are capped, because a broad catalogue and a curated one need very
    #: different fan-outs.
    primary: bool = False
    #: Searched when no explicit `--source` is given.
    default_enabled: bool = True
    #: The registry behind this catalogue refuses anonymous pulls, so its
    #: candidates cannot be scanned without credentials. Not a reason to
    #: hide the source -- it is a reason the verdict will be UNVERIFIED,
    #: which is exactly what the user needs to be told.
    requires_auth: bool = False
    #: Short note surfaced next to the source name in `--help`/`doctor`.
    description: str = ""


@dataclass
class SourceRegistry:
    """The catalogues this process knows about, in registration order."""

    _specs: dict[str, SourceSpec] = field(default_factory=dict)

    def register(self, spec: SourceSpec) -> None:
        if spec.name in self._specs:
            raise ValueError(f"source already registered: {spec.name}")
        if spec.name == ALL_SOURCES:
            raise ValueError(f"{ALL_SOURCES!r} is reserved and cannot name a source")
        self._specs[spec.name] = spec

    @property
    def specs(self) -> list[SourceSpec]:
        return list(self._specs.values())

    @property
    def names(self) -> list[str]:
        return list(self._specs)

    def get(self, name: str) -> SourceSpec | None:
        return self._specs.get(name.strip().lower())

    def resolve(
        self,
        selection: Sequence[str] | None = None,
        *,
        all_sources: bool = False,
        include_optional: bool = True,
    ) -> list[SourceSpec]:
        """Which sources this run should search.

        * `all_sources` (or a selection containing `all`) -- every registered
          source, including the ones that are off by default.
        * an explicit selection -- exactly those, in registration order so
          the primary stays first regardless of the order they were typed.
          An explicit selection overrides `include_optional`: asking for a
          source by name is a stronger statement than a default.
        * neither -- the default-enabled sources, minus the non-primary ones
          when `include_optional` is False (that is `--no-hardened`).

        Order matters downstream: the first spec becomes the composite's
        primary and therefore gets the full tag limit.
        """
        requested = [s.strip().lower() for s in (selection or []) if s.strip()]
        if all_sources or ALL_SOURCES in requested:
            return self._ordered(self._specs)

        if requested:
            unknown = [name for name in requested if name not in self._specs]
            if unknown:
                raise UnknownSourceError(unknown, self.names)
            return self._ordered({name: self._specs[name] for name in requested})

        chosen = {
            name: spec
            for name, spec in self._specs.items()
            if spec.default_enabled and (include_optional or spec.primary)
        }
        return self._ordered(chosen)

    def _ordered(self, chosen: dict[str, SourceSpec]) -> list[SourceSpec]:
        """Registration order, primary first.

        `CompositeImageRepository` gives its primary the full limit and caps
        the rest, so which spec lands in position zero is a behavioural
        decision, not a cosmetic one.
        """
        selected = [spec for name, spec in self._specs.items() if name in chosen]
        return sorted(selected, key=lambda spec: not spec.primary)
