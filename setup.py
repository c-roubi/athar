"""Build the optional native core.

Project metadata lives in ``pyproject.toml``; this file exists only to compile
the C++ extension. The build is *optional*: if no toolchain is available the
extension is skipped with a warning and athar installs anyway, using its
pure-Python backend. That keeps ``pip install athar`` working everywhere while
rewarding machines that can build the fast path.
"""

from __future__ import annotations

import warnings

from setuptools import setup

try:
    from pybind11.setup_helpers import Pybind11Extension
    from pybind11.setup_helpers import build_ext as _build_ext

    ext_modules = [
        Pybind11Extension("athar._core", ["core/athar_core.cpp"], cxx_std=17),
    ]
except ImportError:  # pybind11 missing at build time -- ship pure Python only
    _build_ext = None
    ext_modules = []


class OptionalBuildExt(_build_ext if _build_ext else object):  # type: ignore[misc]
    """Compile the native core if we can; never fail the install if we can't."""

    def run(self) -> None:
        try:
            super().run()
        except Exception as exc:  # pragma: no cover - depends on host toolchain
            _skip(exc)

    def build_extension(self, ext) -> None:  # type: ignore[no-untyped-def]
        try:
            super().build_extension(ext)
        except Exception as exc:  # pragma: no cover
            _skip(exc)


def _skip(exc: Exception) -> None:
    warnings.warn(
        f"athar: native core not built ({exc}); using the pure-Python backend",
        stacklevel=2,
    )


setup(
    ext_modules=ext_modules,
    cmdclass={"build_ext": OptionalBuildExt} if ext_modules else {},
)
