# Contributing to athar

Thanks for your interest. athar aims to be a *forensically sound* tool, so
contributions are held to a matching bar: correct, typed, tested, and honest
about limitations.

## Ground rules

- **No third-party runtime dependencies** in the Python package. The parser,
  detectors, store, and report all run on the standard library. Build- and
  dev-only tools (pybind11, ruff, mypy, pytest) are fine; the React dashboard has
  its own `package.json`.
- **Determinism.** Analysis must be reproducible: same input, same output. The
  native C++ core and the pure-Python path must stay byte-for-byte identical
  (there is a parity test — keep it green).
- **Evidence integrity is not optional.** Anything that ingests or emits case
  data must preserve hashing/provenance and must not weaken the chain of custody.

## Development setup

```bash
# Python side
python -m pip install -e ".[dev]"      # or install ruff, mypy, pytest, pybind11
python setup.py build_ext --inplace    # optional native core
ruff check .
PYTHONPATH=src mypy
PYTHONPATH=src python -m pytest tests/ -q

# Dashboard
cd dashboard && npm install && npm run build && npx tsc --noEmit
```

## Before opening a PR

1. `ruff check .` is clean.
2. `mypy` (strict) is clean.
3. `pytest` passes, and new behaviour has tests.
4. If you touched a detector, run `python validation/run.py` and include the
   updated `docs/validation-report.md`. New detectors should add labelled
   scenarios (a clear positive, a benign control, and ideally a boundary case).
5. If you touched decoding, confirm native/Python parity still holds.
6. Update `CHANGELOG.md`.

## Adding a detector

Detectors live in `src/athar/detectors.py`, take a `Signals` object, and return
`Event`s. Map every finding to a MITRE ATT&CK technique, keep thresholds explicit
and documented, and add validation scenarios so the detector has a measured error
rate.

## Adding a protocol dissector

Dissectors live in `src/athar/dissectors.py` and run on reassembled TCP streams
(or per-packet for UDP). Cleartext-credential protocols should push onto the
shared `Signals.credentials` list so the existing detector picks them up.

## Reporting security or evidentiary issues

See `SECURITY.md`.
