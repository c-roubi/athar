"""Thin bridge to the sample-capture generator so tests can reuse it."""
import make_sample_pcap as _gen


def client_hello(sni: str) -> bytes:
    return _gen.tls_client_hello(sni)


def client_hello_profile(sni: str, **kwargs) -> bytes:
    return _gen.tls_client_hello(sni, **kwargs)


def sample_bytes() -> bytes:
    return _gen.build()
