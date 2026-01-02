import dave

# This test setup is extremely simple, it primarily serves as a smoke test for CI for now.


def test_max_version() -> None:
    assert dave.get_max_supported_protocol_version() == 1
