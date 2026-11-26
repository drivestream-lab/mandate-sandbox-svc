"""verify-runner-live: a deliberately failing test."""


def test_verify_runner_broken() -> None:
    assert 1 + 1 == 3
