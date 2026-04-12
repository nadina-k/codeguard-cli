import builtins

from codeguard_cli.cli.commands import run


def test_dashboard_opens_and_exits(monkeypatch, capsys) -> None:
    inputs = iter(["0"])

    monkeypatch.setattr(builtins, "input", lambda _: next(inputs))
    exit_code = run([])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Security Dashboard" in captured.out
    assert "Exiting CodeGuard dashboard." in captured.out
