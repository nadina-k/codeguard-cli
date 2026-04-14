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


def test_dashboard_rerun_last_scan_handles_empty_history(monkeypatch, capsys, tmp_path) -> None:
    inputs = iter(["8", "", "0"])

    monkeypatch.setenv("CODEGUARD_HISTORY_FILE", str(tmp_path / "history.json"))
    monkeypatch.setattr(builtins, "input", lambda _: next(inputs))
    exit_code = run([])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "No previous scan available to rerun." in captured.out
