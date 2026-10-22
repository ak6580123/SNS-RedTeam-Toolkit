import pytest

from scripter.config import ConfigError, load_config, write_scope_targets


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "nope.toml")


def test_empty_scope_fails(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("[scope]\ntargets = []\n")
    with pytest.raises(ConfigError):
        load_config(cfg_path)


def test_valid_minimal_config(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[scope]\ntargets = ["10.10.1.5"]\n')
    cfg = load_config(cfg_path)
    assert cfg.scope.hosts == ("10.10.1.5",)
    assert cfg.scan.timeout_seconds == 2.0
    assert cfg.validate.enabled is False


def test_invalid_port_rejected(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[scope]\ntargets = ["10.10.1.5"]\n\n[scan]\nports = [99999]\n')
    with pytest.raises(ConfigError):
        load_config(cfg_path)


def test_malformed_toml(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("not valid toml [[[")
    with pytest.raises(ConfigError):
        load_config(cfg_path)


def test_bad_logging_level_rejected(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[scope]\ntargets = ["10.10.1.5"]\n\n[logging]\nlevel = "VERBOSE"\n')
    with pytest.raises(ConfigError):
        load_config(cfg_path)


def test_empty_scope_allowed_when_flagged(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("[scope]\ntargets = []\n")
    cfg = load_config(cfg_path, allow_empty_scope=True)
    assert cfg.scope.hosts == ()
    assert cfg.scope.raw_entries == ()


def test_allow_empty_scope_still_validates_nonempty_targets(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text('[scope]\ntargets = ["not-an-ip!!"]\n')
    with pytest.raises(ConfigError):
        load_config(cfg_path, allow_empty_scope=True)


def test_write_scope_targets_updates_targets_line_only(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        "[scope]\n"
        "# keep this comment\n"
        "targets = []\n"
        "allow_public = false\n\n"
        "[scan]\n"
        "timeout_seconds = 2.0\n"
    )
    write_scope_targets(cfg_path, ["10.10.1.5", "10.10.2.0/24"])
    cfg = load_config(cfg_path)
    assert cfg.scope.raw_entries == ("10.10.1.5", "10.10.2.0/24")
    text = cfg_path.read_text()
    assert "# keep this comment" in text
    assert "allow_public = false" in text
    assert "timeout_seconds = 2.0" in text


def test_write_scope_targets_missing_line_raises(tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("[storage]\ndata_dir = \"data\"\n")
    with pytest.raises(ConfigError):
        write_scope_targets(cfg_path, ["10.10.1.5"])
