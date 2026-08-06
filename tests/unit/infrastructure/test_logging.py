from __future__ import annotations

from loguru import logger

from dockerls.infrastructure.logging.setup import _mask_secrets, setup_logging


class TestSecretMasking:
    def test_mask_token(self):
        result = _mask_secrets("token=my-secret-token-123")
        assert "my-secret-token-123" not in result
        assert "***MASKED***" in result

    def test_mask_bearer(self):
        result = _mask_secrets("Authorization: Bearer eyJhbGciOi...")
        assert "eyJhbGciOi..." not in result

    def test_no_false_positive(self):
        result = _mask_secrets("Processing node:22-alpine image")
        assert result == "Processing node:22-alpine image"

    def test_no_partial_leak_of_token_value(self):
        result = _mask_secrets("token=abcdefghijklmnopqrstuvwxyz")
        assert "abcdefghij" not in result

    def test_no_partial_leak_of_bearer_value(self):
        result = _mask_secrets("Bearer abcdefghijklmnopqrstuvwxyz")
        assert "abcdefghij" not in result


class TestFileOnlySinks:
    """The terminal belongs to Rich; loguru must not write to it by default.

    Without this, Trivy failures and retry chatter interleave with the
    progress display and corrupt the rendered output.
    """

    def test_log_file_is_created_in_log_dir(self, tmp_path):
        path = setup_logging("INFO", log_dir=tmp_path / "logs")
        assert path is not None
        assert path.parent == tmp_path / "logs"
        assert path.name.startswith("dockerls_")
        assert path.name.endswith(".log")

    def test_messages_land_in_the_file(self, tmp_path):
        path = setup_logging("INFO", log_dir=tmp_path / "logs")
        logger.error("trivy returned code 1 for node:22-alpine")
        logger.complete()
        logger.remove()
        assert "trivy returned code 1" in path.read_text()

    def test_no_stderr_sink_by_default(self, tmp_path, capsys):
        setup_logging("INFO", log_dir=tmp_path / "logs")
        logger.error("this must not reach the terminal")
        logger.complete()
        logger.remove()
        captured = capsys.readouterr()
        assert "this must not reach the terminal" not in captured.err
        assert "this must not reach the terminal" not in captured.out

    def test_console_opt_in_restores_stderr_sink(self, tmp_path, capsys):
        setup_logging("INFO", log_dir=tmp_path / "logs", console=True)
        logger.error("verbose mode message")
        logger.complete()
        logger.remove()
        assert "verbose mode message" in capsys.readouterr().err

    def test_secrets_are_masked_in_the_file(self, tmp_path):
        path = setup_logging("INFO", log_dir=tmp_path / "logs")
        logger.info("auth: Bearer supersecretvalue")
        logger.complete()
        logger.remove()
        contents = path.read_text()
        assert "supersecretvalue" not in contents
        assert "***MASKED***" in contents

    def test_falls_back_to_stderr_when_no_dir_is_writable(self, tmp_path, monkeypatch, capsys):
        blocker = tmp_path / "logs"
        blocker.write_text("not a directory")
        monkeypatch.setattr("pathlib.Path.home", lambda: blocker)

        path = setup_logging("INFO", log_dir=blocker)
        assert path is None
        logger.error("fallback message")
        logger.complete()
        logger.remove()
        assert "fallback message" in capsys.readouterr().err


class TestSchemeInsideKeyValue:
    """Regression: an auth scheme nested in a key-value pair must not leak.

    The key-value pattern's \\S+ matches only "Bearer", so if it ran first
    the credential after it survived into the log.
    """

    def test_auth_colon_bearer_masks_the_token(self):
        result = _mask_secrets("auth: Bearer supersecretvalue")
        assert "supersecretvalue" not in result

    def test_authorization_header_masks_the_token(self):
        result = _mask_secrets("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")
        assert "eyJhbGciOiJIUzI1NiJ9" not in result

    def test_auth_equals_basic_masks_the_credential(self):
        result = _mask_secrets("auth=Basic dXNlcjpwYXNz")
        assert "dXNlcjpwYXNz" not in result
