"""Adversarial coverage for credential redaction.

Audit finding: the previous key/value pattern required the key name to be
followed *immediately* by `=` or `:`. Every JSON-shaped line has a quote in
between (`"token": "..."`), so 10 of 17 realistic formats leaked the
credential in full into the log file -- including the ones an HTTP client
is most likely to produce.

A credential must survive none of these. Each case asserts the secret is
absent rather than that some particular masked form is present, so a future
rewrite of the patterns cannot pass by accident.
"""

from __future__ import annotations

import pytest

from dockerls.infrastructure.logging.setup import MASK, _mask_secrets

SECRET = "dckr_pat_AbCdEf123456789xyz"

LEAKY_FORMATS = {
    "json_nested": '{"auth": {"token": "%s"}}',
    "json_compact": '{"token":"%s"}',
    "json_password": '{"password": "%s"}',
    "json_single_quotes": "{'token': '%s'}",
    "json_multiline": '{\n  "token": "%s"\n}',
    "json_camel_case_key": '{"apiKey": "%s"}',
    "json_snake_case_key": '{"api_key": "%s"}',
    "querystring": "https://hub.docker.com/v2/x?access_token=%s&page=1",
    "multipart": 'Content-Disposition: form-data; name="token"\r\n\r\n%s\r\n',
    "header_dict_repr": "{'Authorization': 'Bearer %s'}",
    "url_userinfo": "https://user:%s@hub.docker.com/v2/",
    "env_dump": "DOCKERHUB_TOKEN=%s",
    "env_dump_lowercase": "dockerhub_token=%s",
    "http_header": "x-api-key: %s",
    "credential_word": "credential=%s",
    "portuguese_key": "senha=%s",
    "curl_short_flag": "curl -u user:%s https://hub.docker.com",
    "curl_long_flag": "curl --user user:%s https://hub.docker.com",
    "bearer_lowercase": "authorization: bearer %s",
    "basic_scheme": "Authorization: Basic %s",
    "toml_config": 'dockerhub_token = "%s"',
    "spaced_equals": "token = %s",
    "yaml_style": "token: %s",
    "nested_in_list": '["%s", {"secret": "%s"}]',
    "repr_of_settings": "Settings(dockerhub_token='%s', log_level='INFO')",
}


class TestNoFormatLeaksTheSecret:
    @pytest.mark.parametrize("name,template", sorted(LEAKY_FORMATS.items()))
    def test_secret_is_never_present_in_the_output(self, name, template):
        message = template % ((SECRET,) * template.count("%s"))
        assert SECRET not in _mask_secrets(message), f"{name} leaked the credential"

    @pytest.mark.parametrize("name,template", sorted(LEAKY_FORMATS.items()))
    def test_no_partial_prefix_of_the_secret_survives(self, name, template):
        """A truncated credential is still a credential."""
        message = template % ((SECRET,) * template.count("%s"))
        masked = _mask_secrets(message)
        for cut in (24, 16, 12):
            assert SECRET[:cut] not in masked, f"{name} leaked a {cut}-char prefix"

    def test_every_format_is_actually_masked_not_just_absent(self):
        """Guards against a masker that passes by deleting the line."""
        for template in LEAKY_FORMATS.values():
            message = template % ((SECRET,) * template.count("%s"))
            assert MASK in _mask_secrets(message)


class TestBenignLinesAreUntouched:
    """Over-masking is acceptable, but not to the point of destroying the
    log's usefulness -- these are the lines the tool writes constantly."""

    @pytest.mark.parametrize(
        "line",
        [
            "Processing node:22-alpine image",
            "Scanning cgr.dev/chainguard/node:latest with Trivy",
            "Trivy DB ready at /home/u/.cache/trivy; cache isolation enabled",
            "12/24 analyzed, 12 skipped",
            "Skipping node:26.7-slim: ERROR (trivy exited with code 1)",
            "Chainguard: 5 usable tags for cgr.dev/chainguard/node",
            "Scanner divergence for node:22: HIGH trivy=0 vs grype=9",
        ],
    )
    def test_line_survives_unchanged(self, line):
        assert _mask_secrets(line) == line


class TestMaskingIsAppliedThroughTheLogFilter:
    """The patterns are only worth anything if the sink actually runs them."""

    def test_filter_rewrites_the_record(self):
        from dockerls.infrastructure.logging.setup import _log_filter

        record = {"message": f"Authorization: Bearer {SECRET}"}
        assert _log_filter(record) is True
        assert SECRET not in record["message"]

    def test_secret_never_reaches_the_log_file(self, tmp_path):
        from loguru import logger

        from dockerls.infrastructure.logging.setup import setup_logging

        path = setup_logging("INFO", log_dir=tmp_path / "logs")
        for template in LEAKY_FORMATS.values():
            logger.info(template % ((SECRET,) * template.count("%s")))
        logger.complete()
        logger.remove()

        contents = path.read_text()
        assert SECRET not in contents
        assert MASK in contents


class TestGitHubTokens:
    """`DOCKERLS_GITHUB_TOKEN` raises the catalogue's API rate limit.

    Nothing logs it, but a token that reaches a log through an exception
    message or a request repr has no key in front of it to identify it --
    which is what the self-identifying value patterns are for. The
    fine-grained format (`github_pat_...`) does not match the classic one,
    so it needs its own arm.
    """

    @pytest.mark.parametrize(
        "token",
        [
            "ghp_AbCdEf0123456789AbCdEf0123456789xy",
            "github_pat_11ABCDEFG0abcdefghijkl_MNOPQRSTUVWXYZ0123456789",
        ],
    )
    def test_a_bare_github_token_is_masked(self, token):
        assert token not in _mask_secrets(f"request failed with credential {token}")

    def test_a_github_token_in_a_bearer_header_is_masked(self):
        token = "github_pat_11ABCDEFG0abcdefghijkl_MNOPQRSTUVWXYZ0123456789"
        assert token not in _mask_secrets(f"Authorization: Bearer {token}")
