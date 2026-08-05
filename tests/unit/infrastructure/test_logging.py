from dockerls.infrastructure.logging.setup import _mask_secrets


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
