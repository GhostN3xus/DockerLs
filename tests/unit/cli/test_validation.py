import pytest

from dockerls.utils.validation import sanitize_image_name, validate_threshold


class TestSanitizeImageName:
    def test_valid_names(self):
        assert sanitize_image_name("node") == "node"
        assert sanitize_image_name("node:22-alpine") == "node:22-alpine"
        assert sanitize_image_name("library/python") == "library/python"
        assert sanitize_image_name("myorg/myimage:v1.2.3") == "myorg/myimage:v1.2.3"

    def test_empty(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            sanitize_image_name("")

    def test_too_long(self):
        with pytest.raises(ValueError, match="exceeds"):
            sanitize_image_name("a" * 257)

    def test_path_traversal(self):
        with pytest.raises(ValueError):
            sanitize_image_name("../../etc/passwd")

    def test_invalid_chars(self):
        with pytest.raises(ValueError, match="Invalid"):
            sanitize_image_name("node; rm -rf /")

    def test_strips_whitespace(self):
        assert sanitize_image_name("  node  ") == "node"


class TestValidateThreshold:
    def test_valid(self):
        assert validate_threshold(0, "max_critical") == 0
        assert validate_threshold(5, "max_high") == 5

    def test_negative(self):
        with pytest.raises(ValueError, match="non-negative"):
            validate_threshold(-1, "max_critical")

    def test_too_large(self):
        with pytest.raises(ValueError, match="exceeds"):
            validate_threshold(100000, "max_high")
