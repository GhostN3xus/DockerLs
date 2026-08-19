"""Rótulos de responsabilidade, exigidos antes de publicar.

A regra DF007 deste projeto cobra `maintainer` e `security.scanner` de todo
Dockerfile que ele analisa, enquanto o `build` publicava imagens sem nenhum
dos dois. `--labels` aceitava qualquer JSON e não exigia nada.
"""

from __future__ import annotations

import pytest

from dockerls.domain.value_objects.build_labels import (
    BuildIdentity,
    MissingBuildMetadataError,
)


class TestRequiredMetadata:
    def test_an_empty_identity_names_everything_it_needs(self):
        assert BuildIdentity().missing() == ["owner", "security_contact", "source"]

    def test_whitespace_does_not_count_as_an_answer(self):
        identity = BuildIdentity(owner="   ", security_contact="x@y", source="http://r")
        assert identity.missing() == ["owner"]

    def test_require_complete_names_what_is_missing(self):
        with pytest.raises(MissingBuildMetadataError, match="security_contact"):
            BuildIdentity(owner="time", source="http://r").require_complete()

    def test_a_complete_identity_passes(self):
        BuildIdentity(
            owner="Plataforma", security_contact="sec@empresa", source="https://git/repo"
        ).require_complete()


class TestLabelRendering:
    def test_owner_becomes_maintainer_and_vendor(self):
        labels = BuildIdentity(owner="Plataforma").to_labels()
        assert labels["maintainer"] == "Plataforma"
        assert labels["org.opencontainers.image.vendor"] == "Plataforma"

    def test_the_scanner_label_is_always_present(self):
        # É exatamente o rótulo que a DF007 cobra e que o build não gravava.
        assert BuildIdentity().to_labels()["security.scanner"] == "dockerls"

    def test_empty_fields_are_omitted_not_written_blank(self):
        # Uma chave presente e vazia é pior que ausente: um inventário a lê
        # como respondida.
        labels = BuildIdentity(owner="time").to_labels()
        assert "org.opencontainers.image.source" not in labels
        assert all(value for value in labels.values())

    def test_oci_keys_are_used_verbatim(self):
        labels = BuildIdentity(
            owner="t",
            security_contact="s",
            source="https://git/r",
            title="App",
            description="d",
            version="1.5.0",
            revision="abc123",
        ).to_labels()
        assert labels["org.opencontainers.image.source"] == "https://git/r"
        assert labels["org.opencontainers.image.version"] == "1.5.0"
        assert labels["org.opencontainers.image.revision"] == "abc123"
        assert labels["security.contact"] == "s"

    def test_team_labels_are_applied_on_top(self):
        labels = BuildIdentity(owner="t", extra={"app.port": "8080"}).to_labels()
        assert labels["app.port"] == "8080"
