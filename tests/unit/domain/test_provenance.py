"""A cadeia entre entrada e saída do build.

A parte que faz disto controle e não decoração é a comparação: a entrada é
digerida antes e depois, e se mudou no meio do caminho a imagem existe mas não
corresponde ao que foi medido.
"""

from __future__ import annotations

from dockerls.domain.value_objects.provenance import (
    ArtifactDigests,
    BuildProvenance,
    ProvenanceStatus,
    SourceDigests,
)

_BEFORE = SourceDigests(dockerfile="sha256:aa", context="sha256:bb", context_files=12)
_ARTIFACT = ArtifactDigests(image_id="sha256:cc", scanner="trivy")


class TestVerification:
    def test_unchanged_input_with_an_artifact_is_verified(self):
        record = BuildProvenance(
            tag="app:1.0", source=_BEFORE, source_after=_BEFORE, artifact=_ARTIFACT
        )
        assert record.status is ProvenanceStatus.VERIFIED
        assert record.is_verified is True

    def test_a_changed_dockerfile_breaks_the_chain(self):
        record = BuildProvenance(
            tag="app:1.0",
            source=_BEFORE,
            source_after=SourceDigests(dockerfile="sha256:OUTRO", context="sha256:bb"),
            artifact=_ARTIFACT,
        )
        assert record.status is ProvenanceStatus.INPUT_CHANGED
        assert "Dockerfile" in record.explain()

    def test_a_changed_context_breaks_the_chain(self):
        record = BuildProvenance(
            tag="app:1.0",
            source=_BEFORE,
            source_after=SourceDigests(dockerfile="sha256:aa", context="sha256:OUTRO"),
            artifact=_ARTIFACT,
        )
        assert record.status is ProvenanceStatus.INPUT_CHANGED
        assert "contexto" in record.explain()

    def test_an_undigested_input_is_incomplete_not_verified(self):
        # Ausência de prova nunca vira prova de integridade -- é o mesmo
        # princípio que rege o scan que não completou.
        record = BuildProvenance(tag="app:1.0", artifact=_ARTIFACT)
        assert record.status is ProvenanceStatus.INCOMPLETE
        assert record.is_verified is False

    def test_without_an_artifact_the_chain_does_not_close(self):
        record = BuildProvenance(tag="app:1.0", source=_BEFORE, source_after=_BEFORE)
        assert record.status is ProvenanceStatus.INCOMPLETE


class TestArchivedDocument:
    def test_the_document_carries_both_halves(self):
        record = BuildProvenance(
            tag="app:1.0",
            source=SourceDigests(
                dockerfile="sha256:aa",
                context="sha256:bb",
                context_files=3,
                base_images={"python:3.12-alpine@sha256:dd": "sha256:dd"},
                git_revision="abc123",
                git_dirty=True,
            ),
            source_after=SourceDigests(dockerfile="sha256:aa", context="sha256:bb"),
            artifact=ArtifactDigests(
                image_id="sha256:cc",
                repo_digest="sha256:ee",
                published_reference="meuacr.azurecr.io/apps/app:1.0",
                scanner="trivy",
            ),
        )
        document = record.to_dict()
        assert document["status"] == "VERIFIED"
        assert document["source"]["git_dirty"] is True
        assert document["source"]["base_images"]["python:3.12-alpine@sha256:dd"] == "sha256:dd"
        assert document["artifact"]["repo_digest"] == "sha256:ee"
        assert document["source_after_build"]["context_sha256"] == "sha256:bb"

    def test_a_moving_base_tag_is_recorded_as_such(self):
        # Uma base sem digest é tag móvel; registrar isso vale mais que omitir.
        record = BuildProvenance(
            tag="app:1.0", source=SourceDigests(base_images={"python:3.12": ""})
        )
        assert record.to_dict()["source"]["base_images"] == {"python:3.12": ""}
