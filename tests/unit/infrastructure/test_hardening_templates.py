"""Regressões do provedor de templates hardened.

O defeito de origem: `TEMPLATES_DIR` era montado como
`Path(__file__).parent.parent.parent / "infrastructure" / "templates"`, o que
resolve para `<raiz-do-repo>/infrastructure/templates` -- um diretório que
nunca existiu. `exists()` dava False em toda execução, os três templates
versionados jamais eram lidos, e `--hardened` caía num template genérico que
abria com `FROM <base>:latest`. Ou seja: a ferramenta reprovava base flutuante
nas imagens dos outros (regra DF001) e emitia uma na sua própria saída
"hardened".
"""

from __future__ import annotations

import pytest

from dockerls.infrastructure.dockerfile_validator import (
    DockerfileValidator,
    HardeningTemplates,
    UnknownHardeningTemplateError,
)


class TestTemplatesAreActuallyReachable:
    def test_templates_dir_exists(self):
        assert HardeningTemplates.TEMPLATES_DIR.is_dir(), (
            "TEMPLATES_DIR does not point at a real directory, so every "
            "template lookup silently falls back"
        )

    def test_each_advertised_template_is_read_from_disk(self):
        provider = HardeningTemplates()
        for name in provider.list_templates():
            content = provider.get_template(name)
            assert content.strip(), f"template {name} is empty"

    def test_smart_compound_resolution(self):
        provider = HardeningTemplates()
        # Test exact and compound looks
        assert "22-bookworm-slim" in provider.get_template("node:22-bookworm-slim")
        assert "22-alpine" in provider.get_template("node:22-alpine")
        assert "24.04" in provider.get_template("ubuntu:24.04")
        assert "bookworm-slim" in provider.get_template("debian")
        assert "3.20" in provider.get_template("alpine")
        assert "distroless/static-debian12" in provider.get_template("go-distroless")
        assert "FROM scratch" in provider.get_template("rust-scratch")

    def test_list_templates_matches_what_get_template_serves(self):
        provider = HardeningTemplates()
        listed = provider.list_templates()

        assert listed, "no template is reachable at all"
        for name in listed:
            assert provider.get_template(name).strip()


class TestUnknownBaseFailsLoudly:
    def test_unknown_base_raises_instead_of_inventing_a_dockerfile(self):
        with pytest.raises(UnknownHardeningTemplateError) as exc:
            HardeningTemplates().get_template("unknown_xyz")

        # A mensagem precisa dizer o que existe, não só o que falhou.
        assert "unknown_xyz" in str(exc.value)
        for name in HardeningTemplates().list_templates():
            assert name in str(exc.value)

    def test_it_is_a_value_error_so_the_cli_reports_it_as_user_error(self):
        assert issubclass(UnknownHardeningTemplateError, ValueError)


class TestGeneratedTemplatesPassOurOwnRules:
    """Um gerador "hardened" cuja saída reprova nas próprias regras da
    ferramenta é pior que inútil: ele certifica o que não deveria."""

    def test_all_generated_dockerfiles_pin_their_base_and_drop_root(self, tmp_path):
        provider = HardeningTemplates()
        validator = DockerfileValidator()

        for name in provider.list_templates():
            out = tmp_path / f"Dockerfile.{name}"
            provider.generate_hardened_dockerfile(
                dockerfile_path=tmp_path, base_image=name, output_path=out
            )

            result = validator.validate(out)
            failed = {c.check for c in result.checks if c.status.value == "FAIL"}
            assert "base_image_pinned" not in failed, f"{name} template uses a floating base tag"
            assert "non_root_user" not in failed, f"{name} template runs as root"


class TestTemplatesAreShippedInTheDistribution:
    def test_declared_as_package_data(self):
        """Os templates são arquivos de dados: sem `package-data` eles ficam
        de fora da wheel e `--hardened` só funciona num checkout."""
        import tomllib
        from pathlib import Path

        root = Path(__file__).resolve().parents[3]
        pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        patterns = pyproject["tool"]["setuptools"]["package-data"]["dockerls"]

        assert any("templates" in p and p.endswith(".dockerfile") for p in patterns)
