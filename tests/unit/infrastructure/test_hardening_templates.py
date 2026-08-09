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

    @pytest.mark.parametrize("name", ["node", "python", "go"])
    def test_each_advertised_template_is_read_from_disk(self, name):
        provider = HardeningTemplates()
        content = provider.get_template(name)

        on_disk = (provider.TEMPLATES_DIR / "hardening" / f"{name}.dockerfile").read_text(
            encoding="utf-8"
        )
        assert content == on_disk

    def test_list_templates_matches_what_get_template_serves(self):
        provider = HardeningTemplates()
        listed = provider.list_templates()

        assert listed, "no template is reachable at all"
        for name in listed:
            assert provider.get_template(name).strip()


class TestUnknownBaseFailsLoudly:
    def test_unknown_base_raises_instead_of_inventing_a_dockerfile(self):
        with pytest.raises(UnknownHardeningTemplateError) as exc:
            HardeningTemplates().get_template("java")

        # A mensagem precisa dizer o que existe, não só o que falhou.
        assert "java" in str(exc.value)
        for name in HardeningTemplates().list_templates():
            assert name in str(exc.value)

    def test_it_is_a_value_error_so_the_cli_reports_it_as_user_error(self):
        assert issubclass(UnknownHardeningTemplateError, ValueError)


class TestGeneratedTemplatesPassOurOwnRules:
    """Um gerador "hardened" cuja saída reprova nas próprias regras da
    ferramenta é pior que inútil: ele certifica o que não deveria."""

    @pytest.mark.parametrize("name", ["node", "python", "go"])
    def test_generated_dockerfile_pins_its_base_and_drops_root(self, name, tmp_path):
        out = tmp_path / "Dockerfile"
        HardeningTemplates().generate_hardened_dockerfile(
            dockerfile_path=tmp_path, base_image=name, output_path=out
        )

        result = DockerfileValidator().validate(out)
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
