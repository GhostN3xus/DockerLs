"""A cadeia entre o que entrou no build e o que saiu dele.

Um relatório de segurança afirma coisas sobre uma imagem. Sem procedência, a
afirmação não é verificável: dois builds do mesmo `--tag` produziam relatórios
indistinguíveis mesmo partindo de Dockerfiles diferentes, e nada ligava o
scan ao artefato que ele mediu. Numa cadeia de fornecimento, "nós escaneamos
essa imagem" sem digest é uma frase sobre nada.

O registro tem duas metades, e as duas existem por um motivo distinto:

* **antes do build** -- digest do Dockerfile, digest do contexto, digests das
  imagens base declaradas nos `FROM`, e a revisão do repositório. Isto
  responde "o que foi construído".
* **depois do build** -- id da imagem, digest do manifesto publicado, e a
  identidade do scanner que a mediu. Isto responde "o que saiu, e quem
  atestou".

A parte que faz disto controle e não decoração é a verificação entre as duas:
o Dockerfile e o contexto são digeridos de novo **depois** do build, e se
mudaram no meio do caminho o registro é marcado como quebrado. Um build cuja
entrada mudou enquanto ele acontecia não produziu a imagem que o relatório
descreve -- seja por edição concorrente, seja porque alguém quis exatamente
isso. É o mesmo princípio que governa o resto desta ferramenta: uma coisa que
não pôde ser verificada não é apresentada como verificada.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ProvenanceStatus(StrEnum):
    """O que o registro pode afirmar sobre si mesmo."""

    #: Entrada e saída digeridas, e a entrada não mudou durante o build.
    VERIFIED = "VERIFIED"
    #: O build aconteceu, mas algo não pôde ser digerido (contexto grande
    #: demais, arquivo ilegível). Não é uma acusação -- é a ausência de prova.
    INCOMPLETE = "INCOMPLETE"
    #: O Dockerfile ou o contexto mudaram entre o início e o fim do build.
    #: A imagem existe; o que ela não tem é uma entrada conhecida.
    INPUT_CHANGED = "INPUT_CHANGED"


@dataclass(frozen=True)
class SourceDigests:
    """O que entrou. Medido antes do `docker build` começar."""

    dockerfile: str = ""
    context: str = ""
    context_files: int = 0
    #: `FROM` declarado -> digest resolvido, quando resolvível. Uma base sem
    #: digest é uma tag móvel, e dizer isso é mais útil do que omitir.
    base_images: dict[str, str] = field(default_factory=dict)
    git_revision: str = ""
    #: Repositório com alterações não commitadas no momento do build. O commit
    #: sozinho mentiria sobre o que gerou a imagem.
    git_dirty: bool = False


@dataclass(frozen=True)
class ArtifactDigests:
    """O que saiu. Medido depois do build, e depois do push quando há um."""

    image_id: str = ""
    #: Digest do manifesto no registry. Só existe após o push -- é o único
    #: identificador que outra máquina consegue usar para puxar exatamente
    #: esta imagem.
    repo_digest: str = ""
    published_reference: str = ""
    scanner: str = ""


@dataclass(frozen=True)
class BuildProvenance:
    """Procedência completa de um build, pronta para ser arquivada."""

    tag: str
    source: SourceDigests = field(default_factory=SourceDigests)
    artifact: ArtifactDigests = field(default_factory=ArtifactDigests)
    #: Digests recalculados após o build. Iguais aos de `source` num build
    #: íntegro.
    source_after: SourceDigests = field(default_factory=SourceDigests)
    started_at: str = ""
    finished_at: str = ""

    @property
    def status(self) -> ProvenanceStatus:
        if not self.source.dockerfile or not self.source_after.dockerfile:
            return ProvenanceStatus.INCOMPLETE
        if (
            self.source.dockerfile != self.source_after.dockerfile
            or self.source.context != self.source_after.context
        ):
            return ProvenanceStatus.INPUT_CHANGED
        if not self.artifact.image_id:
            return ProvenanceStatus.INCOMPLETE
        return ProvenanceStatus.VERIFIED

    @property
    def is_verified(self) -> bool:
        return self.status is ProvenanceStatus.VERIFIED

    def explain(self) -> str:
        """Uma frase que um humano usa para decidir se confia no registro."""
        if self.status is ProvenanceStatus.INPUT_CHANGED:
            changed = []
            if self.source.dockerfile != self.source_after.dockerfile:
                changed.append("o Dockerfile")
            if self.source.context != self.source_after.context:
                changed.append("o contexto de build")
            return (
                f"{' e '.join(changed)} mudou durante o build: a imagem existe, mas "
                "não corresponde à entrada que foi medida no início"
            )
        if self.status is ProvenanceStatus.INCOMPLETE:
            return (
                "procedência incompleta: parte da entrada ou da saída não pôde ser "
                "digerida, então a cadeia não fecha"
            )
        return "entrada e saída digeridas, e a entrada não mudou durante o build"

    def to_dict(self) -> dict[str, object]:
        """O documento arquivado junto do relatório.

        Formato próprio, e propositalmente plano: um consumidor precisa
        conseguir comparar dois builds com um `diff` sem instalar nada.
        """
        return {
            "tag": self.tag,
            "status": str(self.status),
            "explanation": self.explain(),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "source": {
                "dockerfile_sha256": self.source.dockerfile,
                "context_sha256": self.source.context,
                "context_files": self.source.context_files,
                "base_images": dict(self.source.base_images),
                "git_revision": self.source.git_revision,
                "git_dirty": self.source.git_dirty,
            },
            "source_after_build": {
                "dockerfile_sha256": self.source_after.dockerfile,
                "context_sha256": self.source_after.context,
            },
            "artifact": {
                "image_id": self.artifact.image_id,
                "repo_digest": self.artifact.repo_digest,
                "published_reference": self.artifact.published_reference,
                "scanner": self.artifact.scanner,
            },
        }
