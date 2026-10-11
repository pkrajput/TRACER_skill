"""ChromaDB-backed store for reasoning embeddings.

Each step's reasoning (prompt + written turns) is embedded once and tagged with its
``step_id`` and the node ids / qualified names / file paths it touched. ChromaDB metadata only
accepts scalars, so all id lists are flattened into comma-separated strings.

Embeddings default to ``all-MiniLM-L6-v2`` (via sentence-transformers). A deterministic,
dependency-free ``hash`` embedder is also available for offline tests, selected by passing
``embedding_model="hash"``.
"""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
from typing import Optional, Sequence

from ..models import LinkedNode, Step

_HASH_DIM = 256


class HashEmbeddingFunction:
    """A deterministic bag-of-tokens hashing embedder.

    Not semantically strong, but stable and offline - ideal for tests and CI where downloading
    a transformer model is undesirable. Implements ChromaDB's embedding-function interface.
    """

    def __init__(self, dim: int = _HASH_DIM) -> None:
        self.dim = dim

    # Legacy ChromaDB API: called with a list of texts.
    def __call__(self, input: Sequence[str]) -> list[list[float]]:  # noqa: A002 - chroma API
        return self._embed_list(input)

    # Modern ChromaDB API (>=1.x): separate document/query embedding entry points.
    def embed_documents(self, input: Sequence[str]) -> list[list[float]]:  # noqa: A002
        """Embed a batch of documents (Chroma embedding-function API)."""
        return self._embed_list(input)

    def embed_query(self, input) -> list[list[float]]:  # noqa: A002 - chroma API
        """Embed a query string or list (Chroma embedding-function API)."""
        texts = [input] if isinstance(input, str) else list(input)
        return self._embed_list(texts)

    # Newer ChromaDB versions probe for these.
    def name(self) -> str:  # pragma: no cover - trivial
        """Stable name for this embedding function."""
        return "hash"

    def is_legacy(self) -> bool:  # pragma: no cover - trivial
        """Whether Chroma should treat this as a legacy embedding function."""
        return True

    def _embed_list(self, input: Sequence[str]) -> list[list[float]]:  # noqa: A002
        return [self._embed(text) for text in input]

    def _embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for token in (text or "").lower().split():
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            vec[h % self.dim] += 1.0
        norm = math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            vec = [v / norm for v in vec]
        return vec


def build_embedding_function(embedding_model: str):
    """Return a ChromaDB-compatible embedding function for the given model name."""
    if embedding_model == "hash":
        return HashEmbeddingFunction()
    # Lazy import so the hash path (and the rest of the package) works without the heavy dep.
    from chromadb.utils import embedding_functions

    return embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=embedding_model
    )


def _flatten(values: Sequence) -> str:
    """Flatten a list into a comma-separated string (ChromaDB metadata is scalar-only)."""
    return ",".join(str(v) for v in values if v is not None and str(v) != "")


class ChromaStore:
    """Persistent ChromaDB collection of reasoning embeddings."""

    COLLECTION = "reasoning"

    def __init__(self, chroma_dir: str | Path, embedding_model: str = "all-MiniLM-L6-v2") -> None:
        import chromadb

        self.chroma_dir = Path(chroma_dir)
        self.chroma_dir.mkdir(parents=True, exist_ok=True)
        self.embedding_model = embedding_model
        self._client = chromadb.PersistentClient(path=str(self.chroma_dir))
        self._embed_fn = build_embedding_function(embedding_model)
        self._collection = self._client.get_or_create_collection(
            name=self.COLLECTION,
            embedding_function=self._embed_fn,
            metadata={"hnsw:space": "cosine"},
        )

    def add_step(self, step: Step, links: list[LinkedNode]) -> None:
        """Embed a step's reasoning and store it with flattened node/file metadata."""
        node_ids = [ln.node.node_id for ln in links if ln.node.node_id is not None]
        qns = [ln.node.qualified_name for ln in links]
        files = sorted({ln.node.file_path for ln in links if ln.node.file_path})

        metadata = {
            "step_id": step.step_id,
            "after_sha": step.after_sha or "",
            "before_sha": step.before_sha or "",
            "timestamp": step.timestamp or "",
            "node_ids": _flatten(node_ids),
            "qualified_names": _flatten(qns),
            "file_paths": _flatten(files),
            "lineage_id": getattr(step, "lineage_id", None) or "main",
        }
        # upsert keeps re-recording idempotent.
        self._collection.upsert(
            ids=[step.step_id],
            documents=[step.document()],
            metadatas=[metadata],
        )

    def update_step_node_metadata(
        self,
        step_id: str,
        *,
        node_ids: Sequence,
        qualified_names: Sequence[str],
        file_paths: Sequence[str],
    ) -> bool:
        """Patch a stored step's flattened node metadata in place (used by reconcile).

        Only the node-related keys are rewritten; the document, embedding, and remaining
        metadata are preserved. Returns False when the step was never embedded.
        """
        res = self._collection.get(ids=[step_id])
        if not (res.get("ids") or []):
            return False
        metadata = dict((res.get("metadatas") or [None])[0] or {})
        metadata["node_ids"] = _flatten(node_ids)
        metadata["qualified_names"] = _flatten(qualified_names)
        metadata["file_paths"] = _flatten(file_paths)
        self._collection.update(ids=[step_id], metadatas=[metadata])
        return True

    def query(
        self,
        text: str,
        k: int = 5,
        *,
        visible_step_ids: Optional[set[str]] = None,
    ) -> list[dict]:
        """Return up to ``k`` reasoning hits ordered by similarity.

        When ``visible_step_ids`` is set, over-fetch and keep only hits whose ``step_id`` is
        visible on the active lineage (one-way visibility).
        """
        fetch = k
        if visible_step_ids is not None:
            fetch = max(k * 4, k)
        res = self._collection.query(query_texts=[text], n_results=fetch)
        out: list[dict] = []
        ids = (res.get("ids") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        for i, step_id in enumerate(ids):
            if visible_step_ids is not None and step_id not in visible_step_ids:
                continue
            out.append(
                {
                    "step_id": step_id,
                    "document": docs[i] if i < len(docs) else "",
                    "metadata": metas[i] if i < len(metas) else {},
                    "distance": dists[i] if i < len(dists) else None,
                }
            )
            if len(out) >= k:
                break
        return out

    def count(self) -> int:
        """Number of reasoning documents currently stored."""
        return self._collection.count()
