from __future__ import annotations

from redatlas.data.schema import Framework, Technique
from redatlas.data.store import DataStore
from redatlas.modeling.inputs import SystemModel


def build_corpus(store: DataStore, *, include_atlas: bool) -> list[Technique]:
    techniques = store.all_techniques(framework=Framework.ATTACK)
    if include_atlas:
        techniques = techniques + store.all_techniques(framework=Framework.ATLAS)
    return techniques


def retrieve_relevant(
    system: SystemModel, corpus: list[Technique], *, top_k: int = 25
) -> list[Technique]:
    if not corpus:
        return []

    # scikit-learn is imported lazily so `redatlas data` commands, which never
    # need retrieval, don't pay its import cost.
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    query_text = system.to_search_text()
    documents = [f"{t.name} {t.description}" for t in corpus]

    vectorizer = TfidfVectorizer(stop_words="english", max_features=20000)
    matrix = vectorizer.fit_transform([query_text, *documents])
    query_vector = matrix[0:1]
    doc_vectors = matrix[1:]

    similarities = cosine_similarity(query_vector, doc_vectors)[0]
    ranked_indices = similarities.argsort()[::-1]

    results: list[Technique] = []
    seen_ids: set[str] = set()
    for idx in ranked_indices:
        if similarities[idx] <= 0:
            break
        technique = corpus[idx]
        if technique.id in seen_ids:
            continue
        seen_ids.add(technique.id)
        results.append(technique)
        if len(results) >= top_k:
            break

    return results
