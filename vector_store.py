# ─────────────────────────────────────────
# SentinelIQ — Vector Store (Day 5)
# Semantic search over MITRE ATT&CK techniques.
#
# Primary engine: ChromaDB persistent vector search.
# Fallback engine: pure-Python TF-IDF-style keyword scoring
#   (used automatically if ChromaDB fails to load on this
#    Python version — no extra packages required).
# ─────────────────────────────────────────

from mitre_mapper import MITRE_TECHNIQUES

# Folder where ChromaDB persists its data
CHROMA_PATH = "./chroma_db"
COLLECTION_NAME = "mitre_techniques"

# Module-level state, filled in by initialize_chromadb()
_collection = None
_use_chromadb = False


def _build_document(tech: dict) -> str:
    """Turn one MITRE technique into a single text document
    that captures everything worth searching on."""
    actors = ", ".join(tech.get("threat_actors", []))
    mitigations = ", ".join(tech.get("mitigations", []))
    return (
        f"ID: {tech['technique_id']}. "
        f"Name: {tech['name']}. "
        f"Tactic: {tech['tactic']}. "
        f"Description: {tech['description']} "
        f"Threat actors: {actors}. "
        f"Mitigations: {mitigations}"
    )


def initialize_chromadb():
    """
    Create a persistent ChromaDB client and return the
    'mitre_techniques' collection.

    Returns the collection on success, or None if ChromaDB
    cannot be initialized (caller falls back to TF-IDF).
    """
    try:
        import chromadb

        client = chromadb.PersistentClient(path=CHROMA_PATH)
        collection = client.get_or_create_collection(
            name=COLLECTION_NAME
        )
        return collection

    except Exception as e:
        print(f"[vector_store] ChromaDB init failed: {e}")
        return None


def embed_mitre_techniques(collection) -> int:
    """
    Embed every MITRE technique into the ChromaDB collection.

    Uses the technique ID as the document ID and skips any
    technique that is already embedded, so this is safe to
    run on every startup without creating duplicates.

    Returns the number of newly embedded techniques.
    """
    if collection is None:
        return 0

    # Find which IDs are already stored
    try:
        existing = set(collection.get().get("ids", []))
    except Exception:
        existing = set()

    new_ids = []
    new_docs = []
    for technique_id, tech in MITRE_TECHNIQUES.items():
        if technique_id in existing:
            continue  # already embedded — skip to avoid duplicates
        new_ids.append(technique_id)
        new_docs.append(_build_document(tech))

    if new_ids:
        collection.add(documents=new_docs, ids=new_ids)

    return len(new_ids)


# ─────────────────────────────────────────
# FALLBACK: TF-IDF-style keyword search
# Pure Python, no external packages.
# ─────────────────────────────────────────
def _search_tfidf(query: str) -> list:
    """
    Score each technique by how many unique query words appear
    in its name + tactic + description. Returns the top 3.
    """
    query_words = set(query.lower().split())

    scored = []
    for tech in MITRE_TECHNIQUES.values():
        haystack = (
            f"{tech['name']} {tech['tactic']} {tech['description']}"
        ).lower()
        score = sum(1 for word in query_words if word in haystack)
        scored.append((score, tech))

    # Sort by score descending, keep top 3
    scored.sort(key=lambda pair: pair[0], reverse=True)

    results = []
    for score, tech in scored[:3]:
        results.append({
            "technique_id": tech["technique_id"],
            "name": tech["name"],
            "tactic": tech["tactic"],
            "description": tech["description"],
            "score": score,
            "search_method": "tfidf_fallback",
        })
    return results


# ─────────────────────────────────────────
# STARTUP: initialize once at import time
# ─────────────────────────────────────────
_collection = initialize_chromadb()
if _collection is not None:
    try:
        embed_mitre_techniques(_collection)
        _use_chromadb = True
    except Exception as e:
        print(f"[vector_store] Embedding failed, using fallback: {e}")
        _use_chromadb = False


def search_mitre(query: str) -> list:
    """
    Semantic search for MITRE techniques matching a natural
    language query. Returns the top 3 results.

    Each result includes: technique_id, name, tactic,
    description, score, and search_method ("chromadb" or
    "tfidf_fallback").
    """
    # Use ChromaDB if it initialized successfully
    if _use_chromadb and _collection is not None:
        try:
            response = _collection.query(
                query_texts=[query],
                n_results=3
            )

            ids = response.get("ids", [[]])[0]
            distances = response.get("distances", [[]])[0]

            results = []
            for index, technique_id in enumerate(ids):
                tech = MITRE_TECHNIQUES.get(technique_id)
                if tech is None:
                    continue

                # Convert distance to a 0-1 similarity-style score
                distance = (
                    distances[index]
                    if index < len(distances) else 0
                )
                score = round(1 / (1 + distance), 4)

                results.append({
                    "technique_id": tech["technique_id"],
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "description": tech["description"],
                    "score": score,
                    "search_method": "chromadb",
                })

            if results:
                return results

        except Exception as e:
            # If a query fails at runtime, fall back gracefully
            print(f"[vector_store] ChromaDB query failed: {e}")

    # Fallback path
    return _search_tfidf(query)
