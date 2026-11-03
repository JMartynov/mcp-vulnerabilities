import re
from collections.abc import Iterable
from collections import defaultdict


class CanonicalAliasGraph:
    """Disjoint-Set Forest (DSU) to manage connected components of vulnerability aliases."""

    def __init__(self) -> None:
        self.parent: dict[str, str] = {}
        self.rank: dict[str, int] = {}

    def _ensure(self, item: str) -> None:
        if item not in self.parent:
            self.parent[item] = item
            self.rank[item] = 0

    def add_alias(self, id_a: str, id_b: str) -> None:
        """Add an alias relationship between two identifiers."""
        self.union(id_a, id_b)

    def add_aliases(self, primary_id: str, aliases: Iterable[str]) -> None:
        """Add alias relationships between a primary ID and a list of aliases."""
        for alias in aliases:
            self.union(primary_id, alias)

    def find(self, item: str) -> str:
        """Find the root representative of the given item with path compression."""
        self._ensure(item)
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, item_a: str, item_b: str) -> None:
        """Unite the clusters containing item_a and item_b using union-by-rank."""
        root_a = self.find(item_a)
        root_b = self.find(item_b)

        if root_a != root_b:
            if self.rank[root_a] > self.rank[root_b]:
                self.parent[root_b] = root_a
            elif self.rank[root_a] < self.rank[root_b]:
                self.parent[root_a] = root_b
            else:
                self.parent[root_b] = root_a
                self.rank[root_a] += 1

    def get_cluster(self, identifier: str) -> set[str]:
        """Get all identifiers in the same cluster as the given identifier."""
        root = self.find(identifier)
        return {item for item in self.parent if self.find(item) == root}

    def get_all_clusters(self) -> list[set[str]]:
        """Return a list of all disjoint clusters."""
        clusters = defaultdict(set)
        for item in self.parent:
            clusters[self.find(item)].add(item)
        return list(clusters.values())

    @staticmethod
    def get_canonical_id(cluster: Iterable[str] | str) -> str:
        """
        Deterministically select the primary canonical identifier from a cluster.
        Hierarchy: CVE > GHSA > MAL > PYSEC > GLAD > Lexicographical.
        For CVE, lower year/sequence is preferred.
        """
        if isinstance(cluster, str):
            return cluster

        items = list(cluster)
        if not items:
            raise ValueError("Cluster cannot be empty")

        def _sort_key(identifier: str) -> tuple[int, int, int, str]:
            ident_upper = identifier.upper()
            if ident_upper.startswith("CVE-"):
                # CVE-YYYY-NNNNN
                match = re.match(r"^CVE-(\d+)-(\d+)$", ident_upper)
                if match:
                    year, seq = int(match.group(1)), int(match.group(2))
                    return (1, year, seq, identifier)
                return (1, 9999, 9999999, identifier)
            elif ident_upper.startswith("GHSA-"):
                return (2, 0, 0, identifier)
            elif ident_upper.startswith("MAL-"):
                return (3, 0, 0, identifier)
            elif ident_upper.startswith("PYSEC-"):
                return (4, 0, 0, identifier)
            elif ident_upper.startswith("GLAD-"):
                return (5, 0, 0, identifier)
            else:
                return (6, 0, 0, identifier)

        # Sort based on the deterministic key and return the first element
        return sorted(items, key=_sort_key)[0]
