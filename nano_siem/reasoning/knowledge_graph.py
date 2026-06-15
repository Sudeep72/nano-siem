"""
reasoning/knowledge_graph.py — Alert Knowledge Graph

Builds an in-memory entity relationship graph from generated alerts:

  Source IP ──fired──> Alert ──maps to──> MITRE Technique ──belongs to──> Tactic
       │                  │
       └──affects──> Host  └──part of──> Correlation Chain

This is a READ-ONLY view over already-generated alerts — it does not
perform detection or influence alert generation. It exists to help
analysts (and the AI reasoning layer) understand relationships between
entities across multiple alerts: "show me everything connected to
203.0.113.5" or "what techniques has this host been associated with".

Graph is rebuilt on-demand from the alert list (no persistent storage —
matches NanoSIEM's in-memory v3 alert store). For large alert volumes,
this could be backed by a real graph DB, but for the SIEM's scale
(hundreds of alerts) an adjacency-dict representation is sufficient
and avoids adding a graph database dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NodeType(str, Enum):
    SOURCE_IP = "source_ip"
    HOST = "host"
    ALERT = "alert"
    TECHNIQUE = "technique"
    TACTIC = "tactic"
    CHAIN = "chain"


@dataclass
class GraphNode:
    id: str             # unique key, e.g. "ip:203.0.113.5" or "alert:abc123"
    type: NodeType
    label: str          # display name
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"id": self.id, "type": self.type.value, "label": self.label,
                "properties": self.properties}


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str       # "fired", "affects", "maps_to", "belongs_to", "part_of"

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target, "relation": self.relation}


@dataclass
class KnowledgeGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
        else:
            # merge properties (e.g. alert counts)
            self.nodes[node.id].properties.update(node.properties)

    def add_edge(self, edge: GraphEdge) -> None:
        key = (edge.source, edge.target, edge.relation)
        existing = {(e.source, e.target, e.relation) for e in self.edges}
        if key not in existing:
            self.edges.append(edge)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }

    def neighbors(self, node_id: str) -> list[GraphNode]:
        """Return all nodes directly connected to the given node."""
        connected_ids = set()
        for edge in self.edges:
            if edge.source == node_id:
                connected_ids.add(edge.target)
            elif edge.target == node_id:
                connected_ids.add(edge.source)
        return [self.nodes[nid] for nid in connected_ids if nid in self.nodes]

    def subgraph_for(self, node_id: str, depth: int = 1) -> KnowledgeGraph:
        """
        Return a subgraph containing the given node and everything
        within `depth` hops.
        """
        visited = {node_id}
        frontier = {node_id}
        for _ in range(depth):
            next_frontier = set()
            for nid in frontier:
                for neighbor in self.neighbors(nid):
                    if neighbor.id not in visited:
                        next_frontier.add(neighbor.id)
                        visited.add(neighbor.id)
            frontier = next_frontier

        sub = KnowledgeGraph()
        for nid in visited:
            if nid in self.nodes:
                sub.add_node(self.nodes[nid])
        for edge in self.edges:
            if edge.source in visited and edge.target in visited:
                sub.add_edge(edge)
        return sub


def build_knowledge_graph(alerts: list[dict]) -> KnowledgeGraph:
    """
    Build a knowledge graph from a list of alert dicts (as produced by
    Alert.to_dict() in alerting/manager.py).

    Node types created:
      - source_ip: from alert['source_key'] (if it looks like an IP)
      - host:      from alert['source_key'] (if not an IP) or event_message host
      - alert:     one per alert
      - technique: from alert['mitre_techniques']
      - tactic:    from alert['mitre_tactic']
      - chain:     from alert['chain_id'] (correlation alerts only)
    """
    import ipaddress

    graph = KnowledgeGraph()

    for alert in alerts:
        alert_id = alert.get("alert_id", "")
        if not alert_id:
            continue

        alert_node_id = f"alert:{alert_id}"
        graph.add_node(GraphNode(
            id=alert_node_id,
            type=NodeType.ALERT,
            label=alert.get("title", "Unknown Alert"),
            properties={
                "severity": alert.get("severity"),
                "alert_type": alert.get("alert_type"),
                "timestamp": alert.get("timestamp"),
                "hit_count": alert.get("hit_count", 1),
            },
        ))

        # Source entity — IP or hostname
        source_key = alert.get("source_key", "")
        if source_key:
            is_ip = False
            try:
                ipaddress.ip_address(source_key)
                is_ip = True
            except ValueError:
                pass

            entity_type = NodeType.SOURCE_IP if is_ip else NodeType.HOST
            entity_prefix = "ip" if is_ip else "host"
            entity_id = f"{entity_prefix}:{source_key}"

            if entity_id not in graph.nodes:
                graph.add_node(GraphNode(
                    id=entity_id,
                    type=entity_type,
                    label=source_key,
                    properties={"alert_count": 0},
                ))
            # Increment alert count for this alert
            existing = graph.nodes[entity_id]
            existing.properties["alert_count"] = existing.properties.get("alert_count", 0) + 1

            graph.add_edge(GraphEdge(source=entity_id, target=alert_node_id, relation="fired"))

        # MITRE tactic
        tactic = alert.get("mitre_tactic", "")
        if tactic:
            # Some chains have compound tactics like "Credential Access -> Initial Access"
            for t in tactic.split("→"):
                t = t.strip()
                if not t:
                    continue
                tactic_id = f"tactic:{t}"
                graph.add_node(GraphNode(id=tactic_id, type=NodeType.TACTIC, label=t))
                graph.add_edge(GraphEdge(source=alert_node_id, target=tactic_id, relation="belongs_to"))

        # MITRE techniques
        for tech in alert.get("mitre_techniques", []):
            tech_id = f"technique:{tech}"
            graph.add_node(GraphNode(id=tech_id, type=NodeType.TECHNIQUE, label=tech))
            graph.add_edge(GraphEdge(source=alert_node_id, target=tech_id, relation="maps_to"))
            # Link technique to tactic if both present
            if tactic:
                for t in tactic.split("→"):
                    t = t.strip()
                    if t:
                        graph.add_edge(GraphEdge(
                            source=tech_id, target=f"tactic:{t}", relation="belongs_to"
                        ))

        # Correlation chain
        chain_id = alert.get("chain_id", "")
        if chain_id:
            chain_node_id = f"chain:{chain_id}"
            graph.add_node(GraphNode(
                id=chain_node_id, type=NodeType.CHAIN,
                label=alert.get("title", chain_id),
            ))
            graph.add_edge(GraphEdge(source=alert_node_id, target=chain_node_id, relation="part_of"))

    return graph


def describe_entity(graph: KnowledgeGraph, entity_id: str) -> str:
    """
    Generate a plain-English description of an entity and its connections.
    Used as context for the AI reasoning layer (not a detection mechanism).
    """
    if entity_id not in graph.nodes:
        return f"No information found for '{entity_id}'."

    node = graph.nodes[entity_id]
    neighbors = graph.neighbors(entity_id)

    alerts = [n for n in neighbors if n.type == NodeType.ALERT]
    techniques = [n for n in neighbors if n.type == NodeType.TECHNIQUE]
    tactics = [n for n in neighbors if n.type == NodeType.TACTIC]
    chains = [n for n in neighbors if n.type == NodeType.CHAIN]

    # If this entity itself has no direct technique/tactic neighbors
    # (e.g. it's an IP, and techniques are 1 hop further via its alerts),
    # aggregate techniques/tactics from connected alerts.
    if not techniques or not tactics:
        for alert_node in alerts:
            for n in graph.neighbors(alert_node.id):
                if n.type == NodeType.TECHNIQUE and n not in techniques:
                    techniques.append(n)
                elif n.type == NodeType.TACTIC and n not in tactics:
                    tactics.append(n)

    lines = [f"Entity: {node.label} ({node.type.value})"]
    if node.properties.get("alert_count"):
        lines.append(f"Total alerts: {node.properties['alert_count']}")
    if alerts:
        lines.append(f"Associated alerts ({len(alerts)}):")
        for a in alerts[:10]:
            lines.append(f"  - [{a.properties.get('severity', '?').upper()}] {a.label}")
    if techniques:
        lines.append(f"MITRE techniques observed: {', '.join(t.label for t in techniques)}")
    if tactics:
        lines.append(f"Tactics involved: {', '.join(t.label for t in tactics)}")
    if chains:
        lines.append(f"Part of correlation chains: {', '.join(c.label for c in chains)}")

    return "\n".join(lines)
