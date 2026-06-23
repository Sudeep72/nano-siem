"""
test_knowledge_graph.py — Tests for reasoning/knowledge_graph.py
"""

import json
import pytest

from nano_siem.reasoning.knowledge_graph import (
    build_knowledge_graph, describe_entity, KnowledgeGraph,
    GraphNode, GraphEdge, NodeType,
)


SIGMA_ALERT = {
    "alert_id": "alert-001",
    "alert_type": "sigma",
    "title": "SSH Brute Force Attempt",
    "severity": "high",
    "source_key": "203.0.113.5",
    "timestamp": 100.0,
    "hit_count": 3,
    "mitre_tactic": "Credential Access",
    "mitre_techniques": ["T1110.001"],
    "chain_id": "",
}

CORR_ALERT = {
    "alert_id": "alert-002",
    "alert_type": "correlation",
    "title": "Brute Force Followed by Successful Login",
    "severity": "critical",
    "source_key": "203.0.113.5",
    "timestamp": 160.0,
    "hit_count": 1,
    "mitre_tactic": "Credential Access → Initial Access",
    "mitre_techniques": ["T1110", "T1078"],
    "chain_id": "chain-001",
}

ML_ALERT = {
    "alert_id": "alert-003",
    "alert_type": "ml",
    "title": "ML Anomaly Detected (score=0.99)",
    "severity": "high",
    "source_key": "web-01",   # hostname, not IP
    "timestamp": 200.0,
    "hit_count": 1,
    "mitre_tactic": "",
    "mitre_techniques": [],
    "chain_id": "",
}


class TestGraphConstruction:
    def test_build_empty(self):
        graph = build_knowledge_graph([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0

    def test_single_sigma_alert(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        assert "alert:alert-001" in graph.nodes
        assert "ip:203.0.113.5" in graph.nodes
        assert "technique:T1110.001" in graph.nodes
        assert "tactic:Credential Access" in graph.nodes

    def test_ip_vs_hostname_node_type(self):
        graph = build_knowledge_graph([SIGMA_ALERT, ML_ALERT])
        assert graph.nodes["ip:203.0.113.5"].type == NodeType.SOURCE_IP
        assert graph.nodes["host:web-01"].type == NodeType.HOST

    def test_correlation_alert_has_chain_node(self):
        graph = build_knowledge_graph([CORR_ALERT])
        assert "chain:chain-001" in graph.nodes
        assert graph.nodes["chain:chain-001"].type == NodeType.CHAIN

    def test_compound_tactic_split(self):
        graph = build_knowledge_graph([CORR_ALERT])
        assert "tactic:Credential Access" in graph.nodes
        assert "tactic:Initial Access" in graph.nodes

    def test_edges_created(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        edge_relations = {(e.source, e.target, e.relation) for e in graph.edges}
        assert ("ip:203.0.113.5", "alert:alert-001", "fired") in edge_relations
        assert ("alert:alert-001", "technique:T1110.001", "maps_to") in edge_relations
        assert ("alert:alert-001", "tactic:Credential Access", "belongs_to") in edge_relations

    def test_technique_linked_to_tactic(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        edge_relations = {(e.source, e.target, e.relation) for e in graph.edges}
        assert ("technique:T1110.001", "tactic:Credential Access", "belongs_to") in edge_relations

    def test_alert_count_increments(self):
        # Same source IP across two alerts should increment alert_count
        graph = build_knowledge_graph([SIGMA_ALERT, CORR_ALERT])
        ip_node = graph.nodes["ip:203.0.113.5"]
        assert ip_node.properties["alert_count"] == 2

    def test_multiple_alerts_combined(self):
        graph = build_knowledge_graph([SIGMA_ALERT, CORR_ALERT, ML_ALERT])
        assert "alert:alert-001" in graph.nodes
        assert "alert:alert-002" in graph.nodes
        assert "alert:alert-003" in graph.nodes
        assert "host:web-01" in graph.nodes

    def test_alert_missing_id_skipped(self):
        bad_alert = {**SIGMA_ALERT, "alert_id": ""}
        graph = build_knowledge_graph([bad_alert])
        assert len(graph.nodes) == 0


class TestNeighbors:
    def test_neighbors_of_ip(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        neighbors = graph.neighbors("ip:203.0.113.5")
        neighbor_ids = {n.id for n in neighbors}
        assert "alert:alert-001" in neighbor_ids

    def test_neighbors_of_alert(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        neighbors = graph.neighbors("alert:alert-001")
        neighbor_ids = {n.id for n in neighbors}
        assert "ip:203.0.113.5" in neighbor_ids
        assert "technique:T1110.001" in neighbor_ids

    def test_neighbors_of_unknown_node(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        neighbors = graph.neighbors("nonexistent")
        assert neighbors == []


class TestSubgraph:
    def test_subgraph_depth_1(self):
        graph = build_knowledge_graph([SIGMA_ALERT, CORR_ALERT])
        sub = graph.subgraph_for("ip:203.0.113.5", depth=1)
        assert "ip:203.0.113.5" in sub.nodes
        assert "alert:alert-001" in sub.nodes
        assert "alert:alert-002" in sub.nodes

    def test_subgraph_depth_2_includes_techniques(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        sub = graph.subgraph_for("ip:203.0.113.5", depth=2)
        assert "technique:T1110.001" in sub.nodes

    def test_subgraph_only_relevant_edges(self):
        graph = build_knowledge_graph([SIGMA_ALERT, ML_ALERT])
        sub = graph.subgraph_for("ip:203.0.113.5", depth=2)
        # host:web-01 should NOT be in this subgraph
        assert "host:web-01" not in sub.nodes


class TestDescribeEntity:
    def test_describe_known_entity(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        desc = describe_entity(graph, "ip:203.0.113.5")
        assert "203.0.113.5" in desc
        assert "alert" in desc.lower()

    def test_describe_unknown_entity(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        desc = describe_entity(graph, "ip:1.2.3.4")
        assert "No information" in desc

    def test_describe_includes_techniques(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        desc = describe_entity(graph, "ip:203.0.113.5")
        assert "T1110.001" in desc

    def test_describe_includes_chain(self):
        graph = build_knowledge_graph([CORR_ALERT])
        desc = describe_entity(graph, "ip:203.0.113.5")
        assert "chain" in desc.lower() or "Brute Force" in desc


class TestSerialization:
    def test_to_dict_structure(self):
        graph = build_knowledge_graph([SIGMA_ALERT])
        d = graph.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert "node_count" in d
        assert "edge_count" in d

    def test_to_dict_json_serializable(self):
        graph = build_knowledge_graph([SIGMA_ALERT, CORR_ALERT, ML_ALERT])
        d = graph.to_dict()
        json.dumps(d)  # should not raise

    def test_node_to_dict(self):
        node = GraphNode(id="ip:1.2.3.4", type=NodeType.SOURCE_IP, label="1.2.3.4")
        d = node.to_dict()
        assert d["type"] == "source_ip"

    def test_edge_to_dict(self):
        edge = GraphEdge(source="a", target="b", relation="fired")
        d = edge.to_dict()
        assert d["relation"] == "fired"


class TestAddNodeMerging:
    def test_add_node_merges_properties(self):
        graph = KnowledgeGraph()
        graph.add_node(GraphNode(id="x", type=NodeType.HOST, label="x", properties={"a": 1}))
        graph.add_node(GraphNode(id="x", type=NodeType.HOST, label="x", properties={"b": 2}))
        assert graph.nodes["x"].properties == {"a": 1, "b": 2}

    def test_add_edge_no_duplicates(self):
        graph = KnowledgeGraph()
        graph.add_edge(GraphEdge(source="a", target="b", relation="fired"))
        graph.add_edge(GraphEdge(source="a", target="b", relation="fired"))
        assert len(graph.edges) == 1
