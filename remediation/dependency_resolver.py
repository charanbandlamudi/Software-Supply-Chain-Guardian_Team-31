from __future__ import annotations

import json
from pathlib import Path

import networkx as nx


def _graph_from_input(graph):
    if isinstance(graph, nx.DiGraph):
        return graph
    if isinstance(graph, dict):
        doc = graph
    else:
        doc = json.loads(Path(graph).read_text(encoding="utf-8"))

    result = nx.DiGraph()
    result.graph["root"] = doc.get("root")
    for node in doc.get("nodes", []):
        node_id = node.get("id")
        if node_id:
            result.add_node(node_id, **node)
    for edge in doc.get("edges", []):
        source = edge.get("from")
        target = edge.get("to")
        if source in result and target in result:
            result.add_edge(source, target)
    return result


def find_dependency(graph, finding: dict) -> dict:
    g = _graph_from_input(graph)
    purl = finding.get("purl")

    if purl:
        matches = [(node, data) for node, data in g.nodes(data=True)
                   if data.get("purl") == purl]
        if len(matches) == 1:
            return _dependency_info(g, matches[0][0], matches[0][1])
        if len(matches) > 1:
            return {"status": "ambiguous", "node_ids": [node for node, _ in matches]}

    matches = [
        (node, data) for node, data in g.nodes(data=True)
        if data.get("name") == finding.get("package")
        and str(data.get("version")) == str(finding.get("current_version"))
    ]
    if len(matches) == 1:
        return _dependency_info(g, matches[0][0], matches[0][1])
    if len(matches) > 1:
        return {"status": "ambiguous", "node_ids": [node for node, _ in matches]}
    return {"status": "unresolved"}


def _dependency_info(g: nx.DiGraph, node: str, data: dict) -> dict:
    root = g.graph.get("root")
    dep_type = data.get("dep_type")
    if not dep_type and root:
        direct = set(g.successors(root))
        if node == root:
            dep_type = "root"
        elif node in direct:
            dep_type = "direct"
        elif root in g and nx.has_path(g, root, node):
            dep_type = "transitive"
        else:
            dep_type = "unresolved"

    paths = data.get("path_ids") or []
    if not paths and root and root in g and nx.has_path(g, root, node):
        try:
            paths = nx.shortest_path(g, root, node)
        except nx.NetworkXNoPath:
            paths = []

    parents = data.get("parent_ids")
    if parents is None:
        parents = list(g.predecessors(node))
    children = data.get("child_ids")
    if children is None:
        children = list(g.successors(node))

    return {
        "status": "resolved",
        "node_id": node,
        "dependency_type": dep_type or "unresolved",
        "path_ids": paths,
        "parent_ids": parents,
        "child_ids": children,
    }

