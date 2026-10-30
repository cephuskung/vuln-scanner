"""IVMP Phase 3: shortest/all-simple-path discovery over the attack graph."""

import networkx as nx


def find_paths_to(graph, target_node, cutoff=4, max_paths=3):
    """Up to max_paths distinct attacker routes from 'internet' to target_node,
    cheapest (lowest total weight) first."""
    if target_node not in graph or "internet" not in graph:
        return []
    try:
        raw_paths = list(nx.all_simple_paths(graph, "internet", target_node, cutoff=cutoff))
    except nx.NodeNotFound:
        return []

    scored = []
    for path in raw_paths:
        total_weight = sum(graph[u][v]["weight"] for u, v in zip(path, path[1:]))
        steps = [
            {"from": u, "to": v, "reason": graph[u][v].get("reason", ""), "weight": graph[u][v]["weight"]}
            for u, v in zip(path, path[1:])
        ]
        scored.append({
            "nodes": path,
            "labels": [graph.nodes[n].get("label", n) for n in path],
            "steps": steps,
            "weight": round(total_weight, 1),
            "hops": len(path) - 1,
        })

    scored.sort(key=lambda p: p["weight"])
    return scored[:max_paths]


def find_all_critical_paths(graph, max_paths_per_target=3):
    """Attack paths to every CRITICAL-criticality asset, ranked by how cheap
    the best path to each one is (cheapest/most-dangerous target first)."""
    results = []
    for node, data in graph.nodes(data=True):
        if data.get("type") == "asset" and data.get("criticality") == "CRITICAL":
            paths = find_paths_to(graph, node, max_paths=max_paths_per_target)
            if paths:
                results.append({
                    "target": node,
                    "target_label": data.get("label"),
                    "paths": paths,
                })

    results.sort(key=lambda r: r["paths"][0]["weight"])
    return results
