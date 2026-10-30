"""IVMP Phase 3: choke-point identification.

Betweenness centrality finds assets that sit on the most attack paths -
patching one of these can break multiple attacker routes at once, which is
a prioritization signal raw CVSS/severity can't give you on its own.
"""

import networkx as nx


def rank_choke_points(graph, top_n=10):
    if graph.number_of_nodes() < 2:
        return []

    centrality = nx.betweenness_centrality(graph, weight="weight")

    ranked = []
    for node, score in centrality.items():
        if node == "internet" or score == 0:
            continue
        data = graph.nodes[node]
        ranked.append({
            "node": node,
            "label": data.get("label"),
            "criticality": data.get("criticality"),
            "exposure": data.get("exposure"),
            "centrality": round(score, 3),
        })

    ranked.sort(key=lambda r: r["centrality"], reverse=True)
    return ranked[:top_n]
