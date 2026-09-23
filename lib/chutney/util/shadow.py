"""
Utilities for setting up shadow simulations.

We wrote these utilities while developing chutney-related functionality, but
they aren't chutney-specific. In particular, they don't import other chutney
modules.

For functionality integrating chutney and shadow functionality see `chutney.shadow`.
"""

from __future__ import annotations

import dataclasses
import logging
import networkx as nx
from typing import Final, Iterable, Tuple

logger = logging.getLogger(__name__)


class GmlGraph:
    """
    A wrapped networkx graph that exposes exported gml node IDs.

    The gml graph format requires integer IDs for each node. These integer IDs
    are also used in the shadow configuration to assign a host to a network
    node.

    Unfortunately there's no way to assign or predict the gml node IDs directly
    from the original networkx Graph object.

    This wrapper solves that problem by exporting a networkx graph as gml, then
    reparsing it so that the original networkx node labels can be looked up to
    find the exported gml node IDs.

    [gml in networkx]: <https://networkx.org/documentation/stable/reference/readwrite/gml.html>
    [gml]:
    <https://web.archive.org/web/20190207140002/http://www.fim.uni-passau.de/index.php?id=17297&L=1>
    """

    def __init__(self, g: nx.Graph[str]) -> None:
        # Store the original graph.
        self._g: Final = g
        # Generate and store the gml that we'll ultimately give to shadow
        self._gml: Final = "\n".join(nx.generate_gml(self._g))
        # Parse the gml, using the 'id' field as the new node label. (Otherwise
        # it's erased entirely).
        parsed_graph = nx.parse_gml(self._gml, label="id")
        self._labels_to_ids: Final[dict[str, int]] = {
            n["label"]: id for (id, n) in parsed_graph.nodes(data=True)
        }

    def id_for_label(self, label: str) -> int:
        """Return the gml node ID in the exported gml for the given networkx node label.

        Raises KeyError if not found.
        """
        return self._labels_to_ids[label]

    def gml(self) -> str:
        """Return the gml-formatted graph"""
        return self._gml


@dataclasses.dataclass(frozen=True)
class ShadowNetworkNode:
    """Represents a node in a shadow network.

    See <https://shadow.github.io/docs/guide/network_graph_spec.html>"""

    label: str
    host_bandwidth_up: str
    host_bandwidth_down: str
    # mandatory self-edge. Not technically part of the node itself in shadow's config,
    # but every node is required to have one.
    self_edge_properties: ShadowNetworkEdgeProperties

    def add_to_graph(self, graph: nx.Graph[str]) -> None:
        """Add this node (and its mandatory self-edge) to `graph`."""
        graph.add_node(
            self.label,
            host_bandwidth_up=self.host_bandwidth_up,
            host_bandwidth_down=self.host_bandwidth_down,
        )
        self_edge = ShadowNetworkEdge(
            src_label=self.label,
            dst_label=self.label,
            properties=self.self_edge_properties,
        )
        self_edge.add_to_graph(graph)


@dataclasses.dataclass(frozen=True)
class ShadowNetworkEdgeProperties:
    """Properties of an edge in a shadow network. See `ShadowNetworkEdge`"""

    latency: str
    packet_loss: float


@dataclasses.dataclass(frozen=True)
class ShadowNetworkEdge:
    """Represents an edge in a shadow network.

    See <https://shadow.github.io/docs/guide/network_graph_spec.html>"""

    src_label: str
    dst_label: str
    properties: ShadowNetworkEdgeProperties

    def add_to_graph(self, graph: nx.Graph[str]) -> None:
        """Add this edge to `graph`.

        Raises TypeError if referenced nodes don't already exist in the graph.
        """
        if self.src_label not in graph.nodes:
            raise TypeError(f"src node '{self.src_label}' doesn't exist")
        if self.dst_label not in graph.nodes:
            raise TypeError(f"dst node '{self.dst_label}' doesn't exist")
        graph.add_edge(
            self.src_label,
            self.dst_label,
            latency=self.properties.latency,
            packet_loss=self.properties.packet_loss,
        )


class ShadowNetworkGraph:
    """
    A shadow network graph.
    """

    def __init__(
        self,
        *,
        # The network node that hosts will be assigned to unless otherwise specified.
        default_network_node: ShadowNetworkNode,
        # Additional network nodes
        addtl_network_nodes: Iterable[Tuple[ShadowNetworkNode, Iterable[str]]],
        edges: Iterable[ShadowNetworkEdge],
    ) -> None:
        """
        Raises TypeError if a hostname is assigned to multiple network nodes.
        """
        self._default_network_node: Final = default_network_node
        self._hostname_to_label: Final[dict[str, str]] = {}
        graph: nx.Graph[str] = nx.Graph()
        default_network_node.add_to_graph(graph)
        for node, hostnames in addtl_network_nodes:
            node.add_to_graph(graph)
            for hostname in hostnames:
                if (cur_label := self._hostname_to_label.get(hostname)) is not None:
                    raise TypeError(
                        f"hostname '{hostname}' assigned to multiple network labels:"
                        f" '{cur_label}', '{node.label}"
                    )
                self._hostname_to_label[hostname] = node.label
        for edge in edges:
            edge.add_to_graph(graph)
        # shadow requires that the graph is fully connected. preemptively check here.
        if not nx.is_connected(graph):
            subgraphs = [c for c in nx.connected_components(graph)]
            raise TypeError(f"graph is not fully connected. subgraphs: {subgraphs}")
        self._g: Final = GmlGraph(graph)

    def gml(self) -> str:
        """Return the gml-formatted graph, suitable for shadow config item
        [network.graph.inline](https://shadow.github.io/docs/guide/shadow_config_spec.html#networkgraphfileinline)
        """
        return self._g.gml()

    def default_node_id(self) -> int:
        """Return the id of the "default" network node"""
        default_label = self._default_network_node.label
        return self._g.id_for_label(default_label)

    def network_node_id_for_hostname(self, hostname: str) -> int:
        """Return the network node id for the given hostname, suitable for shadow config item
        [hosts.<hostname>.network_node_id](https://shadow.github.io/docs/guide/shadow_config_spec.html#hostshostnamenetwork_node_id)

        Raises `KeyError` if not found.
        """
        label = self._hostname_to_label.get(hostname, self._default_network_node.label)
        try:
            id = self._g.id_for_label(label)
        except KeyError as e:
            raise KeyError(
                f"label '{label}' (for hostname '{hostname}') not found"
            ) from e
        return id
