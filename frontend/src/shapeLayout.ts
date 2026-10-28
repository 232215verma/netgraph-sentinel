import type { GraphNode } from "./components/LiveGraph";

/**
 * Fixed layouts, one per threat type, so every threat always draws the same
 * recognisable shape instead of whatever the force simulation settles on.
 *
 *   PortScan      star      scanner in the middle, hosts on an inner ring, ports on an outer ring
 *   DDoS          funnel    many sources on arcs on the left, converging on the target
 *   DGA           comb      one bot on top, one-off destinations in rows below
 *   C2Beaconing   ring      a closed loop: check-ins out, replies back
 *   DNSTunneling  pipeline  a straight line: source, queries, resolver
 *   Exfiltration  diamond   source on the left, burst nodes in a column, destination on the right
 *
 * Nodes are pinned with fx / fy (react-force-graph keeps pinned nodes in place).
 */

type N = GraphNode & { fx?: number; fy?: number; x?: number; y?: number };
type L = { source: unknown; target: unknown };

export type ShapeKind = "star" | "funnel" | "comb" | "ring" | "pipeline" | "diamond";

export const SHAPE_KIND: Record<string, ShapeKind> = {
  PortScan: "star",
  DDoS: "funnel",
  DGA: "comb",
  C2Beaconing: "ring",
  DNSTunneling: "pipeline",
  Exfiltration: "diamond",
};

const TAU = Math.PI * 2;
const isPortNode = (id: string) => /:\d+$/.test(id);
const idOf = (v: unknown): string =>
  typeof v === "object" && v !== null ? String((v as { id: unknown }).id) : String(v);

function put(n: N, x: number, y: number) {
  n.fx = x;
  n.fy = y;
  n.x = x;
  n.y = y;
}

function unpin(n: N) {
  delete n.fx;
  delete n.fy;
}

function degrees(nodes: N[], links: L[]) {
  const d = new Map<string, { in: number; out: number }>();
  for (const n of nodes) d.set(n.id, { in: 0, out: 0 });
  for (const l of links) {
    const s = d.get(idOf(l.source));
    const t = d.get(idOf(l.target));
    if (s) s.out += 1;
    if (t) t.in += 1;
  }
  return d;
}

function best(nodes: N[], score: (n: N) => number): N {
  return nodes.reduce((a, b) => (score(b) > score(a) ? b : a));
}

function ringPlace(list: N[], radius: number, start: number) {
  list.forEach((n, i) => {
    const a = start + (i * TAU) / list.length;
    put(n, Math.cos(a) * radius, Math.sin(a) * radius);
  });
}

/** Follow the links from `start`; `closed` is true when the walk returns to `start`. */
function walk(nodes: N[], links: L[], start: N) {
  const next = new Map<string, string>();
  for (const l of links) {
    const s = idOf(l.source);
    if (!next.has(s)) next.set(s, idOf(l.target));
  }
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const order: N[] = [];
  const seen = new Set<string>();
  let cur: string | undefined = start.id;
  while (cur && !seen.has(cur) && byId.has(cur)) {
    seen.add(cur);
    order.push(byId.get(cur)!);
    cur = next.get(cur);
  }
  return { order, closed: cur === start.id };
}

function circle(nodes: N[]) {
  ringPlace(nodes, Math.max(130, nodes.length * 14), -Math.PI / 2);
}

// ---------------------------------------------------------------------------
function star(nodes: N[], links: L[]) {
  const deg = degrees(nodes, links);
  const center = best(nodes, (n) => deg.get(n.id)!.in + deg.get(n.id)!.out);
  const rest = nodes.filter((n) => n !== center);
  const ports = rest.filter((n) => isPortNode(n.id));
  const hosts = rest.filter((n) => !isPortNode(n.id));
  put(center, 0, 0);

  if (ports.length && hosts.length) {
    const inner = Math.max(120, hosts.length * 10);
    const outer = Math.max(inner + 110, ports.length * 9);
    ringPlace(hosts, inner, -Math.PI / 2);
    ringPlace(ports, outer, -Math.PI / 2 + Math.PI / ports.length);
  } else {
    const list = ports.length ? ports : hosts;
    if (list.length) ringPlace(list, Math.max(130, list.length * 9), -Math.PI / 2);
  }
}

function funnel(nodes: N[], links: L[]) {
  const deg = degrees(nodes, links);
  const target = best(nodes, (n) => deg.get(n.id)!.in);
  put(target, 0, 0);
  const sources = nodes.filter((n) => n !== target);

  const perArc = 14;
  const arcs = Math.max(1, Math.ceil(sources.length / perArc));
  const spread = 1.15; // radians on each side of "straight left"

  sources.forEach((n, i) => {
    const arc = i % arcs;
    const idx = Math.floor(i / arcs);
    const inArc = Math.ceil((sources.length - arc) / arcs);
    const t = inArc > 1 ? idx / (inArc - 1) : 0.5;
    const angle = Math.PI - spread + 2 * spread * t;
    const r = 190 + arc * 95;
    put(n, Math.cos(angle) * r, Math.sin(angle) * r);
  });
}

function comb(nodes: N[], links: L[]) {
  const deg = degrees(nodes, links);
  const root = best(nodes, (n) => deg.get(n.id)!.out);
  put(root, 0, 0);
  const leaves = nodes.filter((n) => n !== root);

  const perRow = 10;
  leaves.forEach((n, i) => {
    const row = Math.floor(i / perRow);
    const inRow = Math.min(perRow, leaves.length - row * perRow);
    const col = i % perRow;
    put(n, (col - (inRow - 1) / 2) * 50, 170 + row * 75 + (col % 2) * 14);
  });
}

function ring(nodes: N[], links: L[]) {
  const { order, closed } = walk(nodes, links, nodes[0]);
  if (!closed || order.length !== nodes.length) return circle(nodes);

  const n = order.length;
  const radius = Math.max(150, n * 22);
  order.forEach((node, i) => {
    const a = Math.PI + (i * TAU) / n; // first node on the far left, then over the top
    put(node, Math.cos(a) * radius * 1.3, Math.sin(a) * radius * 0.85);
  });
}

function pipeline(nodes: N[], links: L[]) {
  const deg = degrees(nodes, links);
  const start = nodes.find((n) => deg.get(n.id)!.in === 0) ?? nodes[0];
  const { order } = walk(nodes, links, start);
  if (order.length !== nodes.length) return circle(nodes);

  const gap = 130;
  order.forEach((node, i) => put(node, (i - (order.length - 1) / 2) * gap, 0));
}

function diamond(nodes: N[], links: L[]) {
  const deg = degrees(nodes, links);
  const src = nodes.find((n) => deg.get(n.id)!.in === 0 && deg.get(n.id)!.out > 0);
  const dst = nodes.find((n) => deg.get(n.id)!.out === 0 && deg.get(n.id)!.in > 0);
  if (!src || !dst || src === dst) return circle(nodes);

  const mids = nodes.filter((n) => n !== src && n !== dst);
  const half = 270;
  put(src, -half, 0);
  put(dst, half, 0);
  mids.forEach((n, i) => put(n, 0, (i - (mids.length - 1) / 2) * 60));
}

// ---------------------------------------------------------------------------
/** Pin every node to its place in the shape of `type`. Unknown / empty: unpin everything. */
export function layoutShape(type: string | null | undefined, nodes: N[], links: L[]): void {
  const kind = type ? SHAPE_KIND[type] : undefined;
  if (!kind || nodes.length === 0) {
    nodes.forEach(unpin);
    return;
  }
  if (nodes.length === 1) {
    put(nodes[0], 0, 0);
    return;
  }
  switch (kind) {
    case "star":
      return star(nodes, links);
    case "funnel":
      return funnel(nodes, links);
    case "comb":
      return comb(nodes, links);
    case "ring":
      return ring(nodes, links);
    case "pipeline":
      return pipeline(nodes, links);
    case "diamond":
      return diamond(nodes, links);
  }
}