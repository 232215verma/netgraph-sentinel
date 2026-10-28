import ForceGraph2D from "react-force-graph-2d";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { THREAT_INFO } from "../threatInfo";
// Phase 1: node attack states (normal / suspicious / compromised / quarantined)
import { NODE_STATE_META, useNodeStates, type NodeState } from "../phase1";
// SHAPES: a fixed layout per threat type (star, funnel, comb, ring, pipeline, diamond)
import { layoutShape } from "../shapeLayout";

export interface GraphNode {
  id: string;
  flagged: boolean;
  types: string[];
  primaryType: string;
  /** The middle of the shape (scanner of a star, target of a hub). Drawn bigger and always labelled. */
  center?: boolean;
  // SHAPES: drawing hints sent by the backend
  /** An important endpoint (e.g. the two real hosts of a ring): drawn bigger and always labelled. */
  key?: boolean;
  /** A spoke or pulse node (port, check-in, query ...): drawn small. */
  minor?: boolean;
  /** Text to show instead of the id. */
  label?: string;
}

export interface GraphLink {
  source: string;
  target: string;
  type: string;
}

interface Props {
  nodes: GraphNode[];
  links: GraphLink[];
  children?: ReactNode;
  /** Phase 1 (optional): override node states. By default they are polled from the backend. */
  nodeStates?: Record<string, NodeState>;
  /** SHAPES: the threat type on screen; decides which fixed layout is used. */
  shapeType?: string | null;
}

// Small graphs: label every node. Big graphs: label only the centre, and the rest once zoomed in.
const LABEL_ALL_MAX_NODES = 8;
const LABEL_ZOOM = 2.2;

export default function LiveGraph({ nodes, links, children, nodeStates, shapeType }: Props) {
  const wrapRef = useRef<HTMLDivElement>(null);
  const fgRef = useRef<any>(null);
  const cacheRef = useRef<Map<string, any>>(new Map());
  const [size, setSize] = useState({ w: 0, h: 0 });

  // Phase 1: keep the latest states in a ref so drawNode (canvas) always reads fresh values.
  const polledStates = useNodeStates();
  const statesRef = useRef<Record<string, NodeState>>({});
  statesRef.current = nodeStates ?? polledStates;

  // Size the canvas to its container (not the window) so nothing is cut off.
  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const update = () => setSize({ w: el.clientWidth, h: el.clientHeight });
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Reuse node objects between updates so positions stay stable as alerts arrive.
  const graphData = useMemo(() => {
    const cache = cacheRef.current;
    const liveIds = new Set(nodes.map((n) => n.id));
    for (const id of Array.from(cache.keys())) {
      if (!liveIds.has(id)) cache.delete(id);
    }
    const outNodes = nodes.map((n) => {
      const existing = cache.get(n.id);
      if (existing) {
        Object.assign(existing, n);
        return existing;
      }
      const fresh = { ...n };
      cache.set(n.id, fresh);
      return fresh;
    });
    const outLinks = links.map((l) => ({ source: l.source, target: l.target, type: l.type }));

    // SHAPES: pin every node to its place in this threat's shape
    layoutShape(shapeType, outNodes, outLinks);

    return { nodes: outNodes, links: outLinks };
  }, [nodes, links, shapeType]);

  const fit = useCallback(() => {
    fgRef.current?.zoomToFit(400, 70);
  }, []);

  // A new shape replaced the old one: re-frame the view once it settles.
  useEffect(() => {
    if (nodes.length === 0) return;
    const t = window.setTimeout(fit, 700);
    return () => clearTimeout(t);
  }, [nodes.length, shapeType, fit]);

  const labelAll = nodes.length <= LABEL_ALL_MAX_NODES;

  const drawNode = useCallback(
    (node: any, ctx: CanvasRenderingContext2D, scale: number) => {
      // Phase 1: quarantined nodes fade out
      const phase1State: NodeState | undefined = statesRef.current[node.id];
      if (phase1State === "quarantined") ctx.globalAlpha = 0.3;

      const color = THREAT_INFO[node.primaryType]?.color || "#e8a33c";
      const isCenter = !!node.center;
      const isKey = isCenter || !!node.key; // SHAPES
      const r = (isCenter ? 9 : node.key ? 6.5 : node.minor ? 2.8 : 4) / scale;

      ctx.beginPath();
      ctx.arc(node.x, node.y, r * 2.1, 0, 2 * Math.PI);
      ctx.fillStyle = `${color}${isKey ? "33" : "22"}`;
      ctx.fill();

      ctx.beginPath();
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = "#0e131e";
      ctx.lineWidth = 1.2 / scale;
      ctx.stroke();

      if (isKey || labelAll || scale > LABEL_ZOOM) {
        ctx.font = `${(isKey ? 12 : 10.5) / scale}px 'JetBrains Mono', monospace`;
        ctx.fillStyle = isKey ? "#e6ebf5" : "#98a4b9";
        ctx.textAlign = "left";
        ctx.textBaseline = "middle";
        ctx.fillText(node.label ?? node.id, node.x + r + 4 / scale, node.y);
      }

      // Phase 1: state ring (yellow = suspicious, pulsing red = compromised, dashed grey = quarantined)
      if (phase1State && phase1State !== "normal") {
        const meta = NODE_STATE_META[phase1State];
        const pulse = phase1State === "compromised" ? 1 + 0.12 * Math.sin(Date.now() / 220) : 1;
        ctx.beginPath();
        ctx.arc(node.x, node.y, r * 2.7 * pulse, 0, 2 * Math.PI);
        ctx.strokeStyle = meta.color;
        ctx.lineWidth = 1.8 / scale;
        if (phase1State === "quarantined") ctx.setLineDash([3 / scale, 3 / scale]);
        ctx.stroke();
        ctx.setLineDash([]);

        if (phase1State === "quarantined") {
          ctx.font = `${9 / scale}px 'JetBrains Mono', monospace`;
          ctx.fillStyle = meta.color;
          ctx.textAlign = "center";
          ctx.textBaseline = "top";
          ctx.fillText("QUARANTINED", node.x, node.y + r * 3.2);
        }
      }
      ctx.globalAlpha = 1;
    },
    [labelAll]
  );

  return (
    <div ref={wrapRef} className="canvas-wrap">
      {size.w > 0 && size.h > 0 && (
        <ForceGraph2D
          ref={fgRef}
          width={size.w}
          height={size.h}
          graphData={graphData as any}
          backgroundColor="rgba(0,0,0,0)"
          nodeLabel={(node: any) => {
            const names = (node.types || []).map((t: string) => THREAT_INFO[t]?.label || t);
            const st: NodeState | undefined = statesRef.current[node.id];
            const stText = st && st !== "normal" ? ` [${NODE_STATE_META[st].label}]` : "";
            return `${node.label ?? node.id} — ${names.join(", ")}${stText}`;
          }}
          nodeCanvasObject={drawNode}
          nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
            ctx.fillStyle = color;
            ctx.beginPath();
            ctx.arc(node.x, node.y, node.center ? 12 : 8, 0, 2 * Math.PI);
            ctx.fill();
          }}
          linkColor={(link: any) => `${THREAT_INFO[link.type]?.color || "#64718a"}aa`}
          linkWidth={1.4}
          linkDirectionalArrowLength={4}
          linkDirectionalArrowRelPos={1}
          linkDirectionalParticles={2}
          linkDirectionalParticleWidth={2}
          linkDirectionalParticleColor={(link: any) => THREAT_INFO[link.type]?.color || "#fff"}
          cooldownTicks={150}
          onEngineStop={fit}
        />
      )}
      <div className="graph-controls">
        <button className="mini-btn" onClick={fit}>
          Fit to view
        </button>
      </div>

      {/* Phase 1: node state legend */}
      <div
        style={{
          position: "absolute",
          left: 10,
          bottom: 10,
          display: "flex",
          gap: 10,
          flexWrap: "wrap",
          fontSize: 11,
          color: "#98a4b9",
          pointerEvents: "none",
        }}
      >
        {(Object.keys(NODE_STATE_META) as NodeState[]).map((s) => (
          <span key={s} style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
            <span
              style={{
                width: 9,
                height: 9,
                borderRadius: "50%",
                border: `2px ${s === "quarantined" ? "dashed" : "solid"} ${NODE_STATE_META[s].color}`,
              }}
            />
            {NODE_STATE_META[s].label}
          </span>
        ))}
      </div>

      {children}
    </div>
  );
}