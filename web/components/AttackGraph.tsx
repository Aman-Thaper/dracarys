"use client";
import { Graph } from "@/lib/api";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

// Fixed internal coordinate space; the SVG scales it responsively to any width.
const VBW = 1280, VBH = 640;
const NODE_W = 178, NODE_H = 58, COL_W = 236, ROW_H = 104, PAD = 46;

const TYPE_STYLE: Record<string, { fill: string; stroke: string; text: string }> = {
  asset:         { fill: "#141019", stroke: "#ff6b2b", text: "#ffb37a" },
  endpoint:      { fill: "#0d0f16", stroke: "#3a4152", text: "#c7ccd8" },
  vulnerability: { fill: "#1a0f0d", stroke: "#ff3b30", text: "#ff8a80" },
  identity:      { fill: "#0b1420", stroke: "#4aa8ff", text: "#9ecbff" },
  resource:      { fill: "#241503", stroke: "#ffd166", text: "#ffd166" },
  privilege:     { fill: "#150f1c", stroke: "#b98cff", text: "#d3b8ff" },
};
const EDGE_STYLE: Record<string, string> = {
  reaches: "#ffd166", enables: "#ff6b2b", authenticates_as: "#4aa8ff",
  exposes: "#00ff9c", discovers: "#3a4152", bypasses: "#ff3b30",
};

export default function AttackGraph({ graph }: { graph: Graph | null }) {
  const layout = useMemo(() => computeLayout(graph), [graph]);
  const svgRef = useRef<SVGSVGElement>(null);
  const [view, setView] = useState({ k: 1, tx: 0, ty: 0 });
  const [hover, setHover] = useState<string | null>(null);
  const [pin, setPin] = useState<string | null>(null);
  const drag = useRef<{ x: number; y: number; moved: boolean } | null>(null);

  const fit = useCallback(() => {
    const { gw, gh } = layout;
    const k = Math.min((VBW - PAD * 2) / Math.max(gw, 1), (VBH - PAD * 2) / Math.max(gh, 1), 1.5);
    setView({ k, tx: (VBW - gw * k) / 2, ty: (VBH - gh * k) / 2 });
  }, [layout]);

  useEffect(() => { fit(); }, [fit]);

  // Map a client point into viewBox coordinates (accounts for meet letterboxing).
  const toVB = (clientX: number, clientY: number) => {
    const rect = svgRef.current!.getBoundingClientRect();
    const s = Math.min(rect.width / VBW, rect.height / VBH);
    const offX = (rect.width - VBW * s) / 2, offY = (rect.height - VBH * s) / 2;
    return { x: (clientX - rect.left - offX) / s, y: (clientY - rect.top - offY) / s, s };
  };

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const { x, y } = toVB(e.clientX, e.clientY);
    setView((v) => {
      const k = Math.min(4, Math.max(0.3, v.k * (e.deltaY < 0 ? 1.15 : 1 / 1.15)));
      return { k, tx: x - (x - v.tx) * (k / v.k), ty: y - (y - v.ty) * (k / v.k) };
    });
  };
  const onDown = (e: React.PointerEvent) => {
    drag.current = { x: e.clientX, y: e.clientY, moved: false };
    (e.target as Element).setPointerCapture?.(e.pointerId);
  };
  const onMove = (e: React.PointerEvent) => {
    if (!drag.current) return;
    const { s } = toVB(e.clientX, e.clientY);
    const dx = (e.clientX - drag.current.x) / s, dy = (e.clientY - drag.current.y) / s;
    if (Math.abs(dx) + Math.abs(dy) > 1) drag.current.moved = true;
    drag.current.x = e.clientX; drag.current.y = e.clientY;
    setView((v) => ({ ...v, tx: v.tx + dx, ty: v.ty + dy }));
  };
  const onUp = () => { drag.current = null; };
  const zoom = (f: number) => setView((v) => {
    const k = Math.min(4, Math.max(0.3, v.k * f));
    return { k, tx: VBW / 2 - (VBW / 2 - v.tx) * (k / v.k), ty: VBH / 2 - (VBH / 2 - v.ty) * (k / v.k) };
  });

  const focus = hover ?? pin;
  const focusSet = useMemo(() => {
    if (!focus || !graph) return null;
    const s = new Set<string>([focus]);
    graph.edges.forEach((e) => {
      if (e.source === focus) s.add(e.target);
      if (e.target === focus) s.add(e.source);
    });
    return s;
  }, [focus, graph]);

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center font-mono text-sm text-slate-600">
        <span className="cursor">awaiting graph — unleash a campaign</span>
      </div>
    );
  }
  const { pos } = layout;

  return (
    <div className="relative">
      {/* controls */}
      <div className="absolute right-2 top-2 z-10 flex gap-1">
        {[["+", () => zoom(1.25)], ["−", () => zoom(0.8)], ["⤢", fit]].map(([l, fn], i) => (
          <button key={i} onClick={fn as any}
            className="h-7 w-7 rounded border border-ink-600 bg-ink-900/80 font-mono text-sm text-slate-300 hover:border-acid/60 hover:text-acid">
            {l as string}
          </button>
        ))}
      </div>
      <div className="pointer-events-none absolute left-2 top-2 z-10 hud">drag · scroll to zoom · hover a node</div>

      <svg
        ref={svgRef} viewBox={`0 0 ${VBW} ${VBH}`} preserveAspectRatio="xMidYMid meet"
        className="h-[clamp(360px,56vh,660px)] w-full touch-none select-none rounded-md bg-ink-900/40"
        style={{ cursor: drag.current ? "grabbing" : "grab" }}
        onWheel={onWheel} onPointerDown={onDown} onPointerMove={onMove}
        onPointerUp={onUp} onPointerLeave={onUp}
      >
        <defs>
          <marker id="arrow" markerWidth="9" markerHeight="9" refX="7.5" refY="4.5" orient="auto">
            <path d="M0,0 L9,4.5 L0,9 Z" fill="#6b7180" />
          </marker>
          <pattern id="dots" width="26" height="26" patternUnits="userSpaceOnUse">
            <circle cx="1" cy="1" r="1" fill="rgba(0,255,156,0.06)" />
          </pattern>
        </defs>
        <rect x="0" y="0" width={VBW} height={VBH} fill="url(#dots)" />

        <g transform={`translate(${view.tx} ${view.ty}) scale(${view.k})`}>
          {graph.edges.map((e, i) => {
            const a = pos[e.source], b = pos[e.target];
            if (!a || !b) return null;
            const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2;
            const mx = (x1 + x2) / 2;
            const color = EDGE_STYLE[e.type] || "#3a4152";
            const active = focus ? (e.source === focus || e.target === focus) : e.type === "reaches";
            const dim = focusSet ? !(e.source === focus || e.target === focus) : false;
            return (
              <g key={i} opacity={dim ? 0.12 : 1} style={{ transition: "opacity .15s" }}>
                <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                  fill="none" stroke={color} strokeWidth={active ? 2.6 : 1.5}
                  markerEnd="url(#arrow)"
                  strokeDasharray={active ? "6 6" : undefined}
                  className={active ? "animate-flow" : ""} />
                <text x={mx} y={(y1 + y2) / 2 - 5} fill={color} fontSize="9"
                  textAnchor="middle" className="font-mono uppercase" style={{ letterSpacing: "0.08em" }}
                  opacity={0.85}>{e.type.replace(/_/g, " ")}</text>
              </g>
            );
          })}
          {graph.nodes.map((n) => {
            const p = pos[n.ref]; if (!p) return null;
            const st = TYPE_STYLE[n.type] || TYPE_STYLE.endpoint;
            const crown = n.type === "resource";
            const dim = focusSet ? !focusSet.has(n.ref) : false;
            const isFocus = focus === n.ref;
            return (
              <g key={n.ref} transform={`translate(${p.x} ${p.y})`}
                opacity={dim ? 0.18 : 1} style={{ transition: "opacity .15s", cursor: "pointer" }}
                onMouseEnter={() => setHover(n.ref)} onMouseLeave={() => setHover(null)}
                onClick={() => !drag.current?.moved && setPin(pin === n.ref ? null : n.ref)}>
                <rect width={NODE_W} height={NODE_H} rx="9" fill={st.fill}
                  stroke={st.stroke} strokeWidth={isFocus || crown ? 2.5 : 1.5}
                  style={{ filter: crown || isFocus ? `drop-shadow(0 0 8px ${st.stroke}88)` : "none" }}
                  className={crown ? "animate-pulseline" : ""} />
                <text x="12" y="19" fill={st.stroke} fontSize="8.5"
                  className="font-mono uppercase" style={{ letterSpacing: "0.16em" }}>
                  {n.type}{crown ? "  ◆" : ""}{pin === n.ref ? "  ●" : ""}
                </text>
                <text x="12" y="37" fill={st.text} fontSize="11.5" fontWeight="600">
                  {truncate(n.label, 24)}
                </text>
                {n.data?.severity && (
                  <text x="12" y="50" fill={st.text} fontSize="8" opacity="0.8"
                    className="font-mono uppercase">{n.data.severity}</text>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {/* legend */}
      <div className="mt-2 flex flex-wrap gap-3 px-1">
        {Object.entries({ enables: "enables", reaches: "reaches", authenticates_as: "auth", exposes: "exposes" }).map(([k, l]) => (
          <span key={k} className="flex items-center gap-1.5 hud">
            <span className="inline-block h-0.5 w-4" style={{ background: EDGE_STYLE[k] }} />{l}
          </span>
        ))}
        <span className="flex items-center gap-1.5 hud"><span className="text-gold">◆</span>crown-jewel canary</span>
      </div>
    </div>
  );
}

function truncate(s: string, n: number) { return s.length > n ? s.slice(0, n - 1) + "…" : s; }

function computeLayout(graph: Graph | null) {
  if (!graph) return { pos: {} as Record<string, { x: number; y: number }>, gw: 400, gh: 200 };
  const nodes = graph.nodes, edges = graph.edges;
  const adj: Record<string, string[]> = {};
  const indeg: Record<string, number> = {};
  nodes.forEach((n) => { indeg[n.ref] = 0; });
  edges.forEach((e) => { (adj[e.source] ||= []).push(e.target); if (indeg[e.target] != null) indeg[e.target]++; });

  const rank: Record<string, number> = {};
  nodes.forEach((n) => { rank[n.ref] = 0; });
  const q = nodes.filter((n) => indeg[n.ref] === 0).map((n) => n.ref);
  const deg = { ...indeg };
  while (q.length) {
    const u = q.shift()!;
    (adj[u] || []).forEach((v) => { rank[v] = Math.max(rank[v], rank[u] + 1); if (--deg[v] === 0) q.push(v); });
  }
  const cols: Record<number, string[]> = {};
  nodes.forEach((n) => { (cols[rank[n.ref]] ||= []).push(n.ref); });
  const pos: Record<string, { x: number; y: number }> = {};
  let maxRow = 0, maxCol = 0;
  Object.entries(cols).forEach(([col, refs]) => {
    refs.forEach((ref, i) => { pos[ref] = { x: PAD + Number(col) * COL_W, y: PAD + i * ROW_H }; });
    maxRow = Math.max(maxRow, refs.length); maxCol = Math.max(maxCol, Number(col));
  });
  return { pos, gw: PAD * 2 + (maxCol + 1) * COL_W - (COL_W - NODE_W), gh: PAD * 2 + maxRow * ROW_H - (ROW_H - NODE_H) };
}
