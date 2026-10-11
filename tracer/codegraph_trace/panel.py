"""The one-page visual panel: ``codegraph-trace panel``.

A small local HTTP server (Flask) that reads ``trace.db`` and serves one page whose
landing is a dual shell with two equal primary tabs — **Decision tree** (default) and
**Code structure** — plus drill-downs for a file, a symbol, a single step, and one
decision. Deep links: ``?view=structure`` (legacy ``?structure``), ``?file=``,
``?node=``, ``?step=``, ``?branch=``. The VS Code extension starts this as a child
process on a free port and points a Webview at it.

All SQL stays here in Python - the extension never reads the database itself. The server is
read-only and binds to localhost; rollback and per-symbol restore are forwarded to the
extension via postMessage (or printed as CLI commands in a plain browser).
"""

from __future__ import annotations

import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Optional

from .config import TraceConfig
from .ignore import is_trace_path
from .query import TraceQuery

_CODE_SUFFIXES = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift", ".scala", ".sql", ".sh",
)

_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>TRACE</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, "Segoe UI", sans-serif; margin: 0; padding: 1rem 1.5rem;
         background: #1e1e1e; color: #d4d4d4; }
  h1 { font-size: 1.1rem; margin: 0 0 .25rem; letter-spacing: .18em; }
  .topbar { display: flex; align-items: center; justify-content: space-between;
            gap: 1rem; }
  .chat-toggle { background: #1e2a28; color: #4ec9b0; border: 1px solid #4ec9b0;
                 border-radius: 999px; padding: .35rem .9rem; font-size: .85rem;
                 cursor: pointer; flex: none; }
  .chat-toggle:hover { background: #24403a; }
  /* Chat drawer: retrieval-backed Q&A over recorded reasoning and code. */
  .chat-drawer { position: fixed; top: 0; right: 0; width: min(430px, 92vw);
                 height: 100vh; background: #1b1b1c; border-left: 1px solid #3c3c3c;
                 display: none; flex-direction: column; z-index: 50;
                 box-shadow: -8px 0 24px rgba(0,0,0,.45); }
  .chat-drawer.open { display: flex; }
  .chat-head { display: flex; align-items: center; justify-content: space-between;
               padding: .7rem .9rem; border-bottom: 1px solid #333; }
  .chat-head .t { font-weight: 600; color: #4ec9b0; }
  .chat-head button { background: none; border: none; color: #808080;
                      font-size: 1.1rem; cursor: pointer; }
  .chat-log { flex: 1; overflow-y: auto; padding: .8rem; display: flex;
              flex-direction: column; gap: .6rem; }
  .chat-msg { border-radius: 10px; padding: .5rem .7rem; font-size: .85rem;
              max-width: 92%; white-space: pre-wrap; }
  .chat-msg.user { align-self: flex-end; background: #24403a; color: #d8f5ec; }
  .chat-msg.bot { align-self: flex-start; background: #232323;
                  border: 1px solid #333; }
  .chat-msg.bot .hit { margin: .45rem 0 0; padding-top: .45rem;
                       border-top: 1px dashed #3c3c3c; }
  .chat-msg.bot .hit a { color: #9cdcfe; text-decoration: none; }
  .chat-msg.bot .hit a:hover { text-decoration: underline; }
  .chat-msg.bot .snippet { color: #c9c9c9; margin-top: .2rem; }
  .chat-msg.bot .syms a { color: #4ec9b0; text-decoration: none; display: block;
                          font-family: monospace; font-size: .8rem; }
  .chat-input { display: flex; gap: .5rem; padding: .7rem .8rem;
                border-top: 1px solid #333; }
  .chat-input input { flex: 1; }
  .chat-input button { background: #252526; color: #4ec9b0;
                       border: 1px solid #4ec9b0; border-radius: 6px;
                       padding: .35rem .8rem; cursor: pointer; }
  h2 { font-size: .95rem; margin: 1.2rem 0 .4rem; color: #9cdcfe; }
  input { width: 100%; box-sizing: border-box; padding: .45rem .6rem; border-radius: 6px;
          border: 1px solid #3c3c3c; background: #252526; color: inherit; font-size: .9rem; }
  .muted { color: #808080; font-size: .8rem; }
  .step { border: 1px solid #333; border-radius: 8px; padding: .6rem .8rem; margin: .5rem 0;
          background: #232323; }
  .step .head { display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }
  .seq { font-weight: 700; color: #4ec9b0; }
  .sha { font-family: monospace; color: #808080; font-size: .8rem; }
  .tag { display: inline-block; font-size: .7rem; padding: .1rem .45rem; border-radius: 999px;
         border: 1px solid #555; margin-left: .3rem; }
  .tag.human { border-color: #dcdcaa; color: #dcdcaa; }
  .tag.locked { border-color: #ce9178; color: #ce9178; }
  .tag.decision { border-color: #c586c0; color: #c586c0; }
  .tag.abandoned { border-color: #f14c4c; color: #f14c4c; }
  .tag.error_retry { border-color: #f14c4c; color: #f14c4c; }
  .tag.revised { border-color: #dcdcaa; color: #dcdcaa; }
  .tag.survived { border-color: #4ec9b0; color: #4ec9b0; }
  /* Change review: the exact entities an incoming change touched, in both graphs. */
  @keyframes reviewPulse {
    0%, 100% { filter: drop-shadow(0 0 3px #ffd166); }
    50% { filter: drop-shadow(0 0 10px #ffd166); }
  }
  .decision-svg .spine-node.review, .radial-svg .r-node.review {
    stroke: #ffd166; stroke-width: 2.5px;
    animation: reviewPulse 1.6s ease-in-out infinite; }
  /* Diff drawer: previous code vs updated code for one reviewable change. */
  .diff-drawer { position: fixed; top: 0; right: 0; width: min(720px, 96vw);
                 height: 100vh; background: #1b1b1c; border-left: 1px solid #ffd166;
                 display: none; flex-direction: column; z-index: 60;
                 box-shadow: -8px 0 24px rgba(0,0,0,.55); }
  .diff-drawer.open { display: flex; }
  .diff-head { display: flex; align-items: flex-start; justify-content: space-between;
               gap: .8rem; padding: .8rem .9rem; border-bottom: 1px solid #333; }
  .diff-head .msg { color: #ffd166; font-weight: 600; font-size: .95rem; }
  .diff-head button { background: none; border: none; color: #808080;
                      font-size: 1.1rem; cursor: pointer; }
  .diff-body { flex: 1; overflow: auto; padding: .6rem .9rem; }
  .diff-body pre { margin: 0; font-size: .8rem; line-height: 1.45;
                   font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .diff-body .dl { display: block; white-space: pre-wrap; }
  .diff-body .dl.add { color: #6ac47a; background: rgba(78,201,120,.10); }
  .diff-body .dl.del { color: #f18a8a; background: rgba(241,76,76,.10); }
  .diff-body .dl.hunk { color: #4ec9b0; }
  .diff-body .dl.meta { color: #808080; }
  .diff-verdict { display: flex; gap: .6rem; padding: .7rem .9rem;
                  border-top: 1px solid #333; }
  .diff-verdict button { background: #252526; border-radius: 6px;
                         padding: .35rem .9rem; cursor: pointer; font-size: .85rem; }
  .diff-verdict button.accept { color: #4ec9b0; border: 1px solid #4ec9b0; }
  .diff-verdict button.reject { color: #f14c4c; border: 1px solid #f14c4c; }
  .adot { color: #dcdcaa; font-size: .7rem; margin-right: .15rem; }
  pre.reason { white-space: pre-wrap; margin: .4rem 0 0; font-size: .85rem; color: #d4d4d4;
               font-family: inherit; }
  pre.code { background: #1a1a1a; border-radius: 6px; padding: .5rem; overflow-x: auto;
             font-size: .8rem; }
  .nodes a { color: #9cdcfe; text-decoration: none; display: block; padding: .1rem 0;
             font-family: monospace; font-size: .85rem; }
  .nodes a:hover { text-decoration: underline; }
  .markers { font-size: .85rem; color: #dcdcaa; }
  /* Timeline strip: the step spine as dots, left to right. */
  .timeline { display: flex; align-items: center; gap: 12px; padding: .9rem .4rem;
              overflow-x: auto; }
  .dot { width: 6px; height: 6px; border-radius: 50%; background: #555; cursor: pointer;
         flex: none; box-sizing: content-box; }
  .dot.touch { width: 10px; height: 10px; background: #4ec9b0; }
  .dot.decision { width: 12px; height: 12px; background: #c586c0;
                  box-shadow: 0 0 0 2px rgba(197,134,192,.35); }
  .dot.human { background: #dcdcaa; box-shadow: 0 0 0 2px rgba(220,220,170,.35); }
  .dot.selected { outline: 2px solid #9cdcfe; outline-offset: 2px; }
  /* Decision-tree color legend (compact swatch row instead of prose). */
  .tree-legend { display: flex; gap: .9rem; flex-wrap: wrap; margin: .4rem 0 .2rem;
                 color: #9a9a9a; font-size: .78rem; align-items: center; }
  .tree-legend .k { display: inline-flex; align-items: center; gap: .35rem; }
  .tree-legend .sw { width: 9px; height: 9px; border-radius: 50%; flex: none;
                     display: inline-block; }
  .tree-legend .ln { width: 18px; height: 0; border-top: 2px solid; flex: none;
                     display: inline-block; }
  .tree-legend .ln.dash { border-top-style: dashed; }
  button.rollback { background: #252526; color: #9cdcfe; border: 1px solid #3c3c3c;
                    border-radius: 6px; padding: .3rem .7rem; font-size: .8rem;
                    cursor: pointer; margin-top: .5rem; }
  button.rollback:hover { border-color: #9cdcfe; }
  .struct-detail { margin-top: .8rem; padding: .7rem .9rem; background: #1e1e1e;
                   border: 1px solid #333; border-radius: 8px; }
  .struct-detail:empty { display: none; }
  .struct-detail h3 { margin: 0 0 .25rem; font-size: .95rem; font-weight: 600; }
  .struct-actions { display: flex; flex-wrap: wrap; gap: .5rem; margin-top: .35rem; }
  .struct-actions button.rollback { margin-top: .25rem; }
  .struct-code { max-height: 28rem; overflow: auto; margin-top: .6rem; }
  .struct-code pre.code { margin: 0; }
  .struct-code .cline { display: block; }
  .struct-code .cline.hl { background: rgba(78, 201, 176, .18); }
  /* Decision view SVG (inside a horizontally scrollable wrapper). */
  .dscroll { overflow-x: auto; }
  .decision-svg { display: block; cursor: grab; }
  .decision-svg.panning { cursor: grabbing; }
  .decision-svg text { fill: #d4d4d4; font-size: 11px; }
  .decision-svg .spine-line { stroke: #4ec9b0; stroke-width: 2; }
  .decision-svg .spine-node { fill: #4ec9b0; cursor: pointer; }
  .decision-svg .spine-node.decision { fill: #c586c0; }
  .decision-svg .spine-node.context { fill: #555; }
  .decision-svg .spine-gap text { fill: #808080; font-size: 10px; }
  .decision-svg .branch-edge { fill: none; stroke-width: 1.5; stroke-dasharray: 5 4; }
  .decision-svg .branch-edge.abandoned, .decision-svg .branch-edge.error_retry
    { stroke: #f14c4c; }
  .decision-svg .branch-edge.revised { stroke: #dcdcaa; }
  .decision-svg .branch-node { cursor: pointer; }
  .decision-svg .branch-node rect { fill: #232323; stroke: #555; rx: 5; }
  .decision-svg .branch-node:hover rect { stroke: #9cdcfe; }
  .decision-svg .supersede-edge { fill: none; stroke: #808080; stroke-width: 1;
                                  stroke-dasharray: 2 3; }
  /* Development-lineage lanes: merged branches ride a blue lane above the spine;
     open (unmerged) branches are faint and locked until accepted. */
  .decision-svg .lane-line.merged { stroke: #9cdcfe; stroke-width: 2; }
  .decision-svg .lane-edge.merged { fill: none; stroke: #9cdcfe; stroke-width: 1.6; }
  .decision-svg .spine-node.lane { stroke: #9cdcfe; stroke-width: 1.5; }
  .decision-svg .lane-label { fill: #9cdcfe; font-size: 10px; }
  .decision-svg .lane-line.open { stroke: #808080; stroke-width: 1.5;
                                  stroke-dasharray: 4 4; opacity: .55; }
  .decision-svg .lane-edge.open { fill: none; stroke: #808080; stroke-width: 1.4;
                                  stroke-dasharray: 4 4; opacity: .55; }
  .decision-svg .spine-node.open { fill: #808080; opacity: .5; cursor: default; }
  .decision-svg .lane-label.open { fill: #9a9a9a; opacity: .9; }
  .decision-svg text.openstep { fill: #9a9a9a; opacity: .75; font-size: 10px; }
  .tag.lineage { border-color: #9cdcfe; color: #9cdcfe; }
  /* The zoomed decision: dead code next to the code that won. */
  .compare { display: grid; grid-template-columns: 1fr 1fr; gap: .8rem; margin: .5rem 0; }
  .compare .col { border: 1px solid #333; border-radius: 8px; padding: .6rem .8rem;
                  background: #232323; min-width: 0; }
  .compare .col.dead { border-color: #f14c4c; }
  .compare .col.win { border-color: #4ec9b0; }
  .compare .col h3 { font-size: .85rem; margin: 0 0 .3rem; }
  .compare .col.dead h3 { color: #f14c4c; }
  .compare .col.win h3 { color: #4ec9b0; }
  /* Zoom navigation. */
  .crumbs { font-size: .85rem; margin: .4rem 0 .5rem; }
  .crumbs a { color: #9cdcfe; text-decoration: none; }
  .crumbs a:hover { text-decoration: underline; }
  .crumbs .sep { color: #555; margin: 0 .35rem; }
  .filecard { cursor: pointer; }
  .filecard:hover { border-color: #9cdcfe; }
  a.zoomlink { color: #9cdcfe; font-size: .8rem; text-decoration: none; margin-left: .6rem; }
  a.zoomlink:hover { text-decoration: underline; }
  /* Filters. */
  .chips { display: flex; gap: .4rem; flex-wrap: wrap; margin: .6rem 0 .2rem;
           align-items: center; }
  .chips .label { color: #808080; font-size: .75rem; margin-left: .5rem; }
  .chip { font-size: .75rem; padding: .15rem .6rem; border-radius: 999px;
          border: 1px solid #3c3c3c; background: #252526; color: #d4d4d4; cursor: pointer; }
  .chip.active { border-color: #4ec9b0; color: #4ec9b0; }
  .chip.finding.active { border-color: #f14c4c; color: #f14c4c; }
  .dot.dim { opacity: .22; }
  .badge { display: inline-block; font-size: .7rem; padding: .05rem .4rem;
           border-radius: 999px; background: rgba(241,76,76,.15); border: 1px solid #f14c4c;
           color: #f14c4c; margin-left: .4rem; }
  /* Code structure view. */
  .struct-viewport { width: 100%; height: min(70vh, 720px); overflow: hidden;
    border: 1px solid #3c3c3c; border-radius: 8px; background: #1e1e1e; }
  /* Radial code-structure tree (phylogenetic style): repo at the glowing core,
     files on the inner ring, symbols as leaves, curved green containment links
     and faint blue cross-file relationship arcs. */
  .radial-svg { display: block; width: 100%; height: 100%; cursor: grab;
    touch-action: none; background:
      radial-gradient(circle at 50% 52%, #12161c 0%, #0c0e12 60%, #090a0d 100%); }
  .radial-svg.panning { cursor: grabbing; }
  .radial-svg .r-link { fill: none; stroke: #35c491; stroke-width: 1.3; opacity: .55; }
  .radial-svg .r-link.root { stroke-width: 1.7; opacity: .7; }
  .radial-svg .r-rel { fill: none; stroke: #7aa2ff; stroke-width: 1;
    opacity: .45; stroke-dasharray: 3 4; }
  .radial-svg .r-rel:hover { opacity: .9; stroke-width: 1.8; }
  .radial-svg .r-node { cursor: pointer; }
  .radial-svg .r-node.file { fill: #4ec9b0; stroke: #0c0e12; stroke-width: 1.2; }
  .radial-svg .r-node.recorded { fill: #4ec9b0; }
  .radial-svg .r-node.decision { fill: #c586c0; }
  .radial-svg .r-node.plain { fill: #6b7784; }
  .radial-svg .r-node.finding { fill: #f14c4c; }
  .radial-svg .r-node:hover { stroke: #ffffff; stroke-width: 1.4; }
  .radial-svg .r-core { fill: #ffffff; filter: url(#coreGlow); }
  .radial-svg .r-core-ring { fill: none; stroke: #9cffe0; stroke-width: 1.5;
    opacity: .5; }
  .radial-svg .r-lbl { fill: #c9d4df; font-size: 9px; pointer-events: none; }
  .radial-svg .r-lbl.file { fill: #a8e6d5; font-size: 10.5px; font-weight: 600; }
  .radial-svg .r-core-lbl { fill: #eafff7; font-weight: 600; pointer-events: none; }
  .radial-svg .r-lbl.decision { fill: #d9a8d6; }
  .radial-svg .r-lbl.dim { opacity: .0; }
  .radial-legend { display: flex; gap: 1rem; flex-wrap: wrap; margin: .5rem 0 .2rem;
    font-size: .75rem; color: #9a9a9a; align-items: center; }
  .radial-legend .k { display: inline-flex; align-items: center; gap: .35rem; }
  .radial-legend .dot { width: 10px; height: 10px; border-radius: 999px;
    display: inline-block; }
  /* Dual landing tabs: Decision tree | Code structure as equal peers. */
  .landing-tabs { display: flex; gap: .5rem; margin: .8rem 0 .4rem; flex-wrap: wrap; }
  .landing-tab { font-size: .9rem; padding: .4rem 1rem; border-radius: 8px;
                 border: 1px solid #3c3c3c; background: #252526; color: #d4d4d4;
                 cursor: pointer; }
  .landing-tab:hover { border-color: #9cdcfe; }
  .landing-tab.active { border-color: #4ec9b0; color: #4ec9b0; background: #1e2a28; }
</style>
</head>
<body>
<div class="topbar">
  <h1>TRACE</h1>
  <button id="chat-toggle" class="chat-toggle">Chat with repository</button>
</div>
<div id="crumbs" class="crumbs"></div>
<input id="q" placeholder="Focus a symbol qualified_name or file path, then press Enter"
       title="qualified_name or file path">
<div id="content"></div>
<div id="chat-drawer" class="chat-drawer">
  <div class="chat-head">
    <span class="t">Chat with repository</span>
    <button id="chat-close" title="Close">&#10005;</button>
  </div>
  <div id="chat-log" class="chat-log"></div>
  <div class="chat-input">
    <input id="chat-q" placeholder="Ask anything about this repository&hellip;">
    <button id="chat-send">Ask</button>
  </div>
</div>
<div id="diff-drawer" class="diff-drawer">
  <div class="diff-head">
    <span id="diff-msg" class="msg"></span>
    <button id="diff-close" title="Close">&#10005;</button>
  </div>
  <div id="diff-body" class="diff-body"></div>
  <div id="diff-verdict" class="diff-verdict"></div>
</div>
<script>
const params = new URLSearchParams(location.search);
const nodeParam = params.get('node') || '';
const fileParam = params.get('file') || '';
const startLineParam = params.get('start_line') || '';
const stepParam = params.get('step') || '';
const branchParam = params.get('branch') || '';
const structureParam = params.has('structure');
const focusParam = params.get('focus') || '';
// Landing tab: decisions (default) or structure. Legacy ?structure=1 selects structure.
const viewParam = (params.get('view') === 'structure' || structureParam)
  ? 'structure' : 'decisions';
const target = nodeParam || fileParam;
const q = document.getElementById('q');
q.value = target;
q.addEventListener('keydown', e => {
  if (e.key === 'Enter') location.search = '?node=' + encodeURIComponent(q.value.trim());
});

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

// --- chat with repository: retrieval over recorded reasoning + code --------
(function wireChat() {
  const drawer = document.getElementById('chat-drawer');
  const log = document.getElementById('chat-log');
  const input = document.getElementById('chat-q');
  document.getElementById('chat-toggle').addEventListener('click', () => {
    drawer.classList.toggle('open');
    if (drawer.classList.contains('open')) input.focus();
  });
  document.getElementById('chat-close').addEventListener('click', () => {
    drawer.classList.remove('open');
  });
  const bubble = (cls) => {
    const b = el('div', 'chat-msg ' + cls);
    log.appendChild(b);
    log.scrollTop = log.scrollHeight;
    return b;
  };
  const renderAnswer = (b, data) => {
    b.textContent = '';
    const hits = data.hits || [];
    const syms = data.symbols || [];
    if (!hits.length && !syms.length) {
      b.textContent = 'Nothing in the recorded reasoning or code matched that ' +
        'question. Try mentioning a file, symbol, or task keyword.';
      return;
    }
    if (hits.length) {
      b.appendChild(el('div', 'muted', 'From the recorded reasoning (' +
        (data.mode === 'semantic' ? 'semantic' : 'keyword') + ' match):'));
      for (const h of hits.slice(0, 3)) {
        const d = el('div', 'hit');
        const a = el('a', '', 'step#' + (h.seq ?? '?'));
        a.href = '?step=' + encodeURIComponent(h.seq);
        d.appendChild(a);
        if (h.prompt) d.appendChild(el('span', 'muted', '  ' + h.prompt));
        if (h.snippet) d.appendChild(el('div', 'snippet', h.snippet));
        b.appendChild(d);
      }
    }
    if (syms.length) {
      const d = el('div', 'hit syms');
      d.appendChild(el('div', 'muted', 'Related code:'));
      for (const s of syms) {
        const a = el('a', '', displayName(s.qualified_name, s.file_path) +
          (s.label ? ' [' + s.label + ']' : ''));
        a.href = '?node=' + encodeURIComponent(s.qualified_name) +
          '&file=' + encodeURIComponent(s.file_path);
        d.appendChild(a);
      }
      b.appendChild(d);
    }
    log.scrollTop = log.scrollHeight;
  };
  const send = async () => {
    const question = input.value.trim();
    if (!question) return;
    input.value = '';
    bubble('user').textContent = question;
    const b = bubble('bot');
    b.textContent = 'Searching the trace\\u2026';
    try {
      const data = await (await fetch('api/ask?q=' + encodeURIComponent(question))).json();
      renderAnswer(b, data);
    } catch (err) {
      b.textContent = 'The panel could not answer: ' + err;
    }
  };
  document.getElementById('chat-send').addEventListener('click', send);
  input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') send(); });
})();
function tag(text, cls) { return el('span', 'tag ' + (cls || ''), text); }
function svgEl(tag, attrs) {
  const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const k in (attrs || {})) n.setAttribute(k, attrs[k]);
  return n;
}

// --- page state ---------------------------------------------------------
let versions = [];            // the global spine (every recorded step)
let entryBySeq = new Map();   // seq -> history entry for the focused target
let touchSeqs = new Set();    // seqs where the target was touched
let importantSeqs = new Set();// decision steps (global, rule-based marker)
let selectedSeq = null;
let branchRows = [];
let lineageData = [];         // registered development lineages (from api/versions)
let activeLineageId = 'main'; // lineage the panel is viewing from
let filters = { author: 'all', kind: 'all', finding: false };
let ledgerOpen = false;         // full ledger rows are opt-in; the tree is primary
let findingFiles = new Map();   // file_path -> semgrep finding count
let findingSymbols = new Map(); // qualified_name -> semgrep finding count
let currentView = 'repo';       // repo | file | symbol | step | decision
// (structure is a landing tab under currentView === 'repo')
let symbolFile = '';            // the focused symbol's file (crumbs + restore)
let historyResolvedQn = '';     // recorded QN when graph QN was aliased
let extraRender = [];           // per-view re-render hooks run on filter change

// --- change review (units recorded by `tracer pull`; see sync/review.py) ----
// The whole surface is: the changed entities light up in both graphs, and clicking
// one opens the before/after diff with its commit message. Nothing else.
let reviewViewer = { username: '', role: '', can_decide: false };
const reviewSeqs = new Set();   // decision-tree steps to light up
const reviewQns = new Set();    // changed symbols to light up
const reviewFiles = new Set();  // changed files to light up
const unitByKey = new Map();    // 'seq:'/'qn:'/'file:' + key -> the change behind it

async function loadReview() {
  try {
    const data = await (await fetch('api/review')).json();
    reviewViewer = data.viewer || reviewViewer;
    const hl = data.highlight || {};
    for (const s of (hl.seqs || [])) reviewSeqs.add(s);
    for (const qn of (hl.symbols || [])) reviewQns.add(qn);
    for (const f of (hl.files || [])) reviewFiles.add(f);
    const claim = (key, unit) => { if (!unitByKey.has(key)) unitByKey.set(key, unit); };
    for (const u of (data.pending || [])) {
      if (u.seq != null) unitByKey.set('seq:' + u.seq, u);
      for (const s of (u.related_seqs || [])) claim('seq:' + s, u);
      for (const s of (u.symbols || [])) {
        if (s.qualified_name) claim('qn:' + s.qualified_name, u);
      }
      for (const f of (u.files || [])) claim('file:' + f, u);
    }
  } catch (err) { /* review is additive; never break the panel */ }
}

function reviewUnitFor(kind, key) { return unitByKey.get(kind + ':' + key) || null; }

// --- the before/after diff panel, opened by clicking a highlighted entity ---
(function wireDiffDrawer() {
  document.getElementById('diff-close').addEventListener('click', () => {
    document.getElementById('diff-drawer').classList.remove('open');
  });
})();

function diffLineClass(line) {
  if (line.startsWith('@@')) return 'dl hunk';
  if (line.startsWith('diff --git') || line.startsWith('index ') ||
      line.startsWith('+++') || line.startsWith('---') ||
      line.startsWith('new file') || line.startsWith('deleted file')) return 'dl meta';
  if (line.startsWith('+')) return 'dl add';
  if (line.startsWith('-')) return 'dl del';
  return 'dl';
}

function openDiffPanel(unit) {
  if (!unit) return;
  document.getElementById('diff-msg').textContent = unit.commit_message || '';
  const body = document.getElementById('diff-body');
  body.textContent = '';
  const pre = el('pre', '');
  for (const line of (unit.diff || '').split('\\n')) {
    pre.appendChild(el('span', diffLineClass(line), line));
  }
  body.appendChild(pre);
  body.scrollTop = 0;
  const verdict = document.getElementById('diff-verdict');
  verdict.textContent = '';
  if (reviewViewer.can_decide) {
    for (const [value, label] of [['accepted', 'Accept'], ['rejected', 'Reject']]) {
      const b = el('button', value === 'accepted' ? 'accept' : 'reject', label);
      b.addEventListener('click', async () => {
        try {
          await fetch('api/review/decide', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ unit_id: unit.unit_id, verdict: value }),
          });
        } catch (err) { /* fall through to the reload; the state is on disk */ }
        location.reload();
      });
      verdict.appendChild(b);
    }
  }
  document.getElementById('diff-drawer').classList.add('open');
}

function crumbs(items) {
  const host = document.getElementById('crumbs');
  host.textContent = '';
  items.forEach((it, i) => {
    if (i) host.appendChild(el('span', 'sep', '/'));
    if (it.href != null) {
      const a = el('a', '', it.label);
      a.href = it.href;
      if (it.title) a.title = it.title;
      host.appendChild(a);
    } else {
      const s = el('span', '', it.label);
      if (it.title) s.title = it.title;
      host.appendChild(s);
    }
  });
  if (currentView !== 'repo') {
    host.appendChild(el('span', 'sep', '|'));
    const a = el('a', '', 'code structure');
    a.href = '?view=structure';
    a.title = 'Open the Code structure landing tab';
    host.appendChild(a);
  }
}

async function loadFindings() {
  // The last saved Semgrep triage report (flag --save); optional.
  try {
    const data = await (await fetch('api/findings')).json();
    for (const r of (data.rows || [])) {
      const fp = (r.path || '').replace(/\\\\/g, '/');
      if (fp) findingFiles.set(fp, (findingFiles.get(fp) || 0) + 1);
      if (r.symbol) findingSymbols.set(r.symbol, (findingSymbols.get(r.symbol) || 0) + 1);
    }
  } catch (e) { /* no findings, no filter */ }
}

function authorOk(a) { return filters.author === 'all' || (a || 'agent') === filters.author; }
function kindOk(k) { return filters.kind === 'all' || k === filters.kind; }

function refilter() {
  renderTimeline();
  renderDecisionView();
  renderLedger();
  for (const fn of extraRender) fn();
}

function filterBar(content, groups) {
  const bar = el('div', 'chips');
  function chip(label, isActive, onclick, cls) {
    const c = el('button', 'chip' + (cls ? ' ' + cls : '') + (isActive() ? ' active' : ''), label);
    c.addEventListener('click', () => { onclick(); refilter(); rebuild(); });
    return c;
  }
  let rebuild = () => {
    bar.textContent = '';
    if (groups.author) {
      bar.appendChild(el('span', 'label', 'author:'));
      for (const a of ['all', 'human', 'agent']) {
        bar.appendChild(chip(a, () => filters.author === a, () => { filters.author = a; }));
      }
      // One legend for the yellow author-dot; rows only show the dot, not a badge.
      bar.appendChild(el('span', 'label', '\\u25CF = human-written'));
    }
    if (groups.kind) {
      bar.appendChild(el('span', 'label', 'kind:'));
      for (const k of ['all', 'abandoned', 'revised', 'error_retry']) {
        bar.appendChild(chip(k, () => filters.kind === k, () => { filters.kind = k; }));
      }
    }
    if (groups.finding) {
      bar.appendChild(el('span', 'label', 'semgrep:'));
      bar.appendChild(chip('has finding', () => filters.finding,
        () => { filters.finding = !filters.finding; }, 'finding'));
    }
  };
  rebuild();
  content.appendChild(bar);
}

// --- bridge to the VS Code extension (or CLI hints in a plain browser) ----
function bridge(msg, hintText, host) {
  if (window.parent !== window) {
    // Inside the VS Code webview: the extension bridge runs the CLI / applies the edit.
    window.parent.postMessage(msg, '*');
    return;
  }
  const old = host.querySelector('.cli-hint');
  if (old) old.remove();
  host.appendChild(el('pre', 'code cli-hint', hintText));
}

function rollbackButton(seq) {
  const b = el('button', 'rollback',
    'Roll back to step ' + seq + '  (git branch rollback/step-' + seq + ')');
  b.addEventListener('click', () => bridge(
    { type: 'rollback', seq: seq },
    'Run from a terminal (non-destructive; creates a new git branch):\\n' +
    'codegraph-trace goto ' + seq + ' --branch rollback/step-' + seq + ' --repo <repo>',
    b.parentElement));
  return b;
}

function restoreButton(file, qn, opts) {
  // Per-symbol restore: an undoable editor edit (WorkspaceEdit), not a checkout.
  const b = el('button', 'rollback', opts.label ||
    ('Restore into editor (as of step ' + opts.seq + ')'));
  b.addEventListener('click', () => {
    const msg = { type: 'restoreSymbol', file: file, qualifiedName: qn };
    let cli = 'codegraph-trace symbol-content "' + file + '" "' + qn + '"';
    if (opts.branchId != null) { msg.branchId = opts.branchId; cli += ' --branch-id ' + opts.branchId; }
    else { msg.seq = opts.seq; cli += ' --at-seq ' + opts.seq; }
    bridge(msg,
      'Inside VS Code this applies an undoable editor edit. From a terminal:\\n' +
      cli + ' --repo <repo>',
      b.parentElement);
  });
  return b;
}

function openToViewButton(file, qn, detailHost) {
  // Show the latest file source in the panel, scrolled to the symbol when known.
  const b = el('button', 'rollback', 'Open to view');
  b.title = 'Show the latest source for ' + file + ' in this panel';
  b.addEventListener('click', async () => {
    let qs = 'api/file-content?file=' + encodeURIComponent(file);
    if (qn) qs += '&node=' + encodeURIComponent(qn);
    b.disabled = true;
    try {
      const data = await (await fetch(qs)).json();
      const old = detailHost.querySelector('.struct-code');
      if (old) old.remove();
      if (data.error) {
        detailHost.appendChild(el('div', 'muted', data.error));
        return;
      }
      const wrap = el('div', 'struct-code');
      const meta = el('div', 'muted',
        data.file + '  (' + (data.source || 'latest') +
        (data.start_line ? ', highlight L' + data.start_line +
          (data.end_line ? '-' + data.end_line : '') : '') + ')');
      wrap.appendChild(meta);
      const pre = document.createElement('pre');
      pre.className = 'code';
      const lines = (data.content || '').split('\\n');
      let firstHl = null;
      const start = data.start_line || 0;
      const end = data.end_line || start;
      lines.forEach((line, i) => {
        const n = i + 1;
        const span = document.createElement('span');
        span.className = 'cline' + (start && n >= start && n <= end ? ' hl' : '');
        span.id = 'L' + n;
        span.textContent = line + (i < lines.length - 1 ? '\\n' : '');
        pre.appendChild(span);
        if (start && n === start) firstHl = span;
      });
      wrap.appendChild(pre);
      detailHost.appendChild(wrap);
      if (firstHl) firstHl.scrollIntoView({ behavior: 'smooth', block: 'center' });
      else wrap.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (err) {
      detailHost.appendChild(el('div', 'muted', 'Failed to load file: ' + err));
    } finally {
      b.disabled = false;
    }
  });
  return b;
}

function zoomStepLink(seq) {
  const a = el('a', 'zoomlink', 'zoom into step #' + seq);
  a.href = '?step=' + seq;
  return a;
}

function structureLink(focus) {
  // Back-link from a decision to the affected code in the structure landing tab.
  const a = el('a', 'zoomlink', '[structure]');
  a.href = '?view=structure&focus=' + encodeURIComponent(focus);
  a.title = 'Show this in the code structure view';
  return a;
}

// Short project-relative display name; the full qualified name (which embeds the
// machine-path project prefix) stays in hrefs and API calls only.
function displayName(qn, filePath) {
  if (!qn) return (filePath || '').split('/').slice(-1)[0] || '';
  if (qn.startsWith('file::')) return qn.slice(6).split('/').slice(-1)[0];
  if (filePath) {
    return filePath.split('/').slice(-1)[0] + ' \\u203A ' + qn.split('.').slice(-1)[0];
  }
  return qn.split('.').slice(-2).join('.');
}

// Author marker: one small dot instead of a badge on every row; the legend next to
// the author filter chips explains it once.
function authorDot(author) {
  if ((author || '') !== 'human') return null;
  const s = el('span', 'adot', '\\u25CF');
  s.title = 'human-written';
  return s;
}

function renderStep(e, important) {
  const d = el('div', 'step');
  const head = el('div', 'head');
  const dot = authorDot(e.author);
  if (dot) head.appendChild(dot);
  head.appendChild(el('span', 'seq', 'step#' + (e.seq ?? '?')));
  head.appendChild(el('span', '', e.step_id));
  head.appendChild(el('span', 'sha', (e.after_sha || '').slice(0, 10) + '  ' + (e.timestamp || '')));
  if (important) head.appendChild(tag('decision', 'decision'));
  d.appendChild(head);
  if (e.prompt) {
    const p = el('div', 'muted'); p.textContent = 'prompt: ' + e.prompt; d.appendChild(p);
  }
  if (e.reasoning_text) d.appendChild(el('pre', 'reason', e.reasoning_text));
  const nodes = el('div', '');
  for (const n of (e.nodes || [])) {
    const line = el('div', 'muted');
    const ndot = authorDot(n.author);
    if (ndot) { line.appendChild(ndot); line.appendChild(document.createTextNode(' ')); }
    const a = el('a', '', displayName(n.qualified_name, n.file_path));
    a.href = '?node=' + encodeURIComponent(n.qualified_name);
    a.title = 'Open the decision history of this symbol';
    line.appendChild(a);
    line.appendChild(document.createTextNode(' [' + (n.change_kind || '?') + ']'));
    line.appendChild(structureLink(n.qualified_name));
    if (n.locked) line.appendChild(tag('locked', 'locked'));
    nodes.appendChild(line);
  }
  d.appendChild(nodes);
  for (const b of (e.branches || [])) {
    const line = el('div', '');
    line.appendChild(tag(b.kind + (b.superseded_by_seq != null ?
      ' - superseded by step ' + b.superseded_by_seq : ''), b.kind));
    line.appendChild(el('span', 'muted',
      ' ' + displayName(b.qualified_name, b.file_path)));
    d.appendChild(line);
    if (b.abandoned_content) {
      const pre = el('pre', 'code', b.abandoned_content);
      d.appendChild(pre);
    }
  }
  return d;
}

// --- timeline strip ---------------------------------------------------------
// The strip exists to surface human-written steps (yellow) among the agent's.
// When the trace has no human steps there is nothing it adds over the tree
// above, so it stays blank.
function renderTimeline() {
  const strip = document.getElementById('timeline');
  if (!strip) return;
  strip.textContent = '';
  if (!versions.some(v => (v.author || '') === 'human')) return;
  for (const v of versions) {
    let cls = 'dot';
    if (touchSeqs.has(v.seq)) cls += ' touch';
    if (importantSeqs.has(v.seq)) cls += ' decision';
    if ((v.author || '') === 'human') cls += ' human';
    if (v.seq === selectedSeq) cls += ' selected';
    if (!authorOk(v.author)) cls += ' dim';
    const d = el('span', cls);
    d.title = 'step ' + v.seq + (v.important ? ' [decision]' : '') +
      ((v.author || '') === 'human' ? ' [human]' : '') +
      (v.prompt ? ': ' + v.prompt.slice(0, 120) : '');
    d.addEventListener('click', () => { selectStep(v.seq); });
    strip.appendChild(d);
  }
}

function stepCard(seq) {
  // One step as a card: full history entry when the step touched the focused
  // target, otherwise the plain versions row. Returns null for unknown seqs.
  const e = entryBySeq.get(seq);
  const v = versions.find(x => x.seq === seq);
  let card;
  if (e) {
    card = renderStep(e, importantSeqs.has(seq));
    if (currentView === 'symbol' && symbolFile && (historyResolvedQn || nodeParam)) {
      card.appendChild(restoreButton(symbolFile, historyResolvedQn || nodeParam, { seq: seq,
        label: 'Restore this symbol as of step ' + seq + ' (editor edit)' }));
    }
  } else if (v) {
    card = el('div', 'step');
    const head = el('div', 'head');
    const dot = authorDot(v.author);
    if (dot) head.appendChild(dot);
    head.appendChild(el('span', 'seq', 'step#' + v.seq));
    head.appendChild(el('span', '', v.step_id));
    head.appendChild(el('span', 'sha', (v.after_sha || '').slice(0, 10) + '  ' + (v.timestamp || '')));
    if (v.important) head.appendChild(tag('decision', 'decision'));
    if (v.lineage_id && v.lineage_id !== 'main' && v.lineage_id !== activeLineageId) {
      head.appendChild(tag('merged from ' + v.lineage_id, 'lineage'));
    }
    card.appendChild(head);
    if (v.prompt) {
      const p = el('div', 'muted'); p.textContent = 'prompt: ' + v.prompt; card.appendChild(p);
    }
    if (currentView === 'file' || currentView === 'symbol') {
      card.appendChild(el('div', 'muted', 'This step did not touch the focused target.'));
    }
  } else {
    return null;
  }
  card.appendChild(rollbackButton(seq));
  card.appendChild(zoomStepLink(seq));
  return card;
}

function selectStep(seq) {
  selectedSeq = seq;
  renderTimeline();
  const detail = document.getElementById('detail');
  if (!detail) return;
  detail.textContent = '';
  const card = stepCard(seq);
  if (card) detail.appendChild(card);
}

document.addEventListener('keydown', (ev) => {
  if (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight') return;
  if (ev.target && ev.target.tagName === 'INPUT') return;
  if (!versions.length) return;
  const seqs = versions.map(v => v.seq);
  let i = seqs.indexOf(selectedSeq);
  if (i === -1) i = ev.key === 'ArrowLeft' ? seqs.length : -1;
  i += (ev.key === 'ArrowLeft' ? -1 : 1);
  if (i < 0 || i >= seqs.length) return;
  ev.preventDefault();
  selectStep(seqs[i]);
});

// --- decision view: the spine plus its abandoned side branches -----------
function truncLabel(s, max) {
  return s.length > max ? s.slice(0, max - 1) + '\\u2026' : s;
}

function branchTargetName(r) {
  const qn = r.qualified_name || '';
  if (qn && !qn.startsWith('file::')) return qn.split('.').slice(-1)[0] || qn;
  return (r.file_path || '').split('/').slice(-1)[0] || '';
}

function renderDecisionView() {
  const host = document.getElementById('decision');
  if (!host) return;
  host.textContent = '';
  const isRepo = currentView === 'repo';
  const sideRows = branchRows.filter(r => r.kind !== 'survived' && r.seq != null &&
    ledgerRowVisible(r));
  if (!versions.length) {
    host.appendChild(el('div', 'muted', isRepo ?
      'No recorded steps yet - record a session first.' :
      'No trace data recorded for this target.'));
    return;
  }

  // The whole run is the spine so the surrounding work stays visible: steps that
  // touched the target are full nodes, other steps are small context nodes, and
  // runs of more than two context steps collapse into one "+k" slot. Branch seqs,
  // superseding seqs, and the immediate neighbors of touched steps always stay.
  const allSeqs = versions.map(v => v.seq).sort((a, b) => a - b);
  const touched = new Set(allSeqs.filter(s => touchSeqs.has(s)));
  const keep = new Set(touched);
  for (const r of sideRows) {
    keep.add(r.seq);
    if (r.superseded_by_seq != null) keep.add(r.superseded_by_seq);
  }
  for (let i = 0; i < allSeqs.length; i++) {
    if (touched.has(allSeqs[i])) {
      if (i > 0) keep.add(allSeqs[i - 1]);
      if (i + 1 < allSeqs.length) keep.add(allSeqs[i + 1]);
    }
  }
  const slots = [];
  let run = [];
  const flushRun = () => {
    if (run.length > 2) slots.push({ gap: run.length });
    else for (const s of run) slots.push({ seq: s });
    run = [];
  };
  for (const s of allSeqs) {
    if (keep.has(s)) { flushRun(); slots.push({ seq: s }); }
    else run.push(s);
  }
  flushRun();

  // Development-lineage lanes (repo view only): merged branches get their own lane
  // between fork and merge-back; open branches show faint + locked (their steps are
  // hidden from this lineage until merged).
  const laneSource = isRepo ? lineageData.filter(l =>
    l.lineage_id !== 'main' && l.lineage_id !== activeLineageId) : [];
  const lanes = [];
  for (const l of laneSource) {
    if (l.status === 'merged') {
      const seqs = versions.filter(v => (v.lineage_id || 'main') === l.lineage_id)
        .map(v => v.seq).sort((a, b) => a - b);
      if (seqs.length) lanes.push({ lin: l, seqs: seqs, open: false });
    } else if ((l.hidden_steps || []).length) {
      lanes.push({ lin: l, steps: l.hidden_steps, open: true });
    }
  }
  const laneSeqSet = new Set();
  for (const ln of lanes) if (!ln.open) for (const s of ln.seqs) laneSeqSet.add(s);

  const laneH = 52;
  const x0 = 90, spineY = 40 + lanes.length * laneH;
  const bw = 140, bh = 40;
  const rowH = bh + 48;
  const slotW = sl => sl.gap ? 56 : (touched.has(sl.seq) ? 165 : 48);
  const slotX = new Map();
  let cx = x0;
  for (let i = 0; i < slots.length; i++) {
    if (i) cx += (slotW(slots[i - 1]) + slotW(slots[i])) / 2;
    slots[i].x = cx;
    if (slots[i].seq != null) slotX.set(slots[i].seq, cx);
  }
  const xOf = seq => slotX.get(seq);

  // Stagger multiple branches hanging off the same step.
  const levelBySeq = new Map();
  let maxLevel = 0;
  const placed = sideRows.filter(r => slotX.has(r.seq)).map(r => {
    const lvl = levelBySeq.get(r.seq) || 0;
    levelBySeq.set(r.seq, lvl + 1);
    maxLevel = Math.max(maxLevel, lvl + 1);
    return { row: r, level: lvl };
  });

  // Spine seqs (main-only) — needed to decide merge-back vs tip-of-history HEAD.
  const spineSeqs = versions.map(v => v.seq).filter(s => !laneSeqSet.has(s))
    .sort((a, b) => a - b);
  const spineSlots = slots.filter(sl => sl.gap || !laneSeqSet.has(sl.seq));

  // Open-lane nodes sit to the right of their fork point at fixed spacing.
  // Tip-of-history merged lanes need an explicit HEAD node past the tip (same
  // visual pattern as merging into a later main step like 9-11 -> 12).
  let extraX = 0;
  for (const ln of lanes) {
    if (ln.open) {
      const base = ln.lin.base_seq != null ? Number(ln.lin.base_seq) : null;
      const forkX = (base != null && slotX.has(base)) ? xOf(base) : x0;
      extraX = Math.max(extraX, forkX + (ln.steps.length + 1) * 60 + 60);
      continue;
    }
    const xs = ln.seqs.map(s => xOf(s)).filter(x => x != null);
    if (!xs.length) continue;
    const lastSeq = ln.seqs[ln.seqs.length - 1];
    const nextSpine = spineSeqs.find(s => s > lastSeq);
    if (!(nextSpine != null && slotX.has(nextSpine))) {
      extraX = Math.max(extraX, xs[xs.length - 1] + 70 + 40);
    }
  }
  const width = Math.max(560, cx + x0, extraX);
  const height = 90 + Math.max(1, maxLevel) * rowH + lanes.length * laneH;
  const svg = svgEl('svg', { class: 'decision-svg', width: width, height: height,
    viewBox: '0 0 ' + width + ' ' + height });

  // Spine line: through main-only slots, then out to any tip-of-history HEAD markers.
  let spineEndX = spineSlots.length ? spineSlots[spineSlots.length - 1].x : x0;
  for (const ln of lanes) {
    if (ln.open) continue;
    const xs = ln.seqs.map(s => xOf(s)).filter(x => x != null);
    if (!xs.length) continue;
    const lastSeq = ln.seqs[ln.seqs.length - 1];
    const nextSpine = spineSeqs.find(s => s > lastSeq);
    if (!(nextSpine != null && slotX.has(nextSpine))) {
      spineEndX = Math.max(spineEndX, xs[xs.length - 1] + 70);
    }
  }
  if (spineSlots.length) {
    svg.appendChild(svgEl('line', { class: 'spine-line', x1: spineSlots[0].x, y1: spineY,
      x2: spineEndX, y2: spineY }));
  }
  for (const sl of slots) {
    if (sl.seq != null && laneSeqSet.has(sl.seq)) continue; // drawn on its lane below
    if (sl.gap) {
      const g = svgEl('g', { class: 'spine-gap' });
      g.appendChild(svgEl('rect', { x: sl.x - 20, y: spineY - 24, width: 40, height: 34,
        fill: 'transparent' }));
      const t = svgEl('text', { x: sl.x, y: spineY - 10, 'text-anchor': 'middle' });
      t.textContent = '+' + sl.gap;
      g.appendChild(t);
      const title = svgEl('title');
      title.textContent = sl.gap + ' step(s) that did not touch this target';
      g.appendChild(title);
      svg.appendChild(g);
      continue;
    }
    const seq = sl.seq;
    const isTouch = touched.has(seq);
    let cls = 'spine-node' + (importantSeqs.has(seq) ? ' decision' : '');
    if (!isTouch) cls += ' context';
    if (reviewSeqs.has(seq)) cls += ' review';
    const c = svgEl('circle', { class: cls, cx: sl.x, cy: spineY, r: isTouch ? 7 : 3.5 });
    c.addEventListener('click', () => {
      const unit = reviewUnitFor('seq', seq);
      if (unit) return openDiffPanel(unit);
      showStepDetail(seq);
    });
    svg.appendChild(c);
    if (isTouch) {
      const label = svgEl('text', { x: sl.x, y: spineY - 14, 'text-anchor': 'middle' });
      label.textContent = 'step ' + seq;
      svg.appendChild(label);
    } else {
      const title = svgEl('title');
      title.textContent = 'step ' + seq + ' (did not touch this target)';
      c.appendChild(title);
    }
  }

  // Decision-ledger stems must attach to the node that owns the step — on a
  // development lane that is the blue lane node, not a blank spot on the green spine.
  const laneYForSeq = new Map();
  // --- development-lineage lanes (fork / merge-back / faint open) ----------
  lanes.forEach((ln, idx) => {
    const laneY = spineY - laneH * (idx + 1);
    const lid = ln.lin.lineage_id;
    const baseSeq = ln.lin.base_seq != null ? Number(ln.lin.base_seq) : null;
    const forkX = (baseSeq != null && slotX.has(baseSeq)) ? xOf(baseSeq) : x0;
    if (!ln.open) {
      const xs = ln.seqs.map(s => xOf(s)).filter(x => x != null);
      if (!xs.length) return;
      // Fork out of the spine, ride the lane, then merge back at the first
      // spine step after the branch's last step — or into an explicit HEAD
      // marker when the merged branch tip is also the tip of history.
      svg.appendChild(svgEl('path', { class: 'lane-edge merged',
        d: 'M ' + forkX + ' ' + (spineY - 7) + ' C ' + forkX + ' ' + (laneY + 26) +
          ', ' + xs[0] + ' ' + (laneY + 26) + ', ' + xs[0] + ' ' + (laneY + 7) }));
      if (xs.length > 1) {
        svg.appendChild(svgEl('line', { class: 'lane-line merged',
          x1: xs[0], y1: laneY, x2: xs[xs.length - 1], y2: laneY }));
      }
      const lastSeq = ln.seqs[ln.seqs.length - 1];
      const nextSpine = spineSeqs.find(s => s > lastSeq);
      const tipOfHistory = !(nextSpine != null && slotX.has(nextSpine));
      const mergeX = tipOfHistory ? (xs[xs.length - 1] + 70) : xOf(nextSpine);
      if (tipOfHistory) {
        const head = svgEl('circle', { class: 'spine-node lane',
          cx: mergeX, cy: spineY, r: 7 });
        const headTitle = svgEl('title');
        headTitle.textContent = 'HEAD after merging ' + lid +
          ' (no later main-only step — same role as a post-merge spine node)';
        head.appendChild(headTitle);
        head.addEventListener('click', () => showStepDetail(lastSeq));
        svg.appendChild(head);
        const headLbl = svgEl('text', { x: mergeX, y: spineY - 14,
          'text-anchor': 'middle' });
        headLbl.textContent = 'HEAD';
        svg.appendChild(headLbl);
      }
      svg.appendChild(svgEl('path', { class: 'lane-edge merged',
        d: 'M ' + xs[xs.length - 1] + ' ' + (laneY + 7) + ' C ' +
          xs[xs.length - 1] + ' ' + (laneY + 26) + ', ' + mergeX + ' ' +
          (laneY + 26) + ', ' + mergeX + ' ' + (spineY - 7) }));
      const lbl = svgEl('text', { class: 'lane-label', x: xs[0] - 8, y: laneY - 28,
        'text-anchor': 'start' });
      lbl.textContent = lid + (tipOfHistory ? ' (merged → HEAD)' : ' (merged)');
      svg.appendChild(lbl);
      for (const s of ln.seqs) {
        const x = xOf(s);
        if (x == null) continue;
        laneYForSeq.set(s, laneY);
        let cls = 'spine-node lane' + (importantSeqs.has(s) ? ' decision' : '');
        if (reviewSeqs.has(s)) cls += ' review';
        const c = svgEl('circle', { class: cls, cx: x, cy: laneY, r: 7 });
        c.addEventListener('click', () => {
          const unit = reviewUnitFor('seq', s);
          if (unit) return openDiffPanel(unit);
          showStepDetail(s);
        });
        const title = svgEl('title');
        const v = versions.find(vv => vv.seq === s) || {};
        title.textContent = 'step ' + s + ' (' + (v.step_id || '') + ') - merged from ' + lid;
        c.appendChild(title);
        svg.appendChild(c);
        const t = svgEl('text', { x: x, y: laneY - 4 - 10, 'text-anchor': 'middle' });
        t.textContent = 'step ' + s;
        svg.appendChild(t);
      }
    } else {
      // Open lineage: its steps are invisible from here (one-way visibility), so
      // draw them faint with a lock - a fork exists but has not been accepted.
      const xs = ln.steps.map((_, k) => forkX + 60 * (k + 1));
      svg.appendChild(svgEl('path', { class: 'lane-edge open',
        d: 'M ' + forkX + ' ' + (spineY - 7) + ' C ' + forkX + ' ' + (laneY + 26) +
          ', ' + xs[0] + ' ' + (laneY + 26) + ', ' + xs[0] + ' ' + (laneY + 7) }));
      if (xs.length > 1) {
        svg.appendChild(svgEl('line', { class: 'lane-line open',
          x1: xs[0], y1: laneY, x2: xs[xs.length - 1], y2: laneY }));
      }
      ln.steps.forEach((st, k) => {
        if (st.seq != null) laneYForSeq.set(st.seq, laneY);
        const c = svgEl('circle', { class: 'spine-node open', cx: xs[k], cy: laneY, r: 6 });
        const title = svgEl('title');
        title.textContent = 'step ' + (st.seq ?? '?') + ' (' + (st.step_id || '') +
          ') on open lineage ' + lid + ' - hidden from ' + activeLineageId + ' until merged';
        c.appendChild(title);
        svg.appendChild(c);
        const t = svgEl('text', { class: 'openstep', x: xs[k], y: laneY - 14,
          'text-anchor': 'middle' });
        t.textContent = 'step ' + (st.seq ?? '?');
        svg.appendChild(t);
      });
      const lockX = xs[xs.length - 1] + 26;
      const lock = svgEl('text', { class: 'openstep', x: lockX, y: laneY + 5,
        'text-anchor': 'start' });
      lock.textContent = '\\uD83D\\uDD12';
      const lt = svgEl('title');
      lt.textContent = 'Open lineage: ' + lid + ' - not visible from ' +
        activeLineageId + ' until merged (codegraph-trace branch merge ' + lid + ')';
      lock.appendChild(lt);
      svg.appendChild(lock);
      const lbl = svgEl('text', { class: 'lane-label open', x: xs[0] - 8, y: laneY - 28,
        'text-anchor': 'start' });
      lbl.textContent = lid + ' (open - locked)';
      svg.appendChild(lbl);
    }
  });

  for (const p of placed) {
    const r = p.row;
    const x = xOf(r.seq), by = spineY + 44 + p.level * rowH;
    // Anchor on the development-lane node when the step lives there (e.g. step 13
    // on feat-move-timer), not on an empty green-spine x under that lane.
    const anchorY = laneYForSeq.has(r.seq) ? laneYForSeq.get(r.seq) : spineY;
    svg.appendChild(svgEl('path', { class: 'branch-edge ' + r.kind,
      d: 'M ' + x + ' ' + (anchorY + 7) + ' C ' + x + ' ' + (anchorY + 26) + ', ' +
        x + ' ' + (by - 20) + ', ' + x + ' ' + (by - bh / 2) }));
    if (r.superseded_by_seq != null && slotX.has(r.superseded_by_seq)) {
      const sx = xOf(r.superseded_by_seq);
      const landY = laneYForSeq.has(r.superseded_by_seq) ?
        laneYForSeq.get(r.superseded_by_seq) + 7 : spineY + 9;
      svg.appendChild(svgEl('path', { class: 'supersede-edge',
        d: 'M ' + (x + bw / 2) + ' ' + by + ' C ' + ((x + sx) / 2) + ' ' + by + ', ' +
          sx + ' ' + (by - 20) + ', ' + sx + ' ' + landY }));
    }
    const g = svgEl('g', { class: 'branch-node' });
    g.appendChild(svgEl('rect', { x: x - bw / 2, y: by - bh / 2, width: bw, height: bh,
      rx: 5 }));
    // Line 1: what the attempt affected. Line 2: what happened to it - the step it
    // started at and the step that replaced it.
    const name = svgEl('text', { x: x, y: by - 4, 'text-anchor': 'middle' });
    name.textContent = truncLabel(branchTargetName(r), 20);
    g.appendChild(name);
    const t = svgEl('text', { x: x, y: by + 12, 'text-anchor': 'middle' });
    t.textContent = r.kind + ' @' + r.seq +
      (r.superseded_by_seq != null ? ' -> ' + r.superseded_by_seq : '');
    g.appendChild(t);
    const title = svgEl('title');
    title.textContent = displayName(r.qualified_name, r.file_path) + ' [' + r.kind + ']' +
      ' - started at step ' + r.seq +
      (r.superseded_by_seq != null ?
        ', replaced by step ' + r.superseded_by_seq : ', never replaced');
    g.appendChild(title);
    g.addEventListener('click', () => showBranchDetail(r));
    svg.appendChild(g);
  }
  const scroller = el('div', 'dscroll');
  scroller.appendChild(svg);
  host.appendChild(scroller);
  // Development-lineage forks often sit far to the right of step 1. Auto-scroll
  // so the leftmost fork is in view — otherwise a merge looks like a flat spine.
  if (lanes.length) {
    let minFork = Infinity;
    for (const ln of lanes) {
      const fx = (ln.lin.base_seq != null && slotX.has(ln.lin.base_seq))
        ? xOf(ln.lin.base_seq) : x0;
      if (fx < minFork) minFork = fx;
    }
    if (Number.isFinite(minFork)) {
      scroller.scrollLeft = Math.max(0, minFork - 100);
    }
  }
  // Zoom + pan, like the code structure view: long histories can be zoomed out
  // to be seen whole. Scaling the element (fixed viewBox) keeps the layout and
  // click targets intact; the scroller still provides the horizontal pan.
  let dzoom = 1;
  const applyZoom = (nz, clientX) => {
    nz = Math.min(3, Math.max(0.15, nz));
    if (nz === dzoom) return;
    const rect = scroller.getBoundingClientRect();
    const px = clientX != null ? clientX - rect.left : rect.width / 2;
    const contentX = (scroller.scrollLeft + px) / dzoom; // point under the cursor
    dzoom = nz;
    svg.style.width = (width * dzoom) + 'px';
    svg.style.height = (height * dzoom) + 'px';
    scroller.scrollLeft = contentX * dzoom - px;
  };
  scroller.addEventListener('wheel', (ev) => {
    // Horizontal wheel/trackpad gestures keep native scrolling; vertical zooms.
    if (Math.abs(ev.deltaX) > Math.abs(ev.deltaY)) return;
    ev.preventDefault();
    applyZoom(dzoom * (ev.deltaY < 0 ? 1.1 : 0.9), ev.clientX);
  }, { passive: false });
  let dpan = null;
  svg.addEventListener('pointerdown', (ev) => {
    if (ev.target.closest('g, circle')) return; // node clicks stay clicks
    dpan = { x: ev.clientX, left: scroller.scrollLeft };
    svg.classList.add('panning');
    svg.setPointerCapture(ev.pointerId);
  });
  svg.addEventListener('pointermove', (ev) => {
    if (!dpan) return;
    scroller.scrollLeft = dpan.left - (ev.clientX - dpan.x);
  });
  const endDpan = (ev) => {
    if (!dpan) return;
    dpan = null;
    svg.classList.remove('panning');
    try { svg.releasePointerCapture(ev.pointerId); } catch (err) {}
  };
  svg.addEventListener('pointerup', endDpan);
  svg.addEventListener('pointercancel', endDpan);
  if (!sideRows.length) {
    host.appendChild(el('div', 'muted', isRepo ?
      'No abandoned side branches anywhere in the repo - plain forward motion.' :
      'No abandoned side branches for this target - plain forward motion.'));
  }
}

// --- one decision, side by side: dead code vs the code that won ------------
function renderCompare(host, data, branchId) {
  const grid = el('div', 'compare');

  const dead = el('div', 'col dead');
  dead.appendChild(el('h3', '', data.kind + ' (step ' + (data.abandoned.seq ?? '?') + ')'));
  if (data.abandoned.prompt) dead.appendChild(el('div', 'muted', 'prompt: ' + data.abandoned.prompt));
  if (data.abandoned.reasoning_text) dead.appendChild(el('pre', 'reason', data.abandoned.reasoning_text));
  dead.appendChild(el('pre', 'code', data.abandoned.content || '(no recorded content)'));
  if (data.qualified_name && data.abandoned.content) {
    dead.appendChild(restoreButton(data.file_path, data.qualified_name,
      { branchId: branchId, label: 'Restore this abandoned code into the editor' }));
  }
  grid.appendChild(dead);

  const win = el('div', 'col win');
  if (data.surviving) {
    win.appendChild(el('h3', '', 'won (step ' + (data.surviving.seq ?? '?') + ')'));
    if (data.surviving.prompt) win.appendChild(el('div', 'muted', 'prompt: ' + data.surviving.prompt));
    if (data.surviving.reasoning_text) win.appendChild(el('pre', 'reason', data.surviving.reasoning_text));
    win.appendChild(el('pre', 'code', data.surviving.content || '(content unavailable)'));
    if (data.qualified_name && data.surviving.content && data.surviving.seq != null) {
      win.appendChild(restoreButton(data.file_path, data.qualified_name,
        { seq: data.surviving.seq, label: 'Restore the winning version into the editor' }));
    }
  } else {
    win.appendChild(el('h3', '', 'no superseding step'));
    win.appendChild(el('div', 'muted',
      'This attempt was not replaced by a recorded later step.'));
  }
  grid.appendChild(win);
  host.appendChild(grid);
}

function decisionSummary(data) {
  // The branch's full story in one line: where it started, what it affected,
  // what happened to it, and what replaced it.
  const qn = data.qualified_name || '';
  const startSeq = data.abandoned.seq;
  const sum = el('div', 'muted');
  sum.appendChild(document.createTextNode('Started at '));
  const startLink = el('a', 'zoomlink', 'step ' + (startSeq ?? '?'));
  if (startSeq != null) startLink.href = '?step=' + startSeq;
  sum.appendChild(startLink);
  sum.appendChild(document.createTextNode(
    ' - affected ' + displayName(qn, data.file_path)));
  sum.appendChild(structureLink(qn || data.file_path || ''));
  sum.appendChild(document.createTextNode(' - ' + data.kind));
  if (data.surviving && data.surviving.seq != null) {
    sum.appendChild(document.createTextNode(' - replaced by '));
    const winLink = el('a', 'zoomlink', 'step ' + data.surviving.seq);
    winLink.href = '?step=' + data.surviving.seq;
    sum.appendChild(winLink);
  } else {
    sum.appendChild(document.createTextNode(' - never replaced by a recorded later step'));
  }
  return sum;
}

// --- decision-detail panel: one step or one branch, right under the tree ----
function showStepDetail(seq) {
  selectStep(seq); // keep the timeline selection in sync
  const host = document.getElementById('decision-detail');
  if (!host) return;
  host.textContent = '';
  const card = stepCard(seq);
  if (card) host.appendChild(card);
  const rows = branchRows.filter(r => r.seq === seq && ledgerRowVisible(r))
    .slice().sort((a, b) => a.branch_id - b.branch_id);
  if (rows.length) {
    host.appendChild(el('div', 'muted', 'Ledger entries for this step:'));
    for (const r of rows) host.appendChild(ledgerCard(r));
  }
  host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

async function showBranchDetail(row) {
  const host = document.getElementById('decision-detail');
  if (!host) return;
  host.textContent = '';
  const data = await (await fetch('api/branch-detail?branch_id=' + row.branch_id)).json();
  if (data.error) { host.appendChild(el('div', 'muted', data.error)); return; }
  host.appendChild(el('h2', '',
    'Decision at step ' + (data.abandoned.seq ?? '?') + ': ' +
    displayName(data.qualified_name, data.file_path)));
  host.appendChild(decisionSummary(data));
  const page = el('a', 'zoomlink', 'open this decision as its own page');
  page.href = '?branch=' + row.branch_id;
  host.appendChild(page);
  host.appendChild(ledgerCard(row));
  renderCompare(host, data, row.branch_id);
  host.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// --- decision view: the deepest zoom level (?branch=<branch_id>) -----------
async function decisionView(content, branchIdStr) {
  currentView = 'decision';
  const branchId = parseInt(branchIdStr, 10);
  const data = await (await fetch('api/branch-detail?branch_id=' + branchId)).json();
  if (data.error) {
    crumbs([{ label: 'repo', href: '?' }, { label: 'decision' }]);
    content.appendChild(el('div', 'muted', data.error));
    return;
  }
  const qn = data.qualified_name || '';
  const startSeq = data.abandoned.seq;

  const trail = [{ label: 'repo', href: '?' }];
  if (data.file_path) {
    trail.push({ label: data.file_path, href: '?file=' + encodeURIComponent(data.file_path) });
  }
  if (qn) {
    const leaf = qn.split('.').slice(-1)[0] || qn;
    trail.push({ label: leaf, href: '?node=' + encodeURIComponent(qn), title: qn });
  }
  trail.push({ label: 'decision @ step ' + (startSeq ?? '?') });
  crumbs(trail);

  content.appendChild(el('h2', '',
    'Decision at step ' + (startSeq ?? '?') + ': ' +
    displayName(qn, data.file_path)));
  content.appendChild(decisionSummary(data));
  renderCompare(content, data, branchId);
}

// --- decision ledger (filter-aware) ---------------------------------------
function ledgerRowVisible(r) {
  if (!kindOk(r.kind)) return false;
  if (!authorOk(r.author)) return false;
  if (filters.finding) {
    const hit = (r.qualified_name && findingSymbols.has(r.qualified_name)) ||
      (!r.qualified_name && findingFiles.has(r.file_path));
    if (!hit) return false;
  }
  return true;
}

function ledgerCard(r) {
  const d = el('div', 'step');
  const head = el('div', 'head');
  const dot = authorDot(r.author);
  if (dot) head.appendChild(dot);
  head.appendChild(el('span', 'seq', 'step#' + (r.seq ?? '?')));
  head.appendChild(el('span', '', r.step_id));
  head.appendChild(tag(r.kind + (r.superseded_by_seq != null ?
    ' - superseded by step ' + r.superseded_by_seq : ''), r.kind));
  if (r.important) head.appendChild(tag('decision', 'decision'));
  d.appendChild(head);
  const where = el('div', 'muted', (r.file_path || '') + ' :: ' +
    (r.qualified_name ? displayName(r.qualified_name, r.file_path) : '(file-level)'));
  where.appendChild(structureLink(r.qualified_name || r.file_path || ''));
  d.appendChild(where);
  if (r.reasoning_text) d.appendChild(el('pre', 'reason', r.reasoning_text));
  if (r.abandoned_content) d.appendChild(el('pre', 'code', r.abandoned_content));
  if (r.kind !== 'survived') {
    const zoom = el('button', 'rollback', 'Zoom into this decision');
    zoom.addEventListener('click', () => { location.search = '?branch=' + r.branch_id; });
    d.appendChild(zoom);
  }
  return d;
}

function renderLedger() {
  const host = document.getElementById('ledger');
  if (!host) return;
  host.textContent = '';
  const rows = branchRows.filter(ledgerRowVisible)
    .slice().sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0) || a.branch_id - b.branch_id);
  const head = el('h2', '', 'Decision ledger (' + rows.length + ' of ' +
    branchRows.length + ' row(s))');
  host.appendChild(head);
  if (!branchRows.length) {
    host.appendChild(el('div', 'muted',
      "No branch rows. Run 'codegraph-trace branches derive' first."));
    return;
  }
  // The tree is the primary view; the full ledger is opt-in detail everywhere
  // except the step view, which is already scoped to one step.
  const expanded = ledgerOpen || currentView === 'step';
  if (currentView !== 'step') {
    const toggle = el('button', 'chip' + (ledgerOpen ? ' active' : ''),
      ledgerOpen ? 'Hide' : 'Show all');
    toggle.style.marginLeft = '.6rem';
    toggle.addEventListener('click', () => { ledgerOpen = !ledgerOpen; renderLedger(); });
    head.appendChild(toggle);
  }
  if (!expanded) return;
  for (const r of rows) host.appendChild(ledgerCard(r));
}

// --- shared scaffolding for the timeline/detail/decision sections ----------
function addTimelineSections(content) {
  const strip = el('div', 'timeline'); strip.id = 'timeline';
  content.appendChild(strip);
  const detail = el('div', ''); detail.id = 'detail';
  content.appendChild(detail);
}

function addDecisionSections(content) {
  content.appendChild(el('h2', '', 'Decision view'));
  const decision = el('div', ''); decision.id = 'decision';
  content.appendChild(decision);
  // On-demand detail for one step or one branch; placeholder until a tree click.
  const detail = el('div', ''); detail.id = 'decision-detail';
  detail.appendChild(el('div', 'muted',
    'Click a step or a branch in the tree to see its reasoning, code, and ledger entry.'));
  content.appendChild(detail);
  const ledger = el('div', ''); ledger.id = 'ledger';
  content.appendChild(ledger);
}

// Color legend for the decision tree: what each dot and line means, in place
// of a prose explainer.
function treeLegend() {
  const legend = el('div', 'tree-legend');
  const dotKey = (color, txt) => {
    const k = el('span', 'k');
    const s = el('span', 'sw'); s.style.background = color; k.appendChild(s);
    k.appendChild(document.createTextNode(txt));
    return k;
  };
  const lineKey = (color, txt, dashed) => {
    const k = el('span', 'k');
    const s = el('span', 'ln' + (dashed ? ' dash' : ''));
    s.style.borderTopColor = color; k.appendChild(s);
    k.appendChild(document.createTextNode(txt));
    return k;
  };
  legend.appendChild(dotKey('#4ec9b0', 'step on the surviving path'));
  legend.appendChild(dotKey('#c586c0', 'decision point'));
  legend.appendChild(dotKey('#dcdcaa', 'human-written step'));
  legend.appendChild(lineKey('#f14c4c', 'abandoned / error retry', true));
  legend.appendChild(lineKey('#dcdcaa', 'revised attempt', true));
  legend.appendChild(lineKey('#9cdcfe', 'merged development branch'));
  return legend;
}

// --- dual landing: Decision tree | Code structure as equal peers -----------
function landingUrl(tab) {
  const q = new URLSearchParams();
  if (tab === 'structure') q.set('view', 'structure');
  if (focusParam) q.set('focus', focusParam);
  const s = q.toString();
  return s ? ('?' + s) : '?';
}

async function repoLanding(content) {
  currentView = 'repo';
  crumbs([]);
  let activeTab = viewParam; // 'decisions' | 'structure'

  const tabs = el('div', 'landing-tabs');
  const pane = el('div', '');
  pane.id = 'landing-pane';
  content.appendChild(tabs);
  content.appendChild(pane);

  const rebuildTabs = () => {
    tabs.textContent = '';
    for (const [id, label] of [['decisions', 'Decision tree'],
                               ['structure', 'Code structure']]) {
      const b = el('button', 'landing-tab' + (activeTab === id ? ' active' : ''), label);
      b.addEventListener('click', () => {
        if (activeTab === id) return;
        activeTab = id;
        history.replaceState(null, '', landingUrl(id));
        rebuildTabs();
        showTab();
      });
      tabs.appendChild(b);
    }
  };

  const showTab = async () => {
    pane.textContent = '';
    extraRender = [];
    touchSeqs = new Set();
    entryBySeq = new Map();
    importantSeqs = new Set();
    selectedSeq = null;
    branchRows = [];
    versions = [];
    lineageData = [];
    activeLineageId = 'main';
    if (activeTab === 'structure') await renderStructureTab(pane);
    else await renderDecisionsTab(pane);
  };

  rebuildTabs();
  await showTab();
}

async function renderDecisionsTab(host) {
  await loadFindings();
  const [ver, files, br] = await Promise.all([
    (await fetch('api/versions')).json(),
    (await fetch('api/files')).json(),
    (await fetch('api/branches')).json(),
  ]);
  versions = ver.versions || [];
  branchRows = br.rows || [];
  lineageData = ver.lineages || [];
  activeLineageId = ver.lineage_id || 'main';
  for (const v of versions) {
    if (v.important) importantSeqs.add(v.seq);
    // Repo scope: the whole repository is the target, so every step sits on
    // the main path and repo-wide branch rows hang off it.
    touchSeqs.add(v.seq);
  }

  const laneCount = lineageData.filter(l => l.lineage_id !== 'main' &&
    l.lineage_id !== activeLineageId).length;
  host.appendChild(el('h2', '', 'Repository decision tree (' + versions.length +
    ' recorded step(s)' + (laneCount ? ', ' + laneCount + ' development branch(es)' : '') +
    ')'));
  host.appendChild(treeLegend());
  // Explicit lineage legend — the tree is wide; without this the fork is easy to miss.
  const devLanes = lineageData.filter(l => l.lineage_id !== 'main' &&
    l.lineage_id !== activeLineageId);
  if (devLanes.length) {
    const legend = el('div', 'chips');
    legend.appendChild(el('span', 'label', 'development branches:'));
    for (const l of devLanes) {
      const label = l.lineage_id + (l.status === 'merged' ?
        ' (merged @ v' + (l.base_seq ?? '?') + ')' :
        ' (open / locked @ v' + (l.base_seq ?? '?') + ')');
      legend.appendChild(tag(label, 'lineage'));
    }
    host.appendChild(legend);
  }
  filterBar(host, { author: true, kind: true, finding: true });
  addDecisionSections(host);
  addTimelineSections(host);

  const fileRows = files.files || [];
  host.appendChild(el('h2', '', 'Recorded files (' + fileRows.length + ')'));
  const filesHost = el('div', '');
  host.appendChild(filesHost);
  const renderFiles = () => {
    filesHost.textContent = '';
    for (const f of fileRows) {
      if (filters.finding && !findingFiles.has(f.file_path)) continue;
      const card = el('div', 'step filecard');
      const head = el('div', 'head');
      head.appendChild(el('span', 'seq', f.file_path));
      if (f.decision_step_count) {
        head.appendChild(tag(f.decision_step_count + ' decision step(s)', 'decision'));
      }
      const bk = f.branch_kinds || {};
      if (bk.abandoned) head.appendChild(tag(bk.abandoned + ' abandoned', 'abandoned'));
      if (bk.revised) head.appendChild(tag(bk.revised + ' revised', 'revised'));
      if (bk.error_retry) head.appendChild(tag(bk.error_retry + ' error retr(ies)', 'error_retry'));
      if (findingFiles.has(f.file_path)) {
        head.appendChild(el('span', 'badge',
          findingFiles.get(f.file_path) + ' semgrep finding(s)'));
      }
      card.appendChild(head);
      card.appendChild(el('div', 'muted',
        f.touch_count + ' step(s), ' + f.symbol_count + ' symbol(s) - click to zoom in'));
      card.addEventListener('click', () => {
        location.search = '?file=' + encodeURIComponent(f.file_path);
      });
      filesHost.appendChild(card);
    }
  };
  renderFiles();
  extraRender.push(renderFiles);

  renderDecisionView();
  renderLedger();
  renderTimeline();
  if (versions.length) selectStep(versions[versions.length - 1].seq);
}

async function renderStructureTab(host) {
  const data = await (await fetch('api/structure')).json();
  if (data.error) {
    host.appendChild(el('h2', '', 'Code structure'));
    host.appendChild(el('div', 'muted', data.error));
    return;
  }
  const allFiles = data.files || [];
  const edges = data.edges || [];
  const repoName = data.repo || 'repository';
  host.appendChild(el('h2', '', 'Code structure (' + allFiles.length +
    ' file(s), ' + edges.length + ' relationship(s))'));

  let recordedOnly = false;
  let layout = 'graph';   // 'graph' (fcose, default) | 'radial'
  const bar = el('div', 'chips');
  bar.appendChild(el('span', 'label', 'layout:'));
  const layoutChips = [];
  const addLayoutChip = (id, label) => {
    const c = el('button', 'chip' + (layout === id ? ' active' : ''), label);
    c.addEventListener('click', () => {
      if (layout === id) return;
      layout = id;
      for (const other of layoutChips) other.classList.remove('active');
      c.classList.add('active');
      render();
    });
    layoutChips.push(c);
    bar.appendChild(c);
  };
  addLayoutChip('graph', 'graph');
  addLayoutChip('radial', 'radial tree');
  bar.appendChild(el('span', 'label', 'show:'));
  const chip = el('button', 'chip', 'recorded only');
  chip.addEventListener('click', () => {
    recordedOnly = !recordedOnly;
    chip.classList.toggle('active', recordedOnly);
    render();
  });
  bar.appendChild(chip);
  host.appendChild(bar);

  const render = () => (layout === 'graph' ? drawGraph() : drawRadial());

  const drawHost = el('div', '');
  host.appendChild(drawHost);
  const detailHost = el('div', 'struct-detail');
  host.appendChild(detailHost);
  const leaf = qn => qn.split('.').slice(-1)[0] || qn;

  const showSymbolActions = (filePath, sym) => {
    detailHost.textContent = '';
    const name = displayName(sym.qualified_name, filePath);
    detailHost.appendChild(el('h3', '', name + ' [' + sym.label + ']'));
    detailHost.appendChild(el('div', 'muted', filePath +
      (sym.start_line ? ' :' + sym.start_line : '')));
    const actions = el('div', 'struct-actions');
    actions.appendChild(openToViewButton(filePath, sym.qualified_name, detailHost));
    const hist = el('button', 'rollback', 'Decision history');
    hist.title = 'Open the recorded decision history for this symbol';
    hist.addEventListener('click', () => {
      let qs = '?node=' + encodeURIComponent(sym.qualified_name) +
        '&file=' + encodeURIComponent(filePath);
      if (sym.start_line) qs += '&start_line=' + encodeURIComponent(sym.start_line);
      location.search = qs;
    });
    actions.appendChild(hist);
    detailHost.appendChild(actions);
    detailHost.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  };

  // --- radial phylogenetic tree: repo core -> files -> symbol leaves ---------
  const drawRadial = () => {
    drawHost.textContent = '';
    detailHost.textContent = '';
    const files = allFiles.filter(f => !recordedOnly || f.recorded);
    if (!files.length) {
      drawHost.appendChild(el('div', 'muted', recordedOnly ?
        'No files with recorded history.' : 'The code graph lists no files.'));
      return;
    }
    // Order files for a stable, readable fan (path-sorted).
    const ordered = files.slice().sort((a, b) =>
      a.file_path < b.file_path ? -1 : a.file_path > b.file_path ? 1 : 0);

    // Angular layout: every symbol (or an empty file) gets one leaf slot; a file
    // spans its symbols and sits at the mean angle of its own leaves.
    let totalLeaves = 0;
    for (const f of ordered) totalLeaves += Math.max(1, f.symbols.length);
    const gapFrac = 0.16;              // breathing room between file sectors
    const step = (2 * Math.PI * (1 - gapFrac)) / Math.max(1, totalLeaves);
    const fileGap = (2 * Math.PI * gapFrac) / Math.max(1, ordered.length);

    const rFile = Math.max(150, totalLeaves * 5.0);
    const rLeaf = rFile * 2.15;
    // The layout radius grows with the symbol count, but the SVG is always scaled to
    // fit the viewport - so stroke widths, node radii, and font sizes must grow with
    // it too, or a large trace degenerates into invisible hairlines and unreadable
    // labels (everything looks like disconnected dots). scale = 1 for small repos.
    const scale = Math.max(1, rLeaf / 340);
    const posByQn = new Map();         // symbol qn -> {x,y,a}
    const fileNodes = [];
    let a = -Math.PI / 2;              // start at top
    const polar = (r, ang) => ({ x: Math.cos(ang) * r, y: Math.sin(ang) * r });
    for (const f of ordered) {
      const nLeaf = Math.max(1, f.symbols.length);
      const a0 = a + fileGap / 2;
      const leafAngles = [];
      for (let i = 0; i < nLeaf; i++) leafAngles.push(a0 + step * (i + 0.5));
      const aMid = (leafAngles[0] + leafAngles[leafAngles.length - 1]) / 2;
      const fp = polar(rFile, aMid);
      const fileNode = { f, a: aMid, x: fp.x, y: fp.y, leaves: [] };
      f.symbols.forEach((s, i) => {
        const ang = leafAngles[i] != null ? leafAngles[i] : aMid;
        const lp = polar(rLeaf, ang);
        const rec = { s, a: ang, x: lp.x, y: lp.y };
        posByQn.set(s.qualified_name, rec);
        fileNode.leaves.push(rec);
      });
      fileNodes.push(fileNode);
      a = a0 + step * nLeaf + fileGap / 2;
    }

    // Radial diagonal link (classic dendrogram bend): parent radius/angle ->
    // child radius/angle with two controls at the midpoint radius.
    const radialLink = (r0, a0, r1, a1) => {
      const rc = (r0 + r1) / 2;
      const p0 = polar(r0, a0), p1 = polar(r1, a1);
      const c0 = polar(rc, a0), c1 = polar(rc, a1);
      return 'M ' + p0.x + ' ' + p0.y + ' C ' + c0.x + ' ' + c0.y + ', ' +
        c1.x + ' ' + c1.y + ', ' + p1.x + ' ' + p1.y;
    };

    // Canvas bounds (labels sit past the leaf ring, so pad proportionally).
    const span = rLeaf + 90 * scale;
    const vbInit = { x: -span, y: -span, w: span * 2, h: span * 2 };
    let vb = { x: vbInit.x, y: vbInit.y, w: vbInit.w, h: vbInit.h };
    const svg = svgEl('svg', { class: 'radial-svg', width: '100%', height: '100%',
      viewBox: vb.x + ' ' + vb.y + ' ' + vb.w + ' ' + vb.h });
    const applyVb = () => svg.setAttribute('viewBox',
      vb.x + ' ' + vb.y + ' ' + vb.w + ' ' + vb.h);

    const defs = svgEl('defs');
    const filter = svgEl('filter', { id: 'coreGlow', x: '-120%', y: '-120%',
      width: '340%', height: '340%' });
    const blur = svgEl('feGaussianBlur', { in: 'SourceGraphic',
      stdDeviation: String(5 * scale) });
    filter.appendChild(blur);
    defs.appendChild(filter);
    svg.appendChild(defs);

    const gRel = svgEl('g', {});      // cross-file relationship arcs (under)
    const gLink = svgEl('g', {});     // green containment links
    const gNode = svgEl('g', {});     // nodes + labels (over)
    svg.appendChild(gRel);
    svg.appendChild(gLink);
    svg.appendChild(gNode);

    // Cross-file relationship arcs (bowed toward the core, like gene transfer).
    // Anchor to the symbol leaf when known, else fall back to the file node so a
    // relationship whose endpoint is file-level (or an unlisted symbol) still shows.
    const fileAnchorByPath = new Map();
    for (const fn of fileNodes) fileAnchorByPath.set(fn.f.file_path, fn);
    const relAnchor = (qn, fp) => posByQn.get(qn) || fileAnchorByPath.get(fp);
    let relCount = 0;
    for (const e of edges) {
      if (e.source_file === e.target_file) continue;
      const p = relAnchor(e.source_qn, e.source_file);
      const q = relAnchor(e.target_qn, e.target_file);
      if (!p || !q) continue;
      const mx = (p.x + q.x) / 2, my = (p.y + q.y) / 2;
      const ctrl = { x: mx * 0.35, y: my * 0.35 };   // pull toward center
      const d = 'M ' + p.x + ' ' + p.y + ' Q ' + ctrl.x + ' ' + ctrl.y +
        ' ' + q.x + ' ' + q.y;
      const path = svgEl('path', { class: 'r-rel', d: d,
        style: 'stroke-width:' + (1 * scale) + 'px;' +
          'stroke-dasharray:' + (3 * scale) + ' ' + (4 * scale) });
      const tt = svgEl('title');
      tt.textContent = displayName(e.source_qn, e.source_file) + ' -> ' +
        displayName(e.target_qn, e.target_file) + ' [' + e.type + ']';
      path.appendChild(tt);
      gRel.appendChild(path);
      relCount++;
    }

    // Containment links: core -> file, file -> each symbol leaf.
    for (const fn of fileNodes) {
      gLink.appendChild(svgEl('path', { class: 'r-link root',
        d: radialLink(0, fn.a, rFile, fn.a),
        style: 'stroke-width:' + (1.7 * scale) + 'px' }));
      for (const lf of fn.leaves) {
        gLink.appendChild(svgEl('path', { class: 'r-link',
          d: radialLink(rFile, fn.a, rLeaf, lf.a),
          style: 'stroke-width:' + (1.3 * scale) + 'px' }));
      }
    }

    // Glowing repo core, named after the indexed project.
    gNode.appendChild(svgEl('circle', { class: 'r-core-ring', cx: 0, cy: 0,
      r: 20 * scale, style: 'stroke-width:' + (1.5 * scale) + 'px' }));
    const core = svgEl('circle', { class: 'r-core', cx: 0, cy: 0, r: 11 * scale });
    const coreTitle = svgEl('title');
    coreTitle.textContent = repoName + ' - ' + ordered.length + ' file(s)';
    core.appendChild(coreTitle);
    gNode.appendChild(core);
    const coreLbl = svgEl('text', { class: 'r-lbl r-core-lbl', x: 0, y: 38 * scale,
      'text-anchor': 'middle', 'dominant-baseline': 'hanging',
      style: 'font-size:' + (12 * scale) + 'px' });
    coreLbl.textContent = repoName;
    gNode.appendChild(coreLbl);

    const labelForAngle = (g, txt, r, ang, cls, fontPx) => {
      const p = polar(r, ang);
      let deg = ang * 180 / Math.PI;
      let anchor = 'start';
      let rot = deg;
      if (deg > 90 || deg < -90) { rot = deg + 180; anchor = 'end'; }
      const t = svgEl('text', { class: 'r-lbl' + (cls ? ' ' + cls : ''),
        x: p.x, y: p.y, 'text-anchor': anchor, 'dominant-baseline': 'middle',
        transform: 'rotate(' + rot + ' ' + p.x + ' ' + p.y + ')',
        style: 'font-size:' + fontPx + 'px' });
      t.textContent = txt;
      g.appendChild(t);
      return t;
    };

    // File nodes + labels.
    const showSymLabels = totalLeaves <= 140;
    for (const fn of fileNodes) {
      const f = fn.f;
      let fileCls = 'r-node file' + (f.decision ? ' decision' : '');
      if (reviewFiles.has(f.file_path)) fileCls += ' review';
      const c = svgEl('circle', { class: fileCls, cx: fn.x, cy: fn.y,
        r: (f.recorded ? 6.5 : 5) * scale,
        style: 'stroke-width:' + (1.2 * scale) + 'px' });
      const tt = svgEl('title');
      tt.textContent = f.file_path + (f.recorded ?
        ' - ' + f.touch_count + ' recorded step(s)' : ' - no recorded steps') +
        (f.decision ? ', has decisions' : '');
      c.appendChild(tt);
      c.addEventListener('click', () => {
        const unit = reviewUnitFor('file', f.file_path);
        if (unit) return openDiffPanel(unit);
        location.search = '?file=' + encodeURIComponent(f.file_path);
      });
      gNode.appendChild(c);
      labelForAngle(gNode, truncLabel(f.file_path.split('/').slice(-1)[0], 22),
        rFile - 12 * scale, fn.a, 'file', 10.5 * scale);

      for (const lf of fn.leaves) {
        const s = lf.s;
        let cls = 'r-node ' + (s.decision ? 'decision' :
          (s.recorded ? 'recorded' : 'plain'));
        if (reviewQns.has(s.qualified_name)) cls += ' review';
        const dot = svgEl('circle', { class: cls, cx: lf.x, cy: lf.y,
          r: (s.decision ? 4.5 : (s.recorded ? 4 : 3)) * scale });
        const st = svgEl('title');
        st.textContent = displayName(s.qualified_name, f.file_path) + ' [' + s.label + ']' +
          (s.recorded ? ' - ' + s.touch_count + ' recorded step(s)' :
            ' - no recorded steps') + (s.decision ? ', has decisions' : '');
        dot.appendChild(st);
        dot.addEventListener('click', () => {
          const unit = reviewUnitFor('qn', s.qualified_name);
          if (unit) return openDiffPanel(unit);
          showSymbolActions(f.file_path, s);
        });
        gNode.appendChild(dot);
        if (showSymLabels) {
          labelForAngle(gNode, truncLabel(leaf(s.qualified_name), 22),
            rLeaf + 9 * scale, lf.a, s.decision ? 'decision' : '', 9 * scale);
        }
      }
    }

    const viewport = el('div', 'struct-viewport');
    viewport.appendChild(svg);
    drawHost.appendChild(viewport);

    // Legend + hint.
    const legend = el('div', 'radial-legend');
    const key = (color, txt) => {
      const k = el('span', 'k');
      const d = el('span', 'dot'); d.style.background = color; k.appendChild(d);
      k.appendChild(document.createTextNode(txt));
      return k;
    };
    legend.appendChild(el('span', '', 'core = repo'));
    legend.appendChild(key('#4ec9b0', 'file / recorded symbol'));
    legend.appendChild(key('#c586c0', 'carries a decision'));
    legend.appendChild(key('#6b7784', 'no recorded history'));
    legend.appendChild(key('#35c491', 'green = contains'));
    legend.appendChild(key('#7aa2ff', 'blue = cross-file relationship'));
    drawHost.appendChild(legend);

    // Pan / zoom (same viewBox model as the box view).
    let panning = false, panLast = null;
    const clientToSvg = (cx, cy) => {
      const rect = svg.getBoundingClientRect();
      return {
        x: vb.x + ((cx - rect.left) / rect.width) * vb.w,
        y: vb.y + ((cy - rect.top) / rect.height) * vb.h
      };
    };
    svg.addEventListener('wheel', (ev) => {
      ev.preventDefault();
      const factor = ev.deltaY < 0 ? 0.9 : 1.11;
      const nextW = Math.min(vbInit.w * 4, Math.max(vbInit.w * 0.15, vb.w * factor));
      const nextH = nextW * (vb.h / vb.w);
      const pt = clientToSvg(ev.clientX, ev.clientY);
      const sx = (pt.x - vb.x) / vb.w, sy = (pt.y - vb.y) / vb.h;
      vb = { x: pt.x - sx * nextW, y: pt.y - sy * nextH, w: nextW, h: nextH };
      applyVb();
    }, { passive: false });
    svg.addEventListener('pointerdown', (ev) => {
      if (ev.target.closest('.r-node')) return;
      panning = true; panLast = { x: ev.clientX, y: ev.clientY };
      svg.classList.add('panning');
      svg.setPointerCapture(ev.pointerId);
    });
    svg.addEventListener('pointermove', (ev) => {
      if (!panning || !panLast) return;
      const rect = svg.getBoundingClientRect();
      vb.x -= ((ev.clientX - panLast.x) / rect.width) * vb.w;
      vb.y -= ((ev.clientY - panLast.y) / rect.height) * vb.h;
      panLast = { x: ev.clientX, y: ev.clientY };
      applyVb();
    });
    const endPan = (ev) => {
      if (!panning) return;
      panning = false; panLast = null;
      svg.classList.remove('panning');
      try { svg.releasePointerCapture(ev.pointerId); } catch (err) {}
    };
    svg.addEventListener('pointerup', endPan);
    svg.addEventListener('pointercancel', endPan);
  };

  // --- default layout: self-shaping force graph (Cytoscape.js + fCoSE) -------
  // Files are compound containers, symbols nest inside them, cross-file
  // relationships pull related files together. The layout adapts to any
  // graph size instead of forcing a fixed ring, so dense repos stay readable.
  const drawGraph = async () => {
    drawHost.textContent = '';
    detailHost.textContent = '';
    const files = allFiles.filter(f => !recordedOnly || f.recorded);
    if (!files.length) {
      drawHost.appendChild(el('div', 'muted', recordedOnly ?
        'No files with recorded history.' : 'The code graph lists no files.'));
      return;
    }
    const viewport = el('div', 'struct-viewport');
    drawHost.appendChild(viewport);
    const loading = el('div', 'muted', 'Laying out the graph\\u2026');
    drawHost.appendChild(loading);
    try {
      await loadGraphLibs();
    } catch (err) {
      loading.textContent = 'The graph layout library could not be loaded ' +
        '(no network?). Showing the radial tree instead.';
      drawHost.removeChild(viewport);
      drawRadial();
      return;
    }
    loading.remove();

    const kindColor = (label) => GRAPH_KIND_COLORS[label] || GRAPH_KIND_COLORS.other;
    const elements = [];
    const symbolIds = new Set();
    for (const f of files) {
      elements.push({ data: { id: 'f:' + f.file_path, kind: 'file',
        label: f.file_path.split('/').slice(-1)[0], path: f.file_path,
        decision: f.decision ? 1 : 0,
        review: reviewFiles.has(f.file_path) ? 1 : 0 } });
      for (const s of f.symbols) {
        symbolIds.add(s.qualified_name);
        elements.push({ data: { id: 's:' + s.qualified_name,
          parent: 'f:' + f.file_path, kind: s.label || 'other',
          label: leaf(s.qualified_name), qn: s.qualified_name,
          path: f.file_path, decision: s.decision ? 1 : 0,
          recorded: s.recorded ? 1 : 0,
          review: reviewQns.has(s.qualified_name) ? 1 : 0 } });
      }
    }
    const shownFiles = new Set(files.map(f => f.file_path));
    const seenEdge = new Set();
    edges.forEach((e, i) => {
      if (!shownFiles.has(e.source_file) || !shownFiles.has(e.target_file)) return;
      const src = symbolIds.has(e.source_qn) ? 's:' + e.source_qn : 'f:' + e.source_file;
      const tgt = symbolIds.has(e.target_qn) ? 's:' + e.target_qn : 'f:' + e.target_file;
      if (src === tgt) return;
      const k = src + '\\u0000' + tgt + '\\u0000' + e.type;
      if (seenEdge.has(k)) return;
      seenEdge.add(k);
      elements.push({ data: { id: 'e' + i, source: src, target: tgt,
        type: e.type, cross: e.source_file !== e.target_file ? 1 : 0 } });
    });

    const cy = window.cytoscape({
      container: viewport,
      elements: elements,
      wheelSensitivity: 0.2,
      style: [
        { selector: 'node[kind = "file"]', style: {
          'shape': 'round-rectangle',
          'background-color': '#7aa2ff', 'background-opacity': 0.07,
          'border-color': '#7aa2ff', 'border-width': 1.2, 'border-opacity': 0.55,
          'label': 'data(label)', 'color': '#9cdcfe', 'font-size': 12,
          'text-valign': 'top', 'text-halign': 'center',
          'text-margin-y': -4, 'padding': 14 } },
        { selector: 'node[kind = "file"][decision = 1]', style: {
          'border-color': '#c586c0', 'border-width': 2 } },
        { selector: 'node[kind != "file"]', style: {
          'width': 16, 'height': 16,
          'background-color': (n) => kindColor(n.data('kind')),
          'label': 'data(label)', 'color': '#c9c9c9', 'font-size': 9,
          'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 3,
          'text-max-width': 84, 'text-wrap': 'ellipsis',
          'border-width': 0 } },
        { selector: 'node[kind != "file"][recorded = 0]', style: {
          'background-opacity': 0.35, 'color': '#777' } },
        { selector: 'node[kind != "file"][decision = 1]', style: {
          'border-width': 2.5, 'border-color': '#c586c0', 'width': 19,
          'height': 19 } },
        // The entities an incoming change touched (see /api/review).
        { selector: 'node[review = 1]', style: {
          'border-width': 3, 'border-color': '#ffd166',
          'underlay-color': '#ffd166', 'underlay-opacity': 0.28,
          'underlay-padding': 8 } },
        { selector: 'node[kind = "file"][review = 1]', style: {
          'border-color': '#ffd166', 'border-width': 2.5,
          'background-color': '#ffd166', 'background-opacity': 0.10 } },
        { selector: 'edge', style: {
          'width': 1.4, 'line-color': '#7aa2ff', 'line-opacity': 0.45,
          'curve-style': 'bezier', 'target-arrow-shape': 'triangle',
          'target-arrow-color': '#7aa2ff', 'arrow-scale': 0.7 } },
        { selector: 'edge[cross = 0]', style: {
          'line-color': '#6b7784', 'target-arrow-color': '#6b7784',
          'line-opacity': 0.4 } },
      ],
      layout: { name: 'fcose', quality: 'default', animate: false,
        randomize: true, nodeRepulsion: 9000, idealEdgeLength: 90,
        nodeSeparation: 130, tile: true, packComponents: false,
        tilingPaddingVertical: 26, tilingPaddingHorizontal: 78 },
    });
    cy.on('tap', 'node', (ev) => {
      const d = ev.target.data();
      if (d.kind === 'file') {
        const unit = reviewUnitFor('file', d.path);
        if (unit) return openDiffPanel(unit);
        location.search = '?file=' + encodeURIComponent(d.path);
        return;
      }
      const byQn = reviewUnitFor('qn', d.qn);
      if (byQn) return openDiffPanel(byQn);
      const f = files.find(x => x.file_path === d.path);
      const s = f && f.symbols.find(x => x.qualified_name === d.qn);
      if (s) showSymbolActions(d.path, s);
    });

    // Deep link (?focus=): zoom to the focused symbol or file and open it.
    if (focusParam) {
      const target = cy.getElementById('s:' + focusParam).length ?
        cy.getElementById('s:' + focusParam) : cy.getElementById('f:' + focusParam);
      if (target.length) {
        cy.animate({ fit: { eles: target.closedNeighborhood(), padding: 80 } },
          { duration: 250 });
        const d = target.data();
        if (d.kind !== 'file') {
          const f = files.find(x => x.file_path === d.path);
          const s = f && f.symbols.find(x => x.qualified_name === d.qn);
          if (s) showSymbolActions(d.path, s);
        }
      }
    }

    const legend = el('div', 'radial-legend');
    const key = (color, txt) => {
      const k = el('span', 'k');
      const d = el('span', 'dot'); d.style.background = color; k.appendChild(d);
      k.appendChild(document.createTextNode(txt));
      return k;
    };
    legend.appendChild(key('#7aa2ff', 'file (container)'));
    legend.appendChild(key(GRAPH_KIND_COLORS.Function, 'function'));
    legend.appendChild(key(GRAPH_KIND_COLORS.Class, 'class'));
    legend.appendChild(key(GRAPH_KIND_COLORS.Method, 'method'));
    legend.appendChild(key(GRAPH_KIND_COLORS.other, 'other symbol'));
    legend.appendChild(key('#c586c0', 'purple ring = carries a decision'));
    drawHost.appendChild(legend);
  };

  render();
}

// Symbol-kind palette for the force-graph structure view.
const GRAPH_KIND_COLORS = {
  Function: '#35c491', Class: '#c586c0', Method: '#e0a86b',
  Interface: '#e0a86b', Struct: '#c586c0', Enum: '#c586c0',
  Variable: '#9cdcfe', Constant: '#9cdcfe', Property: '#9cdcfe',
  other: '#8894a3',
};

// Cytoscape.js + fCoSE, loaded once from a CDN on first use of the graph layout.
let _graphLibsPromise = null;
function loadGraphLibs() {
  if (window.cytoscape && window.cytoscape.__fcose) return Promise.resolve();
  if (_graphLibsPromise) return _graphLibsPromise;
  const addScript = (src) => new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error('failed to load ' + src));
    document.head.appendChild(s);
  });
  _graphLibsPromise = (async () => {
    await addScript('https://cdn.jsdelivr.net/npm/cytoscape@3.30.4/dist/cytoscape.min.js');
    await addScript('https://cdn.jsdelivr.net/npm/layout-base@2.0.1/layout-base.js');
    await addScript('https://cdn.jsdelivr.net/npm/cose-base@2.2.0/cose-base.js');
    await addScript('https://cdn.jsdelivr.net/npm/cytoscape-fcose@2.2.0/cytoscape-fcose.js');
    window.cytoscape.use(window.cytoscapeFcose);
    window.cytoscape.__fcose = true;
  })();
  _graphLibsPromise.catch(() => { _graphLibsPromise = null; });
  return _graphLibsPromise;
}

// --- file / symbol views: the spine for one target -------------------------
async function targetView(content, isSymbol) {
  currentView = isSymbol ? 'symbol' : 'file';
  await loadFindings();
  const fileHint = (isSymbol && fileParam) ? fileParam : '';
  const lineHint = (isSymbol && startLineParam) ? startLineParam : '';
  const histQs = 'api/history?target=' + encodeURIComponent(target) +
    (fileHint ? '&file=' + encodeURIComponent(fileHint) : '') +
    (lineHint ? '&start_line=' + encodeURIComponent(lineHint) : '');
  const brQs = 'api/branches?target=' + encodeURIComponent(target) +
    (fileHint ? '&file=' + encodeURIComponent(fileHint) : '') +
    (lineHint ? '&start_line=' + encodeURIComponent(lineHint) : '');
  const [ver, hist, br] = await Promise.all([
    (await fetch('api/versions')).json(),
    (await fetch(histQs)).json(),
    (await fetch(brQs)).json(),
  ]);
  versions = ver.versions || [];
  branchRows = br.rows || [];
  const resolvedQn = hist.resolved_qualified_name || nodeParam;
  historyResolvedQn = resolvedQn || '';
  for (const v of versions) if (v.important) importantSeqs.add(v.seq);
  for (const e of (hist.entries || [])) {
    if (e.seq != null) { entryBySeq.set(e.seq, e); touchSeqs.add(e.seq); }
  }

  if (isSymbol) {
    for (const e of entryBySeq.values()) {
      const n = (e.nodes || []).find(x =>
        x.qualified_name === target || x.qualified_name === resolvedQn);
      if (n && n.file_path) { symbolFile = n.file_path; break; }
    }
    if (!symbolFile && hist.file_path) symbolFile = hist.file_path;
    if (!symbolFile && branchRows.length) symbolFile = branchRows[0].file_path || '';
    if (!symbolFile && fileHint) symbolFile = fileHint;
    const leaf = target.split('.').slice(-1)[0] || target;
    const trail = [{ label: 'repo', href: '?' }];
    if (symbolFile) {
      trail.push({ label: symbolFile, href: '?file=' + encodeURIComponent(symbolFile) });
    }
    trail.push({ label: leaf, title: resolvedQn || target });
    crumbs(trail);
  } else {
    crumbs([{ label: 'repo', href: '?' }, { label: target }]);
  }

  const head2 = el('h2', '', (isSymbol ? 'Symbol: ' : 'File: ') +
    (isSymbol ? displayName(target, symbolFile) : target));
  if (isSymbol) head2.title = resolvedQn || target;
  if (findingSymbols.has(target) || findingSymbols.has(resolvedQn)) {
    const n = findingSymbols.get(target) || findingSymbols.get(resolvedQn);
    head2.appendChild(el('span', 'badge', n + ' semgrep finding(s)'));
  } else if (!isSymbol && findingFiles.has(target)) {
    head2.appendChild(el('span', 'badge', findingFiles.get(target) + ' semgrep finding(s)'));
  }
  content.appendChild(head2);

  // Shared lookup scopes: symbol hit, file fallback, or explicit no-trace empty state.
  if (isSymbol && hist.scope === 'file' && (hist.entries || []).length) {
    content.appendChild(el('div', 'muted',
      'No recorded steps for this symbol; showing file history for ' +
      (hist.file_path || symbolFile || 'this file') + '.'));
  } else if (isSymbol && !(hist.entries || []).length) {
    content.appendChild(el('div', 'muted',
      'No trace data recorded for this symbol.'));
    if (symbolFile) {
      content.appendChild(el('div', 'muted',
        'No file-level history for ' + symbolFile + ' either.'));
    }
    return;
  } else if (!isSymbol && !(hist.entries || []).length) {
    content.appendChild(el('div', 'muted',
      'No trace data recorded for this file.'));
    return;
  }

  if (hist.markers) {
    content.appendChild(el('div', 'markers',
      'introduced at step ' + hist.markers.introduced_at_step +
      ', last changed at step ' + hist.markers.last_changed_at_step +
      ' (' + hist.markers.touch_count + ' touch(es))'));
  }

  filterBar(content, { author: true, kind: true, finding: true });
  addTimelineSections(content);
  addDecisionSections(content);

  // File view: the symbols inside this file, the next zoom level down.
  if (!isSymbol) {
    const data = await (await fetch('api/nodes')).json();
    const inFile = (data.nodes || []).filter(n =>
      n.file_path === target && !(n.qualified_name || '').startsWith('file::'));
    const sec = el('div', '');
    sec.appendChild(el('h2', '', 'Symbols in this file (' + inFile.length + ')'));
    const list = el('div', 'nodes');
    sec.appendChild(list);
    content.appendChild(sec);
    const renderSymbols = () => {
      list.textContent = '';
      for (const n of inFile) {
        if (filters.finding && !findingSymbols.has(n.qualified_name)) continue;
        const line = el('div', '');
        const a = el('a', '', displayName(n.qualified_name, n.file_path) +
          (n.locked ? '  [locked]' : ''));
        a.href = '?node=' + encodeURIComponent(n.qualified_name);
        a.title = n.qualified_name;
        line.appendChild(a);
        if (findingSymbols.has(n.qualified_name)) {
          line.appendChild(el('span', 'badge',
            findingSymbols.get(n.qualified_name) + ' finding(s)'));
        }
        list.appendChild(line);
      }
    };
    renderSymbols();
    extraRender.push(renderSymbols);
  }

  if (!entryBySeq.size) content.appendChild(el('div', 'muted', 'No recorded reasoning.'));

  renderTimeline();
  renderDecisionView();
  renderLedger();
  const touched = Array.from(touchSeqs).sort((a, b) => a - b);
  if (touched.length) selectStep(touched[touched.length - 1]);
  else if (versions.length) selectStep(versions[versions.length - 1].seq);
}

// --- step view: one step, fully expanded ------------------------------------
async function stepView(content, seqStr) {
  currentView = 'step';
  const seq = parseInt(seqStr, 10);
  crumbs([{ label: 'repo', href: '?' }, { label: 'step#' + seqStr }]);
  const data = await (await fetch('api/step?seq=' + seq)).json();
  if (data.error) { content.appendChild(el('div', 'muted', data.error)); return; }
  const s = data.step;

  content.appendChild(el('h2', '', 'Step ' + s.seq + ' - what happened here'));
  const card = el('div', 'step');
  const head = el('div', 'head');
  const sdot = authorDot(s.author);
  if (sdot) head.appendChild(sdot);
  head.appendChild(el('span', 'seq', 'step#' + s.seq));
  head.appendChild(el('span', '', s.step_id));
  head.appendChild(el('span', 'sha', (s.after_sha || '').slice(0, 10) + '  ' + (s.timestamp || '')));
  if (s.important) head.appendChild(tag('decision', 'decision'));
  card.appendChild(head);
  if (s.prompt) {
    const p = el('div', 'muted'); p.textContent = 'prompt: ' + s.prompt; card.appendChild(p);
  }
  if (s.reasoning_text) card.appendChild(el('pre', 'reason', s.reasoning_text));
  card.appendChild(rollbackButton(s.seq));
  content.appendChild(card);

  content.appendChild(el('h2', '', 'Touched nodes (' + (data.nodes || []).length + ')'));
  const list = el('div', 'nodes');
  for (const n of (data.nodes || [])) {
    const line = el('div', '');
    const ndot = authorDot(n.author);
    if (ndot) { line.appendChild(ndot); line.appendChild(document.createTextNode(' ')); }
    const a = el('a', '', displayName(n.qualified_name, n.file_path));
    a.href = '?node=' + encodeURIComponent(n.qualified_name);
    a.title = n.qualified_name;
    line.appendChild(a);
    line.appendChild(el('span', 'muted', '  [' + (n.change_kind || '?') + ']'));
    line.appendChild(structureLink(n.qualified_name));
    if (n.locked) line.appendChild(tag('locked', 'locked'));
    list.appendChild(line);
  }
  content.appendChild(list);

  content.appendChild(el('h2', '', 'Changed files (' + (s.changed_files || []).length + ')'));
  const flist = el('div', 'nodes');
  for (const f of (s.changed_files || [])) {
    const a = el('a', '', f);
    a.href = '?file=' + encodeURIComponent(f);
    flist.appendChild(a);
  }
  content.appendChild(flist);

  branchRows = data.branches || [];
  const ledger = el('div', ''); ledger.id = 'ledger';
  content.appendChild(ledger);
  renderLedger();
}

// --- page assembly ----------------------------------------------------------
async function main() {
  const content = document.getElementById('content');
  await loadReview();
  if (branchParam) return decisionView(content, branchParam);
  if (stepParam) return stepView(content, stepParam);
  if (nodeParam) return targetView(content, true);
  if (fileParam) return targetView(content, false);
  // / and ?view=structure / legacy ?structure= all open the dual landing shell.
  return repoLanding(content);
}
main();
</script>
</body>
</html>
"""


def _optional_int(raw: Optional[str]) -> Optional[int]:
    """Parse a positive query int, or None when missing/invalid."""
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    try:
        value = int(text)
    except ValueError:
        return None
    return value if value > 0 else None


def _versions_payload(config: TraceConfig) -> dict[str, Any]:
    """The lineage-visible step spine with the rule-based decision marker.

    Also carries every registered development lineage so the decision tree can draw
    merged branches as their own lane and open (unmerged) branches as a faint,
    locked fork — one-way visibility means an open lineage's steps are *not* part of
    ``versions``; they ride along here as ``hidden_steps`` for display only.
    """
    with TraceQuery(config, enable_embeddings=False) as q:
        lineage = q.active_lineage()
        important = q.db.important_step_ids(lineage=lineage)
        versions = [
            dict(v.as_dict(), important=(v.step_id in important))
            for v in q.list_versions()
        ]
        lineages: list[dict[str, Any]] = []
        for lin in q.db.list_lineages():
            d: dict[str, Any] = {
                "lineage_id": lin.lineage_id,
                "git_ref": lin.git_ref,
                "base_seq": lin.base_seq,
                "base_step_id": lin.base_step_id,
                "parent_lineage": lin.parent_lineage,
                "status": lin.status,
                "merged_at": lin.merged_at,
            }
            if (
                lin.lineage_id != "main"
                and lin.status == "open"
                and lin.lineage_id != lineage.lineage_id
            ):
                # Steps invisible from the active lineage: shown faint + locked only.
                d["hidden_steps"] = [
                    {
                        "seq": s.get("seq"),
                        "step_id": s.get("step_id"),
                        "author": s.get("author"),
                        "timestamp": s.get("timestamp"),
                    }
                    for s in q.db.steps_for_lineage(lin.lineage_id)
                ]
            lineages.append(d)
    return {
        "versions": versions,
        "important_step_ids": sorted(important),
        "lineage_id": lineage.lineage_id,
        "lineages": lineages,
    }


def _branch_detail_payload(config: TraceConfig, branch_id: int) -> dict[str, Any]:
    """One decision, zoomed in: the abandoned attempt next to the code that won.

    The abandoned side comes straight from the branch row (``abandoned_content`` plus its
    step's prompt/reasoning). The surviving side is enriched at read time: the superseding
    step's file content at ``after_sha``, sliced to the symbol span when the row is
    symbol-level (same AST approach as the derivation in :mod:`codegraph_trace.branches`).
    """
    from . import gitdiff
    from .ast_symbols import extract_symbols, language_for_path
    from .branches import _match_symbol

    with TraceQuery(config, enable_embeddings=False) as q:
        row = q.db.conn.execute(
            """
            SELECT b.*, s.prompt AS prompt, s.reasoning_text AS reasoning_text,
                   s2.seq AS superseded_by_seq, s2.after_sha AS superseding_after_sha,
                   s2.prompt AS superseding_prompt,
                   s2.reasoning_text AS superseding_reasoning
            FROM branches b
            LEFT JOIN steps s ON s.step_id = b.step_id
            LEFT JOIN steps s2 ON s2.step_id = b.superseded_by_step_id
            WHERE b.branch_id = ?
            """,
            (branch_id,),
        ).fetchone()
    if row is None:
        return {"error": f"no branch row with branch_id={branch_id}"}
    row = dict(row)

    abandoned = {
        "content": row.get("abandoned_content"),
        "reasoning_text": row.get("reasoning_text"),
        "prompt": row.get("prompt"),
        "seq": row.get("seq"),
        "step_id": row.get("step_id"),
    }

    surviving = None
    surv_sha = row.get("superseding_after_sha")
    file_path = row.get("file_path") or ""
    if surv_sha:
        content = None
        source = gitdiff.file_at_sha(config.repo_root, surv_sha, file_path)
        if source is not None:
            qn = row.get("qualified_name") or ""
            if qn:
                language = language_for_path(file_path)
                sym = (
                    _match_symbol(extract_symbols(source, language=language), qn)
                    if language
                    else None
                )
                if sym is not None:
                    lines = source.splitlines()
                    content = "\n".join(lines[sym.start_line - 1 : sym.end_line])
            if content is None:
                # File-level row (or the symbol was not found): show the whole winning file.
                content = source
        surviving = {
            "content": content,
            "reasoning_text": row.get("superseding_reasoning"),
            "prompt": row.get("superseding_prompt"),
            "seq": row.get("superseded_by_seq"),
            "step_id": row.get("superseded_by_step_id"),
        }

    return {
        "branch_id": row.get("branch_id"),
        "kind": row.get("kind"),
        "file_path": file_path,
        "qualified_name": row.get("qualified_name") or "",
        "abandoned": abandoned,
        "surviving": surviving,
    }


def _history_payload(
    config: TraceConfig,
    target: str,
    *,
    file_path: Optional[str] = None,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> dict[str, Any]:
    """Shared symbol → file history resolution as JSON (same as ``flag`` / ``history``)."""
    with TraceQuery(config, enable_embeddings=False) as q:
        lineage = q.active_lineage()
        resolved = q.resolve_history(
            target,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
        )
        out = resolved.as_dict()
        out["important_step_ids"] = sorted(q.db.important_step_ids(lineage=lineage))
        out["lineage_id"] = lineage.lineage_id
        return out


def _branches_payload(
    config: TraceConfig,
    target: Optional[str],
    *,
    file_path: Optional[str] = None,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> dict[str, Any]:
    from .query import resolve_story

    with TraceQuery(config, enable_embeddings=False) as q:
        lineage = q.active_lineage()
        if not target:
            rows = q.db.list_branches(target=None, lineage=lineage)
        else:
            rows = resolve_story(
                q.db,
                target,
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                lineage=lineage,
            ).branch_rows
        important = q.db.important_step_ids(lineage=lineage)
    return {
        "rows": [dict(r, important=(r["step_id"] in important)) for r in rows],
        "lineage_id": lineage.lineage_id,
    }


def _files_payload(config: TraceConfig) -> dict[str, Any]:
    """Every recorded file with activity counts - the repo-level zoom of the explorer."""
    with TraceQuery(config, enable_embeddings=False) as q:
        lineage = q.active_lineage()
        important = q.db.important_step_ids(lineage=lineage)
        visible_ids = {s["step_id"] for s in q.db.list_steps(lineage=lineage)}
        files: dict[str, dict[str, Any]] = {}
        for r in q.db.conn.execute(
            """
            SELECT file_path, step_id, qualified_name FROM node_links
            WHERE file_path IS NOT NULL AND file_path != ''
            """
        ).fetchall():
            if r["step_id"] not in visible_ids:
                continue
            if is_trace_path(r["file_path"] or ""):
                continue
            f = files.setdefault(
                r["file_path"],
                {"steps": set(), "symbols": set(), "decision_steps": set()},
            )
            f["steps"].add(r["step_id"])
            qn = r["qualified_name"] or ""
            if qn and not qn.startswith("file::"):
                f["symbols"].add(qn)
            if r["step_id"] in important:
                f["decision_steps"].add(r["step_id"])
        kinds: dict[str, dict[str, int]] = {}
        for r in q.db.list_branches(target=None, lineage=lineage):
            fp = r.get("file_path") or ""
            if is_trace_path(fp):
                continue
            kind = r.get("kind") or ""
            kinds.setdefault(fp, {})
            kinds[fp][kind] = kinds[fp].get(kind, 0) + 1
    out = []
    for fp in sorted(files):
        if is_trace_path(fp):
            continue
        f = files[fp]
        out.append(
            {
                "file_path": fp,
                "touch_count": len(f["steps"]),
                "symbol_count": len(f["symbols"]),
                "decision_step_count": len(f["decision_steps"]),
                "branch_kinds": kinds.get(fp, {}),
            }
        )
    return {"files": out, "lineage_id": lineage.lineage_id}


def _step_payload(config: TraceConfig, seq: int) -> dict[str, Any]:
    """One step fully expanded: the steps row plus every node link and branch row."""
    with TraceQuery(config, enable_embeddings=False) as q:
        from .lineage import step_visible

        row = q.db.get_step_by_seq(seq)
        if row is None:
            return {"error": f"no recorded step with seq={seq}"}
        lineage = q.active_lineage()
        if not step_visible(
            row, lineage, merged_lineage_ids=q.db.merged_lineage_ids()
        ):
            return {"error": f"step seq={seq} is not visible on lineage '{lineage.lineage_id}'"}
        important = q.db.important_step_ids(lineage=lineage)
        step = {
            "step_id": row["step_id"],
            "seq": row.get("seq"),
            "timestamp": row.get("timestamp"),
            "before_sha": row.get("before_sha"),
            "after_sha": row.get("after_sha"),
            "prompt": row.get("prompt") or "",
            "reasoning_text": row.get("reasoning_text") or "",
            "author": row.get("author"),
            "changed_files": [
                f
                for f in (row.get("changed_files") or "").split(",")
                if f and not is_trace_path(f)
            ],
            "important": row["step_id"] in important,
        }
        return {
            "step": step,
            "nodes": [
                n
                for n in q.db.links_for_step(row["step_id"])
                if not is_trace_path(n.get("file_path") or "")
            ],
            "branches": [
                b
                for b in q.db.branches_for_step(row["step_id"])
                if not is_trace_path(b.get("file_path") or "")
            ],
        }


def _review_ledger_path(config: TraceConfig) -> Path:
    from .sync.review import REVIEW_FILENAME

    return config.trace_dir / REVIEW_FILENAME


def _review_viewer() -> dict[str, Any]:
    """Who is looking, from the sync session — the role decides who can judge.

    ``role`` is the entity role the sync service issued at login (``admin`` or
    ``user``); only an admin is offered accept/reject.
    """
    from .sync.state import LocalState

    session = None
    try:
        session = LocalState().load_session()
    except Exception:  # a corrupt or unreadable session is simply "nobody"
        session = None
    username = session.username if session else ""
    role = session.role if session else ""
    return {"username": username, "role": role, "can_decide": role == "admin"}


def _review_payload(config: TraceConfig) -> dict[str, Any]:
    """The change-review surface: what to light up, and the changes behind it.

    Units are created by ``tracer pull`` (see ``sync.review``) and live inside the
    synced tree, so verdicts travel back to the author over the same encrypted path.
    """
    from .sync import review as sync_review

    viewer = _review_viewer()
    ledger = sync_review.read_ledger(_review_ledger_path(config))
    pending = ledger.pending_for(viewer["username"])
    files: list[str] = []
    symbols: list[str] = []
    seqs: set[int] = set()
    for unit in pending:
        for f in unit.files:
            if f not in files and not is_trace_path(f):
                files.append(f)
        for sym in unit.symbols:
            qn = sym.get("qualified_name")
            if qn and qn not in symbols:
                symbols.append(qn)
        if unit.seq is not None:
            seqs.add(int(unit.seq))
        seqs.update(int(s) for s in unit.related_seqs)
    return {
        "viewer": viewer,
        "pending": [u.to_dict() for u in pending],
        "rejected": [u.to_dict() for u in ledger.rejected_for(viewer["username"])],
        "highlight": {"files": files, "symbols": symbols, "seqs": sorted(seqs)},
        "clear": ledger.is_clear(),
    }


def _findings_payload(config: TraceConfig) -> dict[str, Any]:
    """The last saved Semgrep triage report (``flag --save``), or an empty report."""
    path = config.trace_dir / "findings-report.json"
    if not path.is_file():
        return {"findings_total": 0, "rows": [], "saved": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"error": f"could not read findings-report.json: {exc}"}
    data["saved"] = True
    return data


def _nodes_payload(config: TraceConfig) -> dict[str, Any]:
    with TraceQuery(config, enable_embeddings=False) as q:
        rows = q.db.conn.execute(
            """
            SELECT nl.qualified_name, MAX(nl.file_path) AS file_path,
                   COALESCE(MAX(ns.locked), 0) AS locked
            FROM node_links nl
            LEFT JOIN node_signatures ns ON ns.qualified_name = nl.qualified_name
            GROUP BY nl.qualified_name
            ORDER BY nl.qualified_name
            """
        ).fetchall()
    nodes = [
        dict(r)
        for r in rows
        if not is_trace_path(r["file_path"] or "")
        and not is_trace_path((r["qualified_name"] or "").removeprefix("file::"))
    ]
    return {"nodes": nodes}


def _merge_working_tree_symbols(
    config: TraceConfig,
    graph: Any,
    files: dict[str, list[dict[str, Any]]],
) -> None:
    """Fill gaps when the code-map lags the working tree (feedback 3.4).

    The structure view is "what code exists". A stale index can omit symbols that are
    plainly in the file (e.g. connector helpers added after the last re-index). Parse
    each listed file's working-tree source and add any missing symbols under the same
    module prefix the graph already uses, without inventing new edge endpoints.
    """
    from .ast_symbols import extract_symbols, language_for_path
    from .codegraph import normalize_path

    for fp in list(files.keys()):
        if is_trace_path(fp):
            continue
        language = language_for_path(fp)
        if not language:
            continue
        abs_path = config.repo_root / fp
        if not abs_path.is_file():
            continue
        try:
            source = abs_path.read_text(encoding="utf-8")
        except OSError:
            continue
        syms = extract_symbols(source, language=language)
        if not syms:
            continue
        prefix = graph.module_prefix(fp)
        if not prefix:
            continue
        existing_leaves = {
            (s.get("qualified_name") or "").rsplit(".", 1)[-1]
            for s in files[fp]
            if s.get("qualified_name")
        }
        for sym in syms:
            leaf = sym.name
            if leaf in existing_leaves:
                # Prefer the indexer's QN when present; still refresh the span so
                # Open-to-view / focus land on the current lines.
                for s in files[fp]:
                    qn = s.get("qualified_name") or ""
                    if qn.rsplit(".", 1)[-1] == leaf:
                        s["start_line"] = sym.start_line
                        s["end_line"] = sym.end_line
                continue
            qn = f"{prefix}.{sym.dotted_suffix}"
            files.setdefault(normalize_path(fp), []).append(
                {
                    "qualified_name": qn,
                    "label": sym.kind,
                    "start_line": sym.start_line,
                    "end_line": sym.end_line,
                    "from_working_tree": True,
                }
            )
            existing_leaves.add(leaf)


def _structure_payload(config: TraceConfig) -> dict[str, Any]:
    """Repository -> files -> symbols, plus the code-graph relationships between them.

    Structure comes from the read-only code graph (``nodes``/``edges``), then is filled
    in from the working tree where the index falls short: missing symbols come from
    the AST, and file pairs the graph leaves unconnected gain a REFERENCES edge when
    one file's text names the other (see :func:`_fill_reference_edges`). Hierarchy
    edges (DEFINES / CONTAINS_*) are dropped - the views already show containment -
    so what remains are the real relationships (CALLS, USAGE, IMPORTS, ...). Trace
    activity is overlaid from ``trace.db`` so the view can show where recorded history
    and decisions exist. ``File`` and ``Module`` nodes are kept as file-level edge
    endpoints but are not listed as symbols.
    """
    from .codegraph import _SYMBOL_LABELS, CodeGraph, normalize_path
    from .query import match_recorded_qualified_name, recorded_qns_for_file

    db_path = config.graph_db_path
    if not db_path or not Path(db_path).is_file():
        return {"error": "no code-graph database configured (pass --graph-db)"}

    hierarchy = {"DEFINES", "DEFINES_METHOD", "CONTAINS_FILE", "CONTAINS_FOLDER"}
    file_level_labels = {"File", "Module"}
    by_id: dict[int, dict[str, Any]] = {}
    files: dict[str, list[dict[str, Any]]] = {}
    repo_name = Path(config.repo_root).name
    with CodeGraph(db_path) as graph:
        # The indexed project name is the most meaningful label for the tree's root;
        # fall back to the repo directory name when the graph does not carry one.
        try:
            row = graph.conn.execute("SELECT name FROM projects LIMIT 1").fetchone()
            if row and row["name"]:
                repo_name = str(row["name"])
        except Exception:
            pass
        for r in graph.conn.execute(
            "SELECT id, label, qualified_name, name, file_path, start_line FROM nodes"
        ).fetchall():
            fp = normalize_path(r["file_path"] or "")
            qn = r["qualified_name"] or r["name"] or ""
            if not fp or not qn:
                continue
            if r["label"] in file_level_labels:
                by_id[r["id"]] = {"qn": qn, "file": fp}
                files.setdefault(fp, [])
            elif r["label"] in _SYMBOL_LABELS:
                by_id[r["id"]] = {"qn": qn, "file": fp}
                files.setdefault(fp, []).append(
                    {
                        "qualified_name": qn,
                        "label": r["label"],
                        "start_line": r["start_line"] or 0,
                    }
                )
        _merge_working_tree_symbols(config, graph, files)
        edge_rows = graph.conn.execute(
            "SELECT source_id, target_id, type FROM edges"
        ).fetchall()
    recorded: dict[str, int] = {}
    file_recorded: dict[str, int] = {}
    decisions: set[str] = set()
    file_decisions: set[str] = set()
    recorded_by_file: dict[str, list[str]] = {}
    decision_by_file: dict[str, list[str]] = {}
    signatures_by_qn: dict[str, dict[str, Any]] = {}
    with TraceQuery(config, enable_embeddings=False) as q:
        for r in q.db.conn.execute(
            "SELECT qualified_name, COUNT(DISTINCT step_id) AS c FROM node_links "
            "WHERE qualified_name != '' GROUP BY qualified_name"
        ).fetchall():
            recorded[r["qualified_name"]] = int(r["c"])
        for r in q.db.conn.execute(
            "SELECT file_path, COUNT(DISTINCT step_id) AS c FROM node_links "
            "WHERE file_path IS NOT NULL AND file_path != '' GROUP BY file_path"
        ).fetchall():
            file_recorded[r["file_path"]] = int(r["c"])
        for r in q.db.conn.execute(
            "SELECT DISTINCT qualified_name, file_path FROM branches "
            "WHERE kind != 'survived'"
        ).fetchall():
            if r["qualified_name"]:
                decisions.add(r["qualified_name"])
                if r["file_path"]:
                    decision_by_file.setdefault(r["file_path"], []).append(r["qualified_name"])
            if r["file_path"]:
                file_decisions.add(r["file_path"])
        for fp in files:
            recorded_by_file[fp] = recorded_qns_for_file(q.db, fp)
            for qn in recorded_by_file[fp]:
                sig = q.db.get_signature(qn)
                if sig:
                    signatures_by_qn[qn] = sig

    out_files = []
    for fp in sorted(files):
        syms = sorted(files[fp], key=lambda s: (s["start_line"], s["qualified_name"]))
        file_recorded_qns = recorded_by_file.get(fp, [])
        file_decision_qns = decision_by_file.get(fp, [])
        for s in syms:
            graph_qn = s["qualified_name"]
            matched = match_recorded_qualified_name(
                graph_qn,
                file_recorded_qns,
                signatures=signatures_by_qn,
                start_line=s.get("start_line") or None,
                end_line=None,
            )
            touch_qn = matched or (graph_qn if graph_qn in recorded else None)
            s["recorded"] = touch_qn is not None and touch_qn in recorded
            s["touch_count"] = recorded.get(touch_qn, 0) if touch_qn else 0
            s["decision"] = graph_qn in decisions
            if not s["decision"] and file_decision_qns:
                decision_match = match_recorded_qualified_name(
                    graph_qn,
                    file_decision_qns,
                    signatures=signatures_by_qn,
                    start_line=s.get("start_line") or None,
                )
                s["decision"] = (
                    decision_match is not None and decision_match in decisions
                )
        out_files.append(
            {
                "file_path": fp,
                "symbols": syms,
                "recorded": fp in file_recorded,
                "touch_count": file_recorded.get(fp, 0),
                "decision": fp in file_decisions,
            }
        )

    edges = []
    seen: set[tuple[str, str, str]] = set()
    for r in edge_rows:
        if r["type"] in hierarchy:
            continue
        a, b = by_id.get(r["source_id"]), by_id.get(r["target_id"])
        if not a or not b:
            continue
        key = (a["qn"], b["qn"], r["type"])
        if key in seen:
            continue
        seen.add(key)
        edges.append(
            {
                "source_qn": a["qn"],
                "target_qn": b["qn"],
                "source_file": a["file"],
                "target_file": b["file"],
                "type": r["type"],
                "cross_file": a["file"] != b["file"],
            }
        )
    _fill_reference_edges(config, out_files, edges)
    return {"files": out_files, "edges": edges, "repo": repo_name}


def _fill_reference_edges(
    config: TraceConfig, out_files: list[dict[str, Any]], edges: list[dict[str, Any]]
) -> None:
    """Fill in file-to-file REFERENCES edges the code graph does not carry.

    A build script or wrapper that names another file (e.g. ``compile.sh`` running
    ``python3 dutree.py``) is a real relationship, but indexers only extract
    language-level imports and calls, leaving such files floating disconnected in
    the structure view. Mirroring the working-tree fill-in used for symbols: for
    every file pair with no edge in the graph, scan the working-tree text for a
    whole-token mention of the other file's basename and add a synthetic
    ``REFERENCES`` edge. Extensionless basenames are skipped as too ambiguous.
    """
    paths = [f["file_path"] for f in out_files]
    if len(paths) < 2 or len(paths) > 200:  # keep the O(n^2) text scan bounded
        return
    linked: set[tuple[str, str]] = set()
    for e in edges:
        linked.add((e["source_file"], e["target_file"]))
        linked.add((e["target_file"], e["source_file"]))
    contents: dict[str, str] = {}
    for fp in paths:
        p = Path(config.repo_root) / fp
        try:
            if p.is_file() and p.stat().st_size <= 1_000_000:
                contents[fp] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    for src in paths:
        text = contents.get(src)
        if not text:
            continue
        for dst in paths:
            if src == dst or (src, dst) in linked:
                continue
            base = dst.rsplit("/", 1)[-1]
            if "." not in base:
                continue
            if re.search(r"(?<![\w-])" + re.escape(base) + r"(?![\w-])", text):
                edges.append(
                    {
                        "source_qn": "file::" + src,
                        "target_qn": "file::" + dst,
                        "source_file": src,
                        "target_file": dst,
                        "type": "REFERENCES",
                        "cross_file": True,
                    }
                )
                linked.add((src, dst))


def _file_content_payload(
    config: TraceConfig, file_path: str, node: Optional[str] = None
) -> dict[str, Any]:
    """Latest source for a file (working tree, else HEAD), with optional symbol span."""
    from . import gitdiff
    from .ast_symbols import extract_symbols, language_for_path
    from .branches import _match_symbol
    from .codegraph import normalize_path

    norm = normalize_path(file_path or "")
    if not norm or is_trace_path(norm):
        return {"error": "missing or invalid ?file="}

    abs_path = Path(config.repo_root) / norm
    content: Optional[str] = None
    source_kind = "working_tree"
    if abs_path.is_file():
        try:
            content = abs_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return {"error": f"could not read {norm}: {exc}"}
    else:
        sha = gitdiff.head_sha(config.repo_root)
        content = gitdiff.file_at_sha(config.repo_root, sha, norm)
        source_kind = "head"
        if content is None:
            return {"error": f"file not found: {norm}"}

    start_line = 0
    end_line = 0
    qn = (node or "").strip()
    if qn:
        language = language_for_path(norm)
        if language:
            sym = _match_symbol(extract_symbols(content, language=language), qn)
            if sym is not None:
                start_line = int(sym.start_line or 0)
                end_line = int(sym.end_line or 0)

    return {
        "file": norm,
        "content": content,
        "start_line": start_line,
        "end_line": end_line,
        "source": source_kind,
    }


_ASK_STOPWORDS = frozenset(
    "a an and are as at be but by can did do does for from had has have how i in is it its "
    "me my of on or that the then there this to was we what when where which who why will "
    "with you your".split()
)


def _ask_tokens(text: str) -> list[str]:
    """Deterministic tokenizer for the chat retrieval: lowercase identifiers/words."""
    return [
        t
        for t in re.findall(r"[a-z0-9_]+", (text or "").lower())
        if len(t) > 1 and t not in _ASK_STOPWORDS
    ]


def _ask_snippet(text: str, tokens: list[str], width: int = 340) -> str:
    """A window of ``text`` centered on the first query-token hit (or the start)."""
    flat = " ".join((text or "").split())
    lower = flat.lower()
    pos = min((lower.find(t) for t in tokens if lower.find(t) >= 0), default=0)
    start = max(0, pos - width // 3)
    out = flat[start : start + width]
    if start > 0:
        out = "\u2026" + out
    if start + width < len(flat):
        out += "\u2026"
    return out


def _ask_payload(config: TraceConfig, question: str) -> dict[str, Any]:
    """Answer a chat question by ranking recorded reasoning and code symbols.

    Uses the recorded-reasoning embedding index (semantic search) when the trace
    was recorded with embeddings; otherwise falls back to deterministic tf-idf
    keyword ranking so the chat works on any trace.
    """
    tokens = _ask_tokens(question)
    hits: list[dict[str, Any]] = []
    mode = "keyword"
    with TraceQuery(config) as q:
        rows = q.db.list_steps(lineage=q.active_lineage())
        if q.chroma is not None:
            try:
                raw = q.semantic_search(question, k=6)
                seq_by_id = {r["step_id"]: r.get("seq") for r in rows}
                for h in raw:
                    hits.append({
                        "seq": seq_by_id.get(h["step_id"]),
                        "step_id": h["step_id"],
                        "prompt": (h.get("prompt") or "")[:160],
                        "snippet": _ask_snippet(h.get("reasoning_text") or "", tokens),
                    })
                mode = "semantic"
            except Exception:
                hits = []
        if not hits and tokens:
            docs = []
            for r in rows:
                body = " ".join(
                    [r.get("prompt") or "", r.get("reasoning_text") or "",
                     (r.get("changed_files") or "").replace(",", " ")]
                ).lower()
                docs.append((r, body))
            n_docs = max(1, len(docs))
            df = {t: sum(1 for _, body in docs if t in body) for t in tokens}
            scored = []
            for r, body in docs:
                score = 0.0
                for t in tokens:
                    tf = body.count(t)
                    if tf:
                        score += (1 + math.log(tf)) * math.log(1 + n_docs / (1 + df[t]))
                if score > 0:
                    scored.append((score, r))
            scored.sort(key=lambda x: (-x[0], x[1].get("seq") or 0))
            for score, r in scored[:4]:
                hits.append({
                    "seq": r.get("seq"),
                    "step_id": r["step_id"],
                    "prompt": (r.get("prompt") or "")[:160],
                    "snippet": _ask_snippet(r.get("reasoning_text") or "", tokens),
                })

    symbols: list[dict[str, Any]] = []
    if tokens:
        structure = _structure_payload(config)
        for f in structure.get("files", []):
            fname = f["file_path"].split("/")[-1].lower()
            for s in f.get("symbols", []):
                leaf = s["qualified_name"].split(".")[-1].lower()
                score = sum(1 for t in tokens if t in leaf) * 2 + sum(
                    1 for t in tokens if t in fname
                )
                if score > 0:
                    symbols.append({
                        "qualified_name": s["qualified_name"],
                        "file_path": f["file_path"],
                        "label": s.get("label") or "",
                        "score": score + (1 if s.get("recorded") else 0),
                    })
        symbols.sort(key=lambda s: (-s["score"], s["qualified_name"]))
        symbols = symbols[:8]
    return {"question": question, "mode": mode, "hits": hits, "symbols": symbols}


def create_app(config: TraceConfig):
    """Build the Flask app (separate from ``run_panel`` so tests can use test_client)."""
    from flask import Flask, Response, request

    app = Flask(__name__)

    def _json(payload: dict[str, Any]) -> Response:
        return Response(json.dumps(payload), mimetype="application/json")

    @app.get("/")
    def index() -> Response:
        return Response(_PAGE, mimetype="text/html")

    @app.get("/api/history")
    def api_history() -> Response:
        target = request.args.get("target", "").strip()
        if not target:
            return _json({"error": "missing ?target="})
        file_hint = request.args.get("file", "").strip() or None
        start_line = _optional_int(request.args.get("start_line"))
        end_line = _optional_int(request.args.get("end_line"))
        return _json(
            _history_payload(
                config,
                target,
                file_path=file_hint,
                start_line=start_line,
                end_line=end_line,
            )
        )

    @app.get("/api/branches")
    def api_branches() -> Response:
        target = request.args.get("target", "").strip() or None
        file_hint = request.args.get("file", "").strip() or None
        start_line = _optional_int(request.args.get("start_line"))
        end_line = _optional_int(request.args.get("end_line"))
        return _json(
            _branches_payload(
                config,
                target,
                file_path=file_hint,
                start_line=start_line,
                end_line=end_line,
            )
        )

    @app.get("/api/nodes")
    def api_nodes() -> Response:
        return _json(_nodes_payload(config))

    @app.get("/api/versions")
    def api_versions() -> Response:
        return _json(_versions_payload(config))

    @app.get("/api/branch-detail")
    def api_branch_detail() -> Response:
        raw = request.args.get("branch_id", "").strip()
        try:
            branch_id = int(raw)
        except ValueError:
            return _json({"error": "missing or non-integer ?branch_id="})
        return _json(_branch_detail_payload(config, branch_id))

    @app.get("/api/files")
    def api_files() -> Response:
        return _json(_files_payload(config))

    @app.get("/api/step")
    def api_step() -> Response:
        raw = request.args.get("seq", "").strip()
        try:
            seq = int(raw)
        except ValueError:
            return _json({"error": "missing or non-integer ?seq="})
        return _json(_step_payload(config, seq))

    @app.get("/api/review")
    def api_review() -> Response:
        return _json(_review_payload(config))

    @app.post("/api/review/decide")
    def api_review_decide() -> Response:
        from .sync import review as sync_review

        viewer = _review_viewer()
        if not viewer["can_decide"]:
            return Response(
                json.dumps({"error": "only an entity admin can accept or reject a change"}),
                status=403,
                mimetype="application/json",
            )
        body = request.get_json(silent=True) or {}
        try:
            unit = sync_review.decide(
                _review_ledger_path(config),
                str(body.get("unit_id") or ""),
                str(body.get("verdict") or ""),
                by=viewer["username"],
            )
        except sync_review.ReviewError as exc:
            return Response(
                json.dumps({"error": str(exc)}), status=400, mimetype="application/json"
            )
        return _json({"ok": True, "unit_id": unit.unit_id, "status": unit.status})

    @app.get("/api/findings")
    def api_findings() -> Response:
        return _json(_findings_payload(config))

    @app.get("/api/structure")
    def api_structure() -> Response:
        return _json(_structure_payload(config))

    @app.get("/api/ask")
    def api_ask() -> Response:
        question = request.args.get("q", "").strip()
        if not question:
            return _json({"error": "missing ?q="})
        return _json(_ask_payload(config, question))

    @app.get("/api/file-content")
    def api_file_content() -> Response:
        file_path = request.args.get("file", "").strip()
        if not file_path:
            return _json({"error": "missing ?file="})
        node = request.args.get("node", "").strip() or None
        return _json(_file_content_payload(config, file_path, node=node))

    return app


def run_panel(config: TraceConfig, *, host: str = "127.0.0.1", port: int = 0) -> int:
    """Serve the panel; prints ``PANEL_URL=...`` once bound so a parent process (the VS Code
    extension) can discover the chosen free port."""
    try:
        from werkzeug.serving import make_server
    except ImportError:
        print("The panel needs Flask: pip install flask", file=sys.stderr)
        return 1

    app = create_app(config)
    server = make_server(host, port, app, threaded=True)
    print(f"PANEL_URL=http://{host}:{server.server_port}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
