"""Study every frozen retained helper in passing SWE-bench recordings."""
import argparse
from collections import Counter, defaultdict
from functools import lru_cache
import json
from pathlib import Path
import urllib.request
import zipfile

if __package__:
    from .structure import definitions, payloads, sha, state_at, maximal_matches
else:
    from structure import definitions, payloads, sha, state_at, maximal_matches


def read_jsonl(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def jsonl(path, rows):
    Path(path).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


class Archive:
    def __init__(self, path, batch, out):
        self.z = zipfile.ZipFile(path)
        self.members = {n.rsplit("/", 1)[-1]: n for n in self.z.namelist()
                        if "/blobs/" in n and not n.startswith("__MACOSX/")}
        self.batch, self.out = batch, out
        self.base_manifest = {}

    @lru_cache(maxsize=8192)
    def blob(self, ref):
        data = self.z.read(self.members[ref])
        if sha(data) != ref:
            raise ValueError("Blob hash mismatch: " + ref)
        return data.decode("utf-8", "replace")

    def run(self, runid, filename):
        return [json.loads(l) for l in self.z.read(f"ghost_model_families/runs/{runid}/{filename}").splitlines() if l.strip()]

    def source(self, ref, row, path):
        if ref is None:
            return "", "deleted"
        if ref != "BASE":
            return self.blob(ref), ref
        inst = json.loads((self.batch / "inputs/swebench" / row["run_id"] / "instance.json").read_text())
        key = f"{inst['repo']}@{inst['base_commit']}:{path}"
        cache = self.out / "base_sources" / sha(key)
        url = f"https://raw.githubusercontent.com/{inst['repo']}/{inst['base_commit']}/{path}"
        if key in self.base_manifest and self.base_manifest[key].get("error"):
            return None, "unavailable_base"
        try:
            if not cache.exists():
                cache.parent.mkdir(exist_ok=True)
                cache.write_bytes(urllib.request.urlopen(url, timeout=30).read())
            data = cache.read_bytes()
            self.base_manifest[key] = dict(url=url, sha256=sha(data), cached=str(cache))
            return data.decode("utf-8", "replace"), sha(data)
        except Exception as exc:
            self.base_manifest[key] = dict(url=url, error=str(exc))
            return None, "unavailable_base"


@lru_cache(maxsize=4096)
def parsed(source):
    if source is None:
        return [], "unavailable_source"
    try:
        return definitions(source), None
    except (SyntaxError, ValueError) as exc:
        return [], str(exc)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--archive", type=Path, required=True)
    ap.add_argument("--batch", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    census = read_jsonl(args.batch / "endpoint_census_final.jsonl")
    rows = {r["run_id"]: r for r in census if r["benchmark"] == "swebench" and r.get("eligible")}
    helpers = [r for r in read_jsonl(args.batch / "nominations.jsonl") if r["nominated"] and r["run_id"] in rows]
    save(args.out / "cohort.json", dict(passing_runs=len(rows), run_ids=sorted(rows),
        helpers=[{k: r[k] for k in ["run_id", "path", "sha256", "event_id"]} for r in helpers],
        census_sha256=sha((args.batch / "endpoint_census_final.jsonl").read_bytes()),
        nominations_sha256=sha((args.batch / "nominations.jsonl").read_bytes()),
        source_archive=str(args.archive), scripts={p.name:sha(p.read_bytes()) for p in Path(__file__).parent.glob("*.py")}))
    archive = Archive(args.archive, args.batch, args.out)
    all_links, inventories, observations, transitions = [], [], [], []
    for index, h in enumerate(helpers):
        runid = h["run_id"]
        row = rows[runid]
        events = archive.run(runid, "events.jsonl")
        snapshots = {s["snapshot_id"]: s for s in archive.run(runid, "snapshots.jsonl")}
        event = next(e for e in events if e["event_id"] == h["event_id"])
        before, after = snapshots[event["before_snapshot"]], snapshots[event["after_snapshot"]]
        final = json.loads((args.batch / "inputs/swebench" / runid / "final.json").read_text())
        ref = {**final["files"], **final.get("tmp_files", {})}.get(h["path"])
        if ref != h["sha256"]:
            raise ValueError("Nominated helper no longer matches frozen endpoint")
        source = archive.blob(ref)
        directory = args.out / "evidence" / runid / sha(h["path"])[:12]
        directory.mkdir(parents=True)
        (directory / "helper.py").write_text(source)
        (directory / "recorded_command.txt").write_text(event.get("command", ""))
        inv = {k:h[k] for k in ["run_id", "task", "path", "sha256", "event_id", "stratum", "output_superseded"]}
        inv.update(evidence_dir=str(directory), event_sequence=event["sequence"])
        try:
            candidates = payloads(source)
            inv.update(helper_parse_error=None, executable_definitions=definitions(source))
        except (SyntaxError, ValueError) as exc:
            candidates = []
            inv.update(helper_parse_error=str(exc), executable_definitions=[])
        save(directory / "payloads.json", candidates)
        inv.update(source_bearing_literals=len(candidates), parseable_literals=sum(not c["parse_error"] for c in candidates),
                   payload_definitions=sum(len(c["definitions"]) for c in candidates))
        links = []
        for path in sorted(h["targets"]):
            texts, units, errors, refs = {}, {}, {}, {}
            for label, snap in [("before", before), ("after", after), ("final", final)]:
                texts[label], refs[label] = archive.source(snap["files"].get(path, "BASE"), row, path)
                units[label], errors[label] = parsed(texts[label])
            target_dir = directory / sha(path)[:12]
            target_dir.mkdir()
            for label, text in texts.items():
                if text is not None: (target_dir / (label + ".py")).write_text(text)
            save(target_dir / "source_identity.json", dict(path=path, refs=refs, parse_errors=errors))
            if errors["after"]:
                continue
            for p in candidates:
                matches = []
                for u in p["definitions"]:
                    matched = [a for a in units["after"] if a["ast_sha256"] == u["ast_sha256"]]
                    for a in matched:
                        matches.append(dict(payload_unit=u, target_unit=a))
                for m in maximal_matches(matches):
                    a = m["target_unit"]
                    previous = state_at(a, units["before"]) if not errors["before"] else "unknown"
                    status = state_at(a, units["final"]) if not errors["final"] else "unknown"
                    origin = "preexisting_match" if previous == "current" else "unknown" if previous in {"unknown", "ambiguous_duplicate_definition"} else "observed_introduction"
                    if sum(u["qualified_name"] == a["qualified_name"] for u in units["after"]) != 1:
                        origin = "ambiguous_after_definition"
                    lid = sha(json.dumps([runid, h["path"], p["literal_line"], path, a["qualified_name"], a["ast_sha256"]]))[:20]
                    link = dict(id=lid, run_id=runid, task=h["task"], helper=h["path"], stratum=h["stratum"],
                        literal_line=p["literal_line"], literal_names=p["names"], literal_roles=p["roles"],
                        target_path=path, target_unit=a, payload_unit=m["payload_unit"], origin=origin,
                        endpoint_status=status, before_status=previous, source_refs=refs,
                        file_changed=refs["after"] != refs["final"], nomination_file_superseded=h["output_superseded"],
                        event_id=event["event_id"], after_snapshot=event["after_snapshot"], evidence_dir=str(target_dir))
                    final_same = [u for u in units["final"] if u["qualified_name"] == a["qualified_name"]]
                    link["final_unit"] = final_same[0] if len(final_same)==1 else None
                    link["code_ast_unchanged"] = len(final_same)==1 and final_same[0]["code_ast_sha256"] == a["code_ast_sha256"]
                    history = []
                    last_ref = refs["after"]
                    for e in events:
                        if e["sequence"] <= event["sequence"] or e.get("after_snapshot") not in snapshots:
                            continue
                        snap = snapshots[e["after_snapshot"]]
                        r = snap["files"].get(path, "BASE")
                        if r == last_ref: continue
                        last_ref = r
                        txt, digest = archive.source(r, row, path)
                        defs, err = parsed(txt)
                        history.append(dict(event_id=e["event_id"], sequence=e["sequence"], snapshot=e["after_snapshot"],
                            source_ref=digest, status=state_at(a,defs) if not err else "unknown", error=err))
                    link["transitions"] = history
                    links.append(link)
                    transitions.extend(dict(link_id=lid, **x) for x in history)
        # Duplicate literals can describe the same entity; preserve links but count entities separately.
        inv.update(matched_links=len(links), introduced_links=sum(x["origin"]=="observed_introduction" for x in links))
        inventories.append(inv)
        all_links.extend(links)
        # Only outputs explicitly attached as model-visible are candidates for exposure.
        visible = defaultdict(list)
        try:
            for e in archive.run(runid, "events_model_visible.jsonl"):
                visible[e["event_id"]].append(e["model_visible_content_ref"])
        except KeyError: pass
        for e in events:
            if e["sequence"] <= event["sequence"]: continue
            refs = set(visible[e["event_id"]])
            if e.get("model_visible_content_ref"): refs.add(e["model_visible_content_ref"])
            for out_ref in refs:
                text = archive.blob(out_ref)
                full, basename = h["path"], Path(h["path"]).name
                if full not in text and basename not in text: continue
                names = sorted({l["target_unit"]["name"] for l in links if l["target_unit"]["name"] in text})
                observations.append(dict(run_id=runid, helper=h["path"], event_id=e["event_id"], sequence=e["sequence"],
                    output_ref=out_ref, command=e.get("command"), matched_symbol_names=names,
                    output_chars=len(text), lead_only=True,
                    note="Filename/name co-occurrence is not confirmed fragment exposure or causal influence."))
        print(index+1, "/", len(helpers), runid, h["path"], "links",len(links), flush=True)
    jsonl(args.out / "helpers.jsonl", inventories)
    jsonl(args.out / "links.jsonl", all_links)
    jsonl(args.out / "exposure_leads.jsonl", observations)
    jsonl(args.out / "transitions.jsonl", transitions)
    save(args.out / "base_sources.json", archive.base_manifest)
    introduced = [r for r in all_links if r["origin"] == "observed_introduction"]
    summary = dict(passing_runs=len(rows), helpers=len(helpers), helper_runs=len({h['run_id'] for h in helpers}),
        helper_strata=dict(Counter(h['stratum'] for h in helpers)),
        helpers_with_payload_definitions=sum(h['payload_definitions']>0 for h in inventories),
        helpers_with_links=sum(h['matched_links']>0 for h in inventories),
        helpers_with_introduced_links=sum(h['introduced_links']>0 for h in inventories),
        links=len(all_links), origins=dict(Counter(r['origin'] for r in all_links)),
        introduced_endpoint_status=dict(Counter(r['endpoint_status'] for r in introduced)),
        introduced_helpers_by_status={s:len({(r['run_id'],r['helper']) for r in introduced if r['endpoint_status']==s}) for s in sorted({r['endpoint_status'] for r in introduced})},
        unchanged_region_in_changed_file=sum(r['file_changed'] and r['endpoint_status']=='current' for r in introduced),
        exposure_leads=len(observations), base_fetch_failures=sum('error' in r for r in archive.base_manifest.values()),
        limits="Source-string complete-definition subset; exact AST identity; compound action provenance; no independent human validation or downstream effectiveness estimate.")
    save(args.out / "summary.json", summary)
    print(json.dumps(summary,indent=2),flush=True)


if __name__ == "__main__": main()
