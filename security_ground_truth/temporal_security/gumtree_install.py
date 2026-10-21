"""Install the pinned GumTree Java matcher; no analyzed source is executed.

Run once: python3 -m security_ground_truth.temporal_security.gumtree_install
Dependencies are downloaded from Maven Central and checksummed in manifest.json.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request

VERSION = "3.0.0"
DEFAULT_HOME = Path.home() / ".cache/tracer/gumtree-3.0.0"
ARTIFACTS = [
    ("com.github.gumtreediff", "core", VERSION),
    ("org.atteo.classindex", "classindex", "3.10"),
    ("com.github.mpkorstanje", "simmetrics-core", "3.2.3"),
    ("it.unimi.dsi", "fastutil", "8.3.1"),
    ("com.google.code.gson", "gson", "2.8.2"),
    ("org.jgrapht", "jgrapht-core", "1.5.1"),
    ("org.jheaps", "jheaps", "0.13"),
    ("com.google.guava", "guava", "18.0"),
    ("commons-codec", "commons-codec", "1.10"),
]

BRIDGE = r'''
import java.io.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
import com.github.gumtreediff.tree.*;
import com.github.gumtreediff.matchers.*;
import com.github.gumtreediff.actions.*;
import com.github.gumtreediff.actions.model.*;

public class TracerGumtree {
  static Tree tree(JsonObject obj) {
    Tree t = new DefaultTree(TypeSet.type(obj.get("type").getAsString()), obj.get("label").getAsString());
    t.setPos(obj.get("id").getAsInt()); t.setLength(1);
    for (JsonElement child : obj.getAsJsonArray("children")) t.addChild(tree(child.getAsJsonObject()));
    return t;
  }
  public static void main(String[] args) throws Exception {
    JsonObject input = new JsonParser().parse(new InputStreamReader(System.in, StandardCharsets.UTF_8)).getAsJsonObject();
    Tree src = tree(input.getAsJsonObject("before")), dst = tree(input.getAsJsonObject("after"));
    MappingStore map = new CompositeMatchers.ClassicGumtree().match(src, dst);
    JsonArray mappings = new JsonArray();
    for (Mapping m : map) { JsonArray p = new JsonArray(); p.add(m.first.getPos()); p.add(m.second.getPos()); mappings.add(p); }
    EditScript script = new SimplifiedChawatheScriptGenerator().computeActions(map);
    JsonArray actions = new JsonArray();
    for (Action a : script) {
      JsonObject o = new JsonObject(); o.addProperty("operation", a.getName());
      boolean insert = a.getName().startsWith("insert");
      o.addProperty(insert ? "target_id" : "source_id", a.getNode().getPos());
      if (!insert && map.isSrcMapped(a.getNode())) o.addProperty("target_id", map.getDstForSrc(a.getNode()).getPos());
      if (a instanceof Update) o.addProperty("new_label", ((Update)a).getValue());
      if (a instanceof Addition) { o.addProperty("position", ((Addition)a).getPosition()); }
      if (a instanceof TreeAddition) { o.addProperty("position", ((TreeAddition)a).getPosition()); }
      actions.add(o);
    }
    JsonObject result = new JsonObject(); result.add("actions", actions); result.add("mappings", mappings);
    System.out.println(new Gson().toJson(result));
  }
}
'''


def install(home: Path = DEFAULT_HOME) -> dict:
    home = Path(home)
    (home / "lib").mkdir(parents=True, exist_ok=True)
    lock = json.loads(Path(__file__).with_name("gumtree_dependencies.json").read_text())
    expected = {entry["filename"]: entry["sha256"] for entry in lock["artifacts"]}
    entries = []
    for group, artifact, version in ARTIFACTS:
        filename = f"{artifact}-{version}.jar"
        path = home / "lib" / filename
        url = f"https://repo.maven.apache.org/maven2/{group.replace('.', '/')}/{artifact}/{version}/{filename}"
        if not path.exists():
            data = urllib.request.urlopen(url, timeout=60).read()
            temporary = path.with_suffix(".partial")
            temporary.write_bytes(data)
            temporary.replace(path)
        fingerprint = hashlib.sha256(path.read_bytes()).hexdigest()
        if fingerprint != expected[filename]:
            raise ValueError("Pinned dependency hash mismatch: " + filename)
        entries.append({"filename": filename, "url": url, "sha256": fingerprint})
    source = home / "TracerGumtree.java"
    source.write_text(BRIDGE)
    subprocess.run(["javac", "-cp", str(home / "lib/*"), str(source)], check=True,
                   capture_output=True, timeout=60)
    manifest = {"matcher": "GumTree ClassicGumtree", "version": VERSION,
                "edit_script": "SimplifiedChawatheScriptGenerator", "artifacts": entries,
                "bridge_source_sha256": hashlib.sha256(BRIDGE.encode()).hexdigest(),
                "bridge_class_sha256": hashlib.sha256((home / "TracerGumtree.class").read_bytes()).hexdigest(),
                "license": "GumTree core LGPL-3.0; dependency licenses remain upstream"}
    (home / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


if __name__ == "__main__":
    print(json.dumps(install(Path(os.environ.get("TRACER_GUMTREE_HOME", DEFAULT_HOME))), indent=2))
