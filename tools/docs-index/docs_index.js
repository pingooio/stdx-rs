import { readFileSync, readdirSync, existsSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const docDir = join(__dirname, "..", "..", "target", "doc");

const cratesJsPath = join(docDir, "crates.js");
if (!existsSync(cratesJsPath)) {
  console.error("target/doc/crates.js not found. Run 'cargo doc --no-deps' first.");
  process.exit(1);
}

const cratesJs = readFileSync(cratesJsPath, "utf-8");
const match = cratesJs.match(/window\.ALL_CRATES\s*=\s*(\[.*?\]);/);
if (!match) {
  throw new Error("Could not parse crates.js");
}

const crateNames = JSON.parse(match[1]);

const excluded = new Set(["static.files", "src", "trait.impl", "type.impl", "search.index"]);

function readCrateMeta(name) {
  const indexPath = join(docDir, name, "index.html");
  if (!existsSync(indexPath)) return null;

  const html = readFileSync(indexPath, "utf-8");
  const version = html.match(/<span class="version">([^<]+)<\/span>/)?.[1] ?? "";
  const description = html.match(/<meta name="description" content="([^"]*)">/)?.[1] ?? "";
  return { name, version, description };
}

const crates = crateNames
  .map(readCrateMeta)
  .filter(Boolean)
  .sort((a, b) => a.name.localeCompare(b.name));

const rows = crates.map(c => `      <dt id="crate-${c.name}"><a class="mod" href="./${c.name}/index.html">${c.name.replace(/_/g, "_<wbr>")}</a></dt><dd>${c.version ? `<span class="version">${c.version}</span> — ` : ""}${escapeHtml(c.description)}</dd>`).join("\n");

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

const indexHtml = `<!DOCTYPE html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="generator" content="rustdoc">
<title>stdx-rs — Workspace documentation</title>
<script>if(window.location.protocol!=="file:")document.head.insertAdjacentHTML("beforeend","SourceSerif4-Regular-6b053e98.ttf.woff2,FiraSans-Italic-81dc35de.woff2,FiraSans-Regular-0fe48ade.woff2,FiraSans-MediumItalic-ccf7e434.woff2,FiraSans-Medium-e1aa3f0a.woff2,SourceCodePro-Regular-8badfe75.ttf.woff2,SourceCodePro-Semibold-aa29a496.ttf.woff2".split(",").map(f=>\`<link rel="preload" as="font" type="font/woff2"href="./static.files/$\{f}">\`).join(""))</script>
<link rel="stylesheet" href="./static.files/normalize-9960930a.css">
<link rel="stylesheet" href="./static.files/rustdoc-17e0aaed.css">
<meta name="rustdoc-vars" data-root-path="./" data-static-root-path="./static.files/" data-current-crate="stdx_rs" data-themes="" data-resource-suffix="" data-rustdoc-version="1.96.0" data-channel="1.96.0" data-search-js="search-b5634cc7.js" data-stringdex-js="stringdex-2da4960a.js" data-settings-js="settings-170eb4bf.js">
<script src="./static.files/storage-41dd4d93.js"></script>
<script defer src="./crates.js"></script>
<script defer src="./static.files/main-5013f961.js"></script>
<noscript><link rel="stylesheet" href="./static.files/noscript-f7c3ffd8.css"></noscript>
<link rel="alternate icon" type="image/png" href="./static.files/favicon-32x32-eab170b8.png">
<link rel="icon" type="image/svg+xml" href="./static.files/favicon-044be391.svg">
</head><body class="rustdoc mod crate">
<a class="skip-main-content" href="#main-content">Skip to main content</a>
<rustdoc-topbar><h2><a href="#">Workspace stdx-rs</a></h2></rustdoc-topbar>
<nav class="sidebar">
<div class="sidebar-crate"><h2><a href="./index.html">stdx-rs</a></h2></div>
<div class="sidebar-elems">
<section id="rustdoc-toc"><h3><a href="#">Crates</a></h3><ul class="block">${crates.map(c => `<li><a href="#crate-${c.name}" title="${escapeHtml(c.description)}">${c.name.replace(/_/g, "_<wbr>")}</a></li>`).join("")}</ul></section>
</div>
</nav>
<div class="sidebar-resizer" title="Drag to resize sidebar"></div>
<main><div class="width-limiter">
<section id="main-content" class="content" tabindex="-1">
<div class="main-heading"><h1>stdx-rs <span>workspace</span></h1></div>
<div class="docblock"><p>This workspace contains ${crates.length} crates.</p></div>
<h2 id="crates" class="section-header">All Crates<a href="#crates" class="anchor">§</a></h2>
<dl class="item-table" id="crate-list">
${rows}
</dl>
</section></div></main>
</body></html>`;

writeFileSync(join(docDir, "index.html"), indexHtml);
console.log(`Generated index.html with ${crates.length} crates`);
