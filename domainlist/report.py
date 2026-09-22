"""Автономный HTML-отчет о проверке: открывается без интернета, все внутри одного файла."""
from __future__ import annotations

import json

_TEMPLATE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Проверка доменов</title>
<style>
:root { --bg:#fafaf9; --fg:#1c1917; --muted:#78716c; --card:#fff; --line:#e7e5e4;
  --ok:#15803d; --keep:#0e7490; --review:#b45309; --remove:#b91c1c; --unknown:#7e22ce; }
@media (prefers-color-scheme: dark) { :root { --bg:#1c1917; --fg:#f5f5f4; --muted:#a8a29e; --card:#292524;
  --line:#44403c; --ok:#4ade80; --keep:#22d3ee; --review:#fbbf24; --remove:#f87171; --unknown:#c084fc; } }
* { box-sizing:border-box; }
body { margin:0; padding:24px 16px; background:var(--bg); color:var(--fg);
  font:14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { max-width:1200px; margin:0 auto; }
h1 { font-size:22px; margin:0 0 4px; }
.meta { color:var(--muted); margin-bottom:16px; }
.box { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px 16px; margin-bottom:16px; }
.box ul { margin:4px 0 0; padding-left:18px; }
.chips { display:flex; flex-wrap:wrap; gap:8px; margin-bottom:12px; }
.chip { border:1px solid var(--line); background:var(--card); color:var(--fg); border-radius:999px;
  padding:4px 12px; cursor:pointer; font:inherit; }
.chip[aria-pressed="true"] { border-color:currentColor; font-weight:600; }
input[type=search] { width:100%; padding:8px 12px; border:1px solid var(--line); border-radius:8px;
  background:var(--card); color:var(--fg); font:inherit; margin-bottom:12px; }
.table { overflow-x:auto; border:1px solid var(--line); border-radius:10px; background:var(--card); }
table { border-collapse:collapse; width:100%; min-width:720px; }
th, td { text-align:left; padding:8px 12px; border-bottom:1px solid var(--line); vertical-align:top; }
th { position:sticky; top:0; background:var(--card); color:var(--muted); font-weight:600; cursor:pointer; }
tr:last-child td { border-bottom:none; }
.dom { font-family:ui-monospace, SFMono-Regular, Menlo, monospace; word-break:break-all; }
.ev { color:var(--muted); font-size:12px; margin-top:2px; }
.s-ok { color:var(--ok); } .s-keep { color:var(--keep); } .s-review { color:var(--review); }
.s-remove { color:var(--remove); } .s-unknown { color:var(--unknown); }
.empty { padding:24px; text-align:center; color:var(--muted); }
</style>
</head>
<body>
<main>
<h1>Проверка доменов</h1>
<div class="meta" id="meta"></div>
<div id="notes"></div>
<div class="chips" id="chips"></div>
<input type="search" id="q" placeholder="Поиск по домену, разделу, причине">
<div class="table"><table>
<thead><tr><th data-k="domain">Домен</th><th data-k="label">Статус</th><th data-k="section">Раздел</th>
<th data-k="line">Строка</th><th data-k="note">Причина и улики</th></tr></thead>
<tbody id="rows"></tbody></table></div>
</main>
<script type="application/json" id="data">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById("data").textContent);
const $ = id => document.getElementById(id);
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
$("meta").textContent = `${D.checked_at.replace("T", " ").slice(0, 16)} · ${D.source || "разовая проверка"} · ${D.results.length} доменов · ${D.duration_sec} с`;
const notes = [];
if (D.channels.length) notes.push(`<b>Каналы:</b><ul>${D.channels.map(c => `<li>${esc(c)}</li>`).join("")}</ul>`);
if (D.warnings.length) notes.push(`<b>Предупреждения:</b><ul>${D.warnings.map(w => `<li>${esc(w)}</li>`).join("")}</ul>`);
if (D.expiring.length) notes.push(`<b>Скоро истекает регистрация:</b><ul>${D.expiring.map(e => `<li>${esc(e.zone)}: ${esc(e.expires)} (${e.days} дн.)</li>`).join("")}</ul>`);
$("notes").innerHTML = notes.map(n => `<div class="box">${n}</div>`).join("");
const rank = {remove: 0, review: 1, unknown: 2, keep: 3, ok: 4};
const groups = [...new Set(D.results.map(r => r.label))].sort((a, b) =>
  rank[D.results.find(r => r.label === a).group] - rank[D.results.find(r => r.label === b).group]);
const active = new Set(groups.filter(g => D.results.some(r => r.label === g && r.group !== "ok")));
if (!active.size) groups.forEach(g => active.add(g));
let sortKey = "line", sortDir = 1;
function chips() {
  $("chips").innerHTML = groups.map(g => {
    const r = D.results.find(x => x.label === g);
    const n = D.results.filter(x => x.label === g).length;
    return `<button class="chip s-${r.group}" aria-pressed="${active.has(g)}" data-g="${esc(g)}">${esc(g)}: ${n}</button>`;
  }).join("");
}
function render() {
  const q = $("q").value.trim().toLowerCase();
  const rows = D.results.filter(r => active.has(r.label) &&
    (!q || [r.domain, r.section, r.note, ...r.evidence].join(" ").toLowerCase().includes(q)));
  rows.sort((a, b) => {
    const x = a[sortKey] ?? "", y = b[sortKey] ?? "";
    return (typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y))) * sortDir;
  });
  $("rows").innerHTML = rows.length ? rows.map(r => `<tr>
    <td class="dom">${esc(r.domain)}</td>
    <td class="s-${r.group}">${esc(r.label)}${r.confirmed.length ? `<div class="ev">подтверждено: ${esc(r.confirmed.join(", "))}</div>` : ""}</td>
    <td>${esc(r.section)}</td><td>${r.line ?? ""}</td>
    <td>${esc(r.note)}${r.evidence.map(e => `<div class="ev">${esc(e)}</div>`).join("")}</td></tr>`).join("")
    : `<tr><td colspan="5" class="empty">Ничего не найдено</td></tr>`;
}
$("chips").addEventListener("click", e => {
  const g = e.target.closest(".chip")?.dataset.g;
  if (!g) return;
  active.has(g) ? active.delete(g) : active.add(g);
  chips(); render();
});
$("q").addEventListener("input", render);
document.querySelectorAll("th").forEach(th => th.addEventListener("click", () => {
  sortDir = sortKey === th.dataset.k ? -sortDir : 1; sortKey = th.dataset.k; render();
}));
chips(); render();
</script>
</body>
</html>
"""


def render_html(data: dict) -> str:
    """data - тот же словарь, что пишется в JSON-отчет."""
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    return _TEMPLATE.replace("__DATA__", payload)

