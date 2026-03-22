from __future__ import annotations

import hashlib
import re
from collections import Counter, OrderedDict
from html import escape
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MD_PATH = ROOT / ".agents" / "structure.md"
SVG_PATH = ROOT / ".agents" / "structure_call_tree.svg"


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def hsl_to_hex(hue: float, saturation: float, lightness: float) -> str:
    hue = hue % 360.0
    saturation = clamp(saturation, 0, 100) / 100.0
    lightness = clamp(lightness, 0, 100) / 100.0
    chroma = (1 - abs(2 * lightness - 1)) * saturation
    x_val = chroma * (1 - abs((hue / 60.0) % 2 - 1))
    match hue:
        case _ if hue < 60:
            red, green, blue = chroma, x_val, 0
        case _ if hue < 120:
            red, green, blue = x_val, chroma, 0
        case _ if hue < 180:
            red, green, blue = 0, chroma, x_val
        case _ if hue < 240:
            red, green, blue = 0, x_val, chroma
        case _ if hue < 300:
            red, green, blue = x_val, 0, chroma
        case _:
            red, green, blue = chroma, 0, x_val
    offset = lightness - chroma / 2
    return "#%02x%02x%02x" % (
        round((red + offset) * 255),
        round((green + offset) * 255),
        round((blue + offset) * 255),
    )


def file_palette(name: str) -> dict[str, str]:
    digest = hashlib.sha1(name.encode("utf-8")).hexdigest()
    hue = int(digest[:6], 16) % 360
    return {
        "accent": hsl_to_hex(hue, 62, 45),
        "mid": hsl_to_hex(hue, 36, 87),
    }


def level_palette(level: int, min_level: int, max_level: int) -> dict[str, str]:
    if max_level == min_level:
        t_val = 0.0
    else:
        t_val = (max_level - level) / (max_level - min_level)
    hue = 205 - 165 * t_val
    return {
        "accent": hsl_to_hex(hue, 68, 42),
        "soft": hsl_to_hex(hue, 55, 96),
        "line": hsl_to_hex(hue, 35, 80),
        "badge": hsl_to_hex(hue, 75, 30),
    }


def short_file(name: str) -> str:
    return name[:-2] if name.endswith(".h") else name


def approx_text_width(text: str, font_size: float, mono: bool = False) -> float:
    factor = 0.58 if mono else 0.54
    return len(text) * font_size * factor


def truncate(text: str, max_width: float, font_size: float, mono: bool = False) -> str:
    if approx_text_width(text, font_size, mono) <= max_width:
        return text
    ellipsis = "..."
    low = 0
    high = len(text)
    while low < high:
        mid = (low + high + 1) // 2
        candidate = text[:mid].rstrip() + ellipsis
        if approx_text_width(candidate, font_size, mono) <= max_width:
            low = mid
        else:
            high = mid - 1
    return text[:low].rstrip() + ellipsis


def parse_structure() -> tuple[list[dict[str, object]], OrderedDict[int, list[dict[str, object]]]]:
    text = MD_PATH.read_text(encoding="utf-8")
    entries: list[dict[str, object]] = []
    current_level: int | None = None
    current_file: str | None = None
    ref_re = re.compile(r"`([^`]+)`")

    for line in text.splitlines():
        level_match = re.match(r"^## Level (\d+) - (\d+) method", line)
        if level_match:
            current_level = int(level_match.group(1))
            current_file = None
            continue

        file_match = re.match(r"^### (.+)$", line)
        if file_match:
            current_file = file_match.group(1)
            continue

        method_match = re.match(r"^- `([^`]+)` - (leaf method|Sandy refs: (.+))$", line)
        if not method_match:
            continue

        full_name = method_match.group(1)
        refs = ref_re.findall(method_match.group(3) or "")
        file_name, method_name = [part.strip() for part in full_name.split(" > ", 1)]
        entries.append(
            {
                "id": full_name,
                "level": current_level,
                "section_file": current_file,
                "file": file_name,
                "method": method_name,
                "refs": refs,
            }
        )

    levels: OrderedDict[int, list[dict[str, object]]] = OrderedDict()
    for level in sorted({int(entry["level"]) for entry in entries}, reverse=True):
        levels[level] = [entry for entry in entries if entry["level"] == level]
    return entries, levels


def build_svg() -> str:
    entries, levels = parse_structure()
    nodes = {str(entry["id"]): entry for entry in entries}

    for entry in entries:
        entry["out_count"] = len(entry["refs"])  # type: ignore[index]
        entry["in_count"] = 0
    for entry in entries:
        for ref in entry["refs"]:  # type: ignore[index]
            if ref in nodes:
                nodes[ref]["in_count"] = int(nodes[ref]["in_count"]) + 1

    min_level = min(levels)
    max_level = max(levels)
    level_order = list(levels.keys())

    outer = 26
    header_h = 94
    arrow_h = 22
    col_gap = 14
    col_header_h = 42
    col_pad = 10
    file_header_h = 18
    method_h = 13
    row_gap = 1
    file_gap = 8
    group_pad = 6
    badge_w = 20
    mono_size = 9.2
    file_size = 10.7

    level_groups: dict[int, OrderedDict[str, list[dict[str, object]]]] = {}
    for level, level_nodes in levels.items():
        groups: OrderedDict[str, list[dict[str, object]]] = OrderedDict()
        for node in level_nodes:
            groups.setdefault(str(node["file"]), []).append(node)
        level_groups[level] = groups

    col_widths: dict[int, int] = {}
    for level, groups in level_groups.items():
        max_method = 0.0
        max_file = 0.0
        for file_name, items in groups.items():
            max_file = max(max_file, approx_text_width(short_file(file_name), file_size))
            for item in items:
                label = str(item["method"])
                label = label.replace("const std::wstring&", "wstring")
                label = label.replace("const std::vector<std::wstring>&", "vector<wstring>")
                label = label.replace("const SandboxConfig&", "const Config&")
                label = label.replace("SandboxConfig&", "Config&")
                max_method = max(max_method, approx_text_width(label, mono_size, mono=True))
        extra = 36 if any(int(node["out_count"]) for node in levels[level]) else 20
        width = int(clamp(max(max_file + 26, max_method + extra + 24), 150, 250))
        if len(levels[level]) <= 3:
            width = int(clamp(width - 10, 136, 220))
        col_widths[level] = width

    x_positions: dict[int, int] = {}
    cursor_x = outer
    for level in level_order:
        x_positions[level] = cursor_x
        cursor_x += col_widths[level] + col_gap

    diagram_top = header_h + arrow_h + 12
    node_pos: dict[str, dict[str, float]] = {}
    col_bottoms: dict[int, float] = {}
    file_cards: list[dict[str, float | str | int]] = []
    col_meta: dict[int, dict[str, float]] = {}

    for level in level_order:
        col_x = x_positions[level]
        col_w = col_widths[level]
        cursor_y = diagram_top + col_header_h + 10
        for file_name, items in level_groups[level].items():
            group_y = cursor_y
            row_area_h = len(items) * method_h + max(0, len(items) - 1) * row_gap
            group_h = group_pad + file_header_h + 5 + row_area_h + group_pad
            file_cards.append(
                {
                    "level": level,
                    "file": file_name,
                    "x": col_x + 8,
                    "y": group_y,
                    "w": col_w - 16,
                    "h": group_h,
                }
            )
            row_y = group_y + group_pad + file_header_h + 5
            for item in items:
                node_pos[str(item["id"])] = {
                    "x": col_x + col_pad,
                    "y": row_y,
                    "w": col_w - col_pad * 2,
                    "h": method_h,
                    "level": float(level),
                }
                row_y += method_h + row_gap
            cursor_y += group_h + file_gap
        col_bottoms[level] = cursor_y - file_gap + 10
        col_meta[level] = {
            "x": float(col_x),
            "y": float(diagram_top),
            "w": float(col_w),
            "h": float(col_bottoms[level] - diagram_top),
        }

    total_nodes = len(entries)
    total_edges = sum(len(entry["refs"]) for entry in entries)  # type: ignore[arg-type]
    file_counts = Counter(str(entry["file"]) for entry in entries)
    fanout = sorted(entries, key=lambda entry: (-int(entry["out_count"]), str(entry["id"])))[:5]

    left_panel_levels = level_order[:6]
    panel_x = outer
    panel_w = sum(col_widths[level] for level in left_panel_levels) + col_gap * (len(left_panel_levels) - 1)
    panel_y = max(col_bottoms[level] for level in left_panel_levels) + 18
    panel_h = 244

    canvas_w = cursor_x - col_gap + outer
    canvas_h = int(max(max(col_bottoms.values()) + outer, panel_y + panel_h + outer))

    svg: list[str] = []
    append = svg.append

    append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas_w}" height="{canvas_h}" '
        f'viewBox="0 0 {canvas_w} {canvas_h}" role="img" aria-labelledby="title desc">'
    )
    append('<title id="title">Sandy CLI call tree from .agents/structure.md</title>')
    append(
        "<desc id=\"desc\">Compact call-depth diagram generated from .agents/structure.md. "
        "Higher-level orchestration methods appear on the left, leaf utility methods on the right. "
        "Curved links show Sandy-only method references.</desc>"
    )
    append("<defs>")
    append('  <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">')
    append('    <feDropShadow dx="0" dy="2" stdDeviation="3" flood-color="#7a6b58" flood-opacity="0.10"/>')
    append("  </filter>")
    append('  <linearGradient id="headerGrad" x1="0" x2="1" y1="0" y2="0">')
    append('    <stop offset="0%" stop-color="#1e3a4a"/>')
    append('    <stop offset="48%" stop-color="#295668"/>')
    append('    <stop offset="100%" stop-color="#87623f"/>')
    append("  </linearGradient>")
    append("</defs>")
    append(f'<rect x="0" y="0" width="{canvas_w}" height="{canvas_h}" fill="#f6f1e8"/>')
    append(
        f'<rect x="16" y="14" width="{canvas_w - 32}" height="{header_h}" rx="20" '
        'fill="url(#headerGrad)" filter="url(#shadow)"/>'
    )
    append(
        f'<text x="{outer + 18}" y="48" fill="#fffdf7" font-family="Aptos, Segoe UI, sans-serif" '
        'font-size="28" font-weight="700">Sandy Method Call Tree</text>'
    )
    append(
        f'<text x="{outer + 18}" y="74" fill="#e7f0f2" font-family="Aptos, Segoe UI, sans-serif" '
        'font-size="13.5">Generated from .agents/structure.md | grouped by call depth | '
        'compact overview of all 358 Sandy-defined methods</text>'
    )
    append(
        f'<text x="{outer + 18}" y="95" fill="#f7debe" font-family="Aptos, Segoe UI, sans-serif" '
        f'font-size="13">358 methods | 766 Sandy-only references | {len(file_counts)} files | '
        f'{len(level_order)} levels</text>'
    )

    arrow_y = header_h + 20
    left_x = x_positions[level_order[0]]
    right_x = x_positions[level_order[-1]] + col_widths[level_order[-1]]
    append(
        f'<path d="M {left_x + 10} {arrow_y} L {right_x - 20} {arrow_y}" '
        'stroke="#b7a690" stroke-width="2" stroke-linecap="round"/>'
    )
    append(f'<path d="M {right_x - 20} {arrow_y} l -10 -5 l 0 10 z" fill="#b7a690"/>')
    append(
        f'<text x="{(left_x + right_x) / 2:.1f}" y="{arrow_y - 7}" text-anchor="middle" '
        'fill="#5c5347" font-family="Aptos, Segoe UI, sans-serif" font-size="12.5" font-weight="600">'
        'Higher-level orchestration on the left -> lower-level helpers on the right</text>'
    )

    append('<g id="edges">')
    edge_items: list[tuple[int, float, str]] = []
    for src in entries:
        src_box = node_pos[str(src["id"])]
        sx = src_box["x"] + src_box["w"]
        sy = src_box["y"] + src_box["h"] / 2
        src_level = int(src["level"])
        palette = level_palette(src_level, min_level, max_level)
        for ref in src["refs"]:  # type: ignore[index]
            dst_box = node_pos.get(ref)
            if not dst_box:
                continue
            ex = dst_box["x"]
            ey = dst_box["y"] + dst_box["h"] / 2
            span = src_level - int(dst_box["level"])
            delta_x = max(32, (ex - sx) * 0.42)
            opacity = 0.15 if span == 1 else 0.10 if span <= 3 else 0.07
            stroke_width = 1.15 if span == 1 else 0.95 if span <= 3 else 0.75
            edge_items.append(
                (
                    span,
                    sy,
                    f'<path d="M {sx:.1f} {sy:.1f} C {sx + delta_x:.1f} {sy:.1f}, '
                    f'{ex - delta_x:.1f} {ey:.1f}, {ex:.1f} {ey:.1f}" fill="none" '
                    f'stroke="{palette["accent"]}" stroke-opacity="{opacity:.3f}" '
                    f'stroke-width="{stroke_width:.2f}" stroke-linecap="round"/>',
                )
            )
    for _, __, edge in sorted(edge_items, key=lambda item: (item[0], item[1])):
        append(edge)
    append("</g>")

    append('<g id="columns">')
    for level in level_order:
        meta = col_meta[level]
        palette = level_palette(level, min_level, max_level)
        count = len(levels[level])
        append(f'<g id="level-{level}">')
        append(
            f'<rect x="{meta["x"]}" y="{meta["y"]}" width="{meta["w"]}" height="{meta["h"]}" rx="18" '
            f'fill="#fffaf2" stroke="{palette["line"]}" stroke-opacity="0.45" filter="url(#shadow)"/>'
        )
        append(
            f'<rect x="{meta["x"]}" y="{meta["y"]}" width="{meta["w"]}" height="{col_header_h}" rx="18" '
            f'fill="{palette["soft"]}"/>'
        )
        append(
            f'<rect x="{meta["x"]}" y="{meta["y"] + col_header_h - 14}" width="{meta["w"]}" height="14" '
            f'fill="{palette["soft"]}"/>'
        )
        append(
            f'<text x="{meta["x"] + 14}" y="{meta["y"] + 18}" fill="#2d2a26" '
            'font-family="Aptos, Segoe UI, sans-serif" font-size="13" font-weight="700">'
            f"Level {level}</text>"
        )
        label = f"{count} method" if count == 1 else f"{count} methods"
        append(
            f'<text x="{meta["x"] + 14}" y="{meta["y"] + 33}" fill="#6b6256" '
            'font-family="Aptos, Segoe UI, sans-serif" font-size="11.2">'
            f"{label}</text>"
        )
        badge_x = meta["x"] + meta["w"] - 46
        append(
            f'<rect x="{badge_x}" y="{meta["y"] + 10}" width="30" height="20" rx="10" '
            f'fill="{palette["badge"]}"/>'
        )
        append(
            f'<text x="{badge_x + 15}" y="{meta["y"] + 24}" text-anchor="middle" fill="#fffaf2" '
            'font-family="Cascadia Mono, Consolas, monospace" font-size="10.8" font-weight="700">'
            f"L{level}</text>"
        )
        append("</g>")
    append("</g>")

    append('<g id="nodes">')
    for card in file_cards:
        palette = file_palette(str(card["file"]))
        file_label = truncate(short_file(str(card["file"])), float(card["w"]) - 18, file_size)
        append("<g>")
        append(f"  <title>{escape(str(card['file']))}</title>")
        append(
            f'  <rect x="{card["x"]}" y="{card["y"]}" width="{card["w"]}" height="{card["h"]}" rx="12" '
            f'fill="#fffdfa" stroke="{palette["mid"]}" stroke-opacity="0.55"/>'
        )
        append(
            f'  <rect x="{card["x"]}" y="{card["y"]}" width="5" height="{card["h"]}" rx="3" '
            f'fill="{palette["accent"]}"/>'
        )
        append(
            f'  <text x="{float(card["x"]) + 12}" y="{float(card["y"]) + 13.5}" fill="#2b2a27" '
            f'font-family="Aptos, Segoe UI, sans-serif" font-size="{file_size}" font-weight="700">'
            f"{escape(file_label)}</text>"
        )
        append("</g>")

    for entry in entries:
        box = node_pos[str(entry["id"])]
        palette = file_palette(str(entry["file"]))
        fill = "#ffffff" if int(entry["out_count"]) == 0 else "#fffaf3"
        stroke = "#e8ddcf" if int(entry["out_count"]) == 0 else palette["mid"]
        label_max = box["w"] - 24 - (badge_w if int(entry["out_count"]) else 8)
        label = truncate(str(entry["method"]), label_max, mono_size, mono=True)
        append("<g>")
        append(
            "  <title>"
            f"{escape(str(entry['file']) + ' > ' + str(entry['method']))}\n"
            f"Level {entry['level']}\n"
            f"Refs out: {entry['out_count']} | Refs in: {entry['in_count']}"
            "</title>"
        )
        append(
            f'  <rect x="{box["x"]}" y="{box["y"]}" width="{box["w"]}" height="{box["h"]}" rx="7" '
            f'fill="{fill}" stroke="{stroke}" stroke-opacity="0.55"/>'
        )
        append(
            f'  <circle cx="{box["x"] + 6.5}" cy="{box["y"] + box["h"] / 2:.1f}" r="2.3" '
            f'fill="{palette["accent"]}" fill-opacity="0.88"/>'
        )
        append(
            f'  <text x="{box["x"] + 14}" y="{box["y"] + 9.4}" fill="#2b2926" '
            f'font-family="Cascadia Mono, Consolas, monospace" font-size="{mono_size}">'
            f"{escape(label)}</text>"
        )
        if int(entry["out_count"]):
            badge_x = box["x"] + box["w"] - badge_w - 6
            badge_y = box["y"] + 2
            append(
                f'  <rect x="{badge_x}" y="{badge_y}" width="{badge_w}" height="9" rx="4.5" '
                f'fill="{palette["accent"]}" fill-opacity="0.92"/>'
            )
            append(
                f'  <text x="{badge_x + badge_w / 2}" y="{badge_y + 7.1}" text-anchor="middle" '
                'fill="#fffdf8" font-family="Cascadia Mono, Consolas, monospace" '
                f'font-size="7.4" font-weight="700">{entry["out_count"]}</text>'
            )
        append("</g>")
    append("</g>")

    append('<g id="summary">')
    append(
        f'<rect x="{panel_x}" y="{panel_y}" width="{panel_w}" height="{panel_h}" rx="18" '
        'fill="#fffaf2" stroke="#cabca8" filter="url(#shadow)"/>'
    )
    append(
        f'<text x="{panel_x + 18}" y="{panel_y + 24}" fill="#2d2a26" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="15.5" font-weight="700">'
        "Reading Notes</text>"
    )
    append(
        f'<text x="{panel_x + 18}" y="{panel_y + 44}" fill="#6f665a" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="11.8">'
        "This uses the sparse lower-left area on purpose so the diagram stays compact.</text>"
    )

    card_gap = 12
    inner_x = panel_x + 16
    inner_y = panel_y + 58
    inner_w = panel_w - 32
    small_h = 66
    half_w = (inner_w - card_gap) / 2

    append(
        f'<rect x="{inner_x}" y="{inner_y}" width="{half_w}" height="{small_h}" rx="14" '
        'fill="#f7f1e6" stroke="#d7c9b3"/>'
    )
    append(
        f'<text x="{inner_x + 14}" y="{inner_y + 18}" fill="#2e2a25" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="12.8" font-weight="700">Scale</text>'
    )
    append(
        f'<text x="{inner_x + 14}" y="{inner_y + 38}" fill="#5f574c" '
        'font-family="Cascadia Mono, Consolas, monospace" font-size="11">'
        f"nodes  {total_nodes}   |   edges  {total_edges}</text>"
    )
    append(
        f'<text x="{inner_x + 14}" y="{inner_y + 54}" fill="#5f574c" '
        'font-family="Cascadia Mono, Consolas, monospace" font-size="11">'
        f"files  {len(file_counts)}    |   levels {len(level_order)}</text>"
    )

    card2_x = inner_x + half_w + card_gap
    append(
        f'<rect x="{card2_x}" y="{inner_y}" width="{half_w}" height="{small_h}" rx="14" '
        'fill="#f7f1e6" stroke="#d7c9b3"/>'
    )
    append(
        f'<text x="{card2_x + 14}" y="{inner_y + 18}" fill="#2e2a25" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="12.8" font-weight="700">'
        "How To Read It</text>"
    )
    append(
        f'<text x="{card2_x + 14}" y="{inner_y + 37}" fill="#5f574c" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="11.4">'
        '1. Start at <tspan font-family="Cascadia Mono, Consolas, monospace">wmain</tspan> on the far left.</text>'
    )
    append(
        f'<text x="{card2_x + 14}" y="{inner_y + 53}" fill="#5f574c" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="11.4">'
        "2. Follow the pale curves into denser helper columns on the right.</text>"
    )

    path_y = inner_y + small_h + 12
    append(
        f'<rect x="{inner_x}" y="{path_y}" width="{inner_w}" height="68" rx="14" '
        'fill="#fbf7f0" stroke="#d7c9b3"/>'
    )
    append(
        f'<text x="{inner_x + 14}" y="{path_y + 19}" fill="#2e2a25" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="12.8" font-weight="700">'
        "Representative Paths</text>"
    )
    append(
        f'<text x="{inner_x + 14}" y="{path_y + 39}" fill="#5f574c" '
        'font-family="Cascadia Mono, Consolas, monospace" font-size="10.7">'
        "wmain -> RunMain -> RunConfigDrivenMode -> RunSandboxed -> RunPipeline</text>"
    )
    append(
        f'<text x="{inner_x + 14}" y="{path_y + 55}" fill="#5f574c" '
        'font-family="Cascadia Mono, Consolas, monospace" font-size="10.7">'
        "wmain -> RunMain -> RunSavedProfileMode -> RunWithProfile -> RunPipeline</text>"
    )

    hotspot_y = path_y + 80
    hotspot_h = panel_y + panel_h - hotspot_y - 16
    append(
        f'<rect x="{inner_x}" y="{hotspot_y}" width="{inner_w}" height="{hotspot_h}" rx="14" '
        'fill="#fbf7f0" stroke="#d7c9b3"/>'
    )
    append(
        f'<text x="{inner_x + 14}" y="{hotspot_y + 19}" fill="#2e2a25" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="12.8" font-weight="700">'
        "Highest Fan-Out Methods</text>"
    )
    row_y = hotspot_y + 38
    for index, item in enumerate(fanout, start=1):
        label = truncate(f"{item['file']} > {item['method']}", inner_w - 82, 10.3, mono=True)
        append(
            f'<text x="{inner_x + 14}" y="{row_y}" fill="#5f574c" '
            'font-family="Cascadia Mono, Consolas, monospace" font-size="10.3">'
            f"{index}. {escape(label)}</text>"
        )
        append(
            f'<text x="{inner_x + inner_w - 16}" y="{row_y}" text-anchor="end" fill="#8d5d31" '
            'font-family="Aptos, Segoe UI, sans-serif" font-size="10.8" font-weight="700">'
            f"{item['out_count']} refs</text>"
        )
        row_y += 16
    append("</g>")

    append(
        f'<text x="{canvas_w - outer}" y="{canvas_h - 12}" text-anchor="end" fill="#8a7e70" '
        'font-family="Aptos, Segoe UI, sans-serif" font-size="10.8">'
        "Each row shows a tiny count badge when the method has outgoing Sandy refs.</text>"
    )
    append("</svg>")
    return "\n".join(svg) + "\n"


def main() -> None:
    SVG_PATH.write_text(build_svg(), encoding="utf-8")
    print(f"Wrote {SVG_PATH}")


if __name__ == "__main__":
    main()
