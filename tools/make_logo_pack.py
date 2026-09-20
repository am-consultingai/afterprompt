#!/usr/bin/env python3
"""Render the logo pack from the SVG masters in afterprompt/assets/logo.

The SVGs are the masters; everything else here is generated, so a change to the mark means re-running
this, not editing twenty PNGs. Rasterising uses headless Chrome (already required for nothing else, so
this is a maintainer tool, not a runtime dependency) and Pillow for the .ico and the checks.

    python3 tools/make_logo_pack.py [--check]

--check re-renders into a temporary folder and fails if anything committed is out of date.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LOGO = os.path.join(os.path.dirname(HERE), "afterprompt", "assets", "logo")

# name -> (source svg, [sizes]); square icons unless the source is the wide lockup.
ICON_SIZES = [16, 32, 48, 64, 96, 128, 180, 192, 256, 512, 1024]
MARK_HEIGHTS = [20, 24, 32, 40, 64, 128]
ICO_SIZES = [16, 32, 48]

CHROME = None


def chrome():
    global CHROME
    if CHROME is None:
        for name in ("google-chrome", "chromium", "chromium-browser", "google-chrome-stable"):
            path = shutil.which(name)
            if path:
                CHROME = path
                break
        else:
            sys.exit("no Chrome or Chromium found; it is what rasterises the SVGs")
    return CHROME


def render(svg_path, out_path, width, height):
    """One SVG to one PNG, transparent where the art is transparent.

    The SVG goes in as markup rather than as <img src>: an image that has not finished loading when
    the screenshot fires comes out half-painted, which is what happened at 128px and above.
    """
    with open(svg_path, encoding="utf-8") as fh:
        svg = fh.read()
    svg = svg.replace("<svg ", f"<svg width='{width}' height='{height}' ", 1)
    page = ("<!doctype html><meta charset='utf-8'>"
            "<style>html,body{margin:0;padding:0;background:transparent}"
            "svg{display:block}</style>" + svg)
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as fh:
        fh.write(page)
        html = fh.name
    # Chrome's new headless takes its (invisible) toolbar out of the window height, so a 128px window
    # screenshots 41px of page. Ask for room, then crop back to the size that was wanted.
    slack = 200
    try:
        subprocess.run([chrome(), "--headless=new", "--disable-gpu", "--no-sandbox", "--hide-scrollbars",
                        "--default-background-color=00000000", f"--window-size={width},{height + slack}",
                        "--virtual-time-budget=4000", f"--screenshot={out_path}", "file://" + html],
                       check=True, capture_output=True, timeout=120)
    finally:
        os.unlink(html)
    from PIL import Image
    im = Image.open(out_path).convert("RGBA")
    if im.size != (width, height):
        im.crop((0, 0, width, height)).save(out_path)


def build(out_dir):
    from PIL import Image

    os.makedirs(out_dir, exist_ok=True)
    made = []

    def png(src, name, w, h):
        path = os.path.join(out_dir, name)
        render(os.path.join(LOGO, src), path, w, h)
        made.append(name)
        return path

    for size in ICON_SIZES:
        png("afterprompt-icon.svg", f"afterprompt-icon-{size}.png", size, size)
    for size in (192, 512):
        png("afterprompt-icon-maskable.svg", f"afterprompt-maskable-{size}.png", size, size)
    # The wide lockup keeps its 64:40 ratio.
    for h in MARK_HEIGHTS:
        png("afterprompt-mark.svg", f"afterprompt-mark-{h}.png", int(round(h * 64 / 40.0)), h)

    # Apple wants no alpha and no rounding of its own; give it the badge on its own background.
    apple = Image.open(os.path.join(out_dir, "afterprompt-icon-180.png")).convert("RGBA")
    flat = Image.new("RGB", apple.size, "#1f5fd0")
    flat.paste(apple, mask=apple.split()[3])
    flat.save(os.path.join(out_dir, "apple-touch-icon.png"))
    made.append("apple-touch-icon.png")

    ico = Image.open(os.path.join(out_dir, "afterprompt-icon-256.png")).convert("RGBA")
    ico.save(os.path.join(out_dir, "favicon.ico"), sizes=[(s, s) for s in ICO_SIZES])
    made.append("favicon.ico")

    # A half-painted screenshot is a real failure mode here, and an empty-file check does not catch it:
    # every picture must actually fill its canvas.
    for name in made:
        if name.endswith(".ico"):
            continue
        im = Image.open(os.path.join(out_dir, name)).convert("RGBA")
        painted = im.split()[3].getbbox()
        if painted is None:
            sys.exit("nothing rendered: " + name)
        w, h = im.size
        if name.startswith("afterprompt-mark"):
            # The lockup is art on transparency: it has padding, but it must still use the canvas.
            wide = (painted[2] - painted[0]) >= w * 0.8
            tall = (painted[3] - painted[1]) >= h * 0.6
            if not (wide and tall):
                sys.exit("the lockup does not fill its canvas (%s of %sx%s): %s" % (painted, w, h, name))
        elif painted[2] < w * 0.9 or painted[3] < h * 0.9:
            # A badge is full-bleed; anything less means a half-painted screenshot.
            sys.exit("only part of the canvas was painted (%s): %s" % (painted, name))
    return made


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="fail if what is committed is out of date")
    args = ap.parse_args()
    if not args.check:
        made = build(LOGO)
        print("\n".join(sorted(made)))
        return
    tmp = tempfile.mkdtemp()
    try:
        made = build(tmp)
        stale = []
        for name in made:
            here = os.path.join(LOGO, name)
            if not os.path.exists(here):
                stale.append(name + " (missing)")
                continue
            # Rasterisers differ by a pixel between versions; compare that it is the same picture,
            # not the same bytes.
            from PIL import Image, ImageChops
            a = Image.open(here).convert("RGBA")
            b = Image.open(os.path.join(tmp, name)).convert("RGBA")
            if a.size != b.size or ImageChops.difference(a, b).getbbox() is not None:
                stale.append(name)
        if stale:
            sys.exit("out of date, re-run tools/make_logo_pack.py: " + ", ".join(stale))
        print("logo pack is current")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
