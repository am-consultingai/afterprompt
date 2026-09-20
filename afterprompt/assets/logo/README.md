# Afterprompt logo pack

The mark is a command-line chevron followed by a key: a prompt, and what was left in it. Three shapes,
so it still reads at 16px.

## The masters

| File | What it is |
|---|---|
| `afterprompt-mark.svg` | the horizontal lockup, drawn in `currentColor` — inherits the text colour, so it works on any background |
| `afterprompt-icon.svg` | the square badge: white mark on `#1f5fd0`, 14/64 corner radius |
| `afterprompt-icon-mono.svg` | the badge as an outline in `currentColor`, for one-colour contexts |
| `afterprompt-icon-maskable.svg` | full-bleed, mark inside the 40% safe circle, for Android maskable icons |

The SVGs are the source. **Everything else in this folder is generated** — change the mark, then run:

    python3 tools/make_logo_pack.py

`--check` re-renders into a temporary folder and fails if what is committed is out of date; the test
suite calls it that way, so a stale PNG is a failing test rather than something you notice a year later.

## What is generated

- `afterprompt-icon-{16,32,48,64,96,128,180,192,256,512,1024}.png` — the badge, transparent outside the corners
- `afterprompt-maskable-{192,512}.png` — full-bleed, for `purpose: maskable`
- `apple-touch-icon.png` — 180px, no alpha, on its own background, the way iOS wants it
- `favicon.ico` — 16, 32 and 48 in one file
- `afterprompt-mark-{20,24,32,40,64,128}.png` — the lockup, transparent, for places that cannot take an SVG

## Colour

`#1f5fd0`, the same `--accent` as the browser view (`assets/ui/tokens.css`). The mark is white on it.
On a light background use the lockup as-is; on a dark one it inherits the light text colour.

## `am/` — AM Consulting

`am/am-logo-600.png` and `am/am-logo-white-600.png` are AM Consulting's logo, copied from
`am-assets@v2` for the About screen. They are bundled rather than linked because the browser view has
to work with no network — which is the exception the brand rules make for bundled apps. Use the white
one on dark backgrounds only; the blue wordmark has too little contrast there.

These are AM Consulting's marks, not Afterprompt's, and they are not covered by this repository's
licence.
