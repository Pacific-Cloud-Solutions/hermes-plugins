#!/usr/bin/env python3
"""Build the aichipmunk catalog card from the AI Chipmunk logo master.

    # Needs Pillow (+ numpy), so run it with Hermes's own interpreter:
    <hermes-python> scripts/build_aichipmunk_card.py

Produces:

    plugins/aichipmunk/docs/hero-2x1.webp    the catalog `image:` — 2:1, 1600x800

The master is `plugins/aichipmunk/docs/logo.png` (the app's mark, RGBA, 550x626), committed
here so the card is reproducible and reviewable rather than hand-edited: the same rule the
security suite's `build_hero_assets.py` follows.

Why a composed card instead of a crop: the mark is portrait and has no wordmark, so a 2:1
crop of it would either clip the tail or leave dead space. It is centred on a warm dark
ground that matches the app's brown/black identity, with a soft amber glow behind it so the
mark's own dark fur bands keep their edge against the background instead of merging into it.
The mark is DOWN-scaled (626px master -> 500px on the card), never up-scaled.
"""

from pathlib import Path

import numpy as np
from PIL import Image, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "plugins" / "aichipmunk" / "docs"
MASTER = DOCS / "logo.png"
OUT = DOCS / "hero-2x1.webp"

CARD = (1600, 800)          # 2:1, what the catalog `image:` field expects
MARK_HEIGHT = 500           # < the 626px master: a downscale, so no invented detail
QUALITY = 92

# Warm espresso, sampled to sit under the app's brown/black/white palette.
TOP = (26, 15, 10)
BOTTOM = (62, 38, 25)
GLOW = (245, 154, 18)       # the mark's own amber (#F59A12)


def vertical_gradient(size: tuple[int, int]) -> np.ndarray:
    width, height = size
    ramp = np.linspace(0.0, 1.0, height, dtype=np.float64)[:, None]
    top = np.array(TOP, dtype=np.float64)
    bottom = np.array(BOTTOM, dtype=np.float64)
    rows = top + (bottom - top) * ramp
    return np.repeat(rows[:, None, :], width, axis=1)


def amber_glow(size: tuple[int, int], centre: tuple[int, int], radius: float) -> np.ndarray:
    """A soft radial bloom, as a 0..1 multiplier per pixel."""
    width, height = size
    ys, xs = np.mgrid[0:height, 0:width]
    distance = np.hypot(xs - centre[0], ys - centre[1])
    falloff = np.clip(1.0 - (distance / radius), 0.0, 1.0)
    return (falloff ** 2.2)[:, :, None]


def strip_matte(logo: Image.Image, ring_px: int = 2) -> Image.Image:
    """Remove the pale cut-out ring the app's PNG carries around the silhouette.

    Measured on the master: the 2px boundary ring averages RGB(234,224,205) and 67.7% of it is
    near-white, against an interior mean of RGB(200,152,109) — and a zoomed look shows it
    broken, jagged and flecked. That is a light matte from background removal, not a drawn
    keyline, and on a dark card it reads as white crumbs. So the ring is eroded away and the
    surviving edge is re-coloured from its interior neighbours.

    The master's alpha is binary, so the LANCZOS down-scale that follows is what gives the final
    edge its anti-aliasing — erode first, resize second, or the new edge would be hard.
    """
    arr = np.asarray(logo).astype(np.float64)
    rgb = arr[:, :, :3].copy()
    solid = arr[:, :, 3] >= 128

    def erode(mask: np.ndarray) -> np.ndarray:
        out = mask.copy()
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                out = np.logical_and(out, np.roll(np.roll(mask, dy, axis=0), dx, axis=1))
        return out

    solid = erode(solid) if ring_px == 1 else erode(erode(solid))

    # Re-colour the surviving outer TWO pixel rings from neighbours that are not themselves on
    # the ring. One ring was not enough: where the master's pale band was thicker than the
    # erosion, pale pixels survived (measured: 7.1% of the boundary still near-white).
    interior = erode(erode(solid))
    edge = np.logical_and(solid, np.logical_not(interior))
    if edge.any():
        acc = np.zeros_like(rgb)
        count = np.zeros(solid.shape)
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if dx == 0 and dy == 0:
                    continue
                neighbour = np.roll(np.roll(interior, dy, axis=0), dx, axis=1)
                acc += np.roll(np.roll(rgb, dy, axis=0), dx, axis=1) * neighbour[:, :, None]
                count += neighbour
        fill = np.logical_and(edge, count > 0)
        rgb[fill] = acc[fill] / count[fill][:, None]

    out = np.dstack([np.clip(rgb, 0, 255), np.where(solid, 255.0, 0.0)]).round().astype(np.uint8)
    return Image.fromarray(out, "RGBA")


def main() -> None:
    if not MASTER.is_file():
        raise SystemExit(f"missing logo master: {MASTER}")
    logo = Image.open(MASTER).convert("RGBA")
    logo = strip_matte(logo)

    # Trim transparent padding so the mark is optically centred, not box-centred.
    bbox = logo.getchannel("A").getbbox()
    if bbox:
        logo = logo.crop(bbox)
    if logo.height > MARK_HEIGHT:
        ratio = MARK_HEIGHT / logo.height
        logo = logo.resize((max(1, round(logo.width * ratio)), MARK_HEIGHT), Image.Resampling.LANCZOS)
    elif logo.height < MARK_HEIGHT:
        print(f"note: master is only {logo.height}px tall; not up-scaling past it")

    base = vertical_gradient(CARD)
    centre = (CARD[0] // 2, CARD[1] // 2)
    glow = amber_glow(CARD, centre, radius=CARD[1] * 0.62) * 0.34
    pixels = base * (1.0 - glow) + np.array(GLOW, dtype=np.float64) * glow
    canvas = Image.fromarray(np.clip(pixels, 0, 255).round().astype(np.uint8), "RGB")

    # A blurred copy of the mark's own silhouette under it, so it does not look pasted on.
    shadow = Image.new("RGBA", CARD, (0, 0, 0, 0))
    silhouette = Image.new("RGBA", logo.size, (0, 0, 0, 150))
    shadow.paste(silhouette, (centre[0] - logo.width // 2, centre[1] - logo.height // 2 + 14),
                 logo.getchannel("A"))
    shadow = shadow.filter(ImageFilter.GaussianBlur(26))
    canvas = Image.alpha_composite(canvas.convert("RGBA"), shadow)

    canvas.alpha_composite(logo, (centre[0] - logo.width // 2, centre[1] - logo.height // 2))
    canvas.convert("RGB").save(OUT, "WEBP", quality=QUALITY, method=6)
    print(f"plugins/aichipmunk/docs/hero-2x1.webp  {CARD[0]}x{CARD[1]}  "
          f"(mark {logo.width}x{logo.height}, {OUT.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()