#!/usr/bin/env python3
"""Build the published hero assets from the lossless master `docs/hero.png`.

    python3 scripts/build_hero_assets.py

Produces:

    docs/hero.webp        the README hero — the master's own 16:9 aspect, WebP q92
    docs/hero-2x1.webp    the catalog card — 2:1, which the catalog `image:` field expects

Why the 2:1 is synthesised rather than cropped or mirrored: the master is 1672x941 (16:9) and
full-bleed — artwork reaches column 55 on the left, column 1621 on the right, and row 3 on top.
Mirror-padding 105px per side would duplicate artwork, and cropping the 105px from the bottom
would delete the "BY PACIFIC CLOUD SOLUTIONS" subtitle (rows 856-872). So the canvas is widened
by extrapolating the background gradient outward from the clean edge bands, one linear fit per
row, which continues a soft gradient without a horizontal seam.

Requires Pillow. Run it with Hermes's venv python if PIL is not on your PATH:
    ~/.hermes/hermes-agent/venv/bin/python scripts/build_hero_assets.py
"""

from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
MASTER = ROOT / "docs" / "hero.png"
QUALITY = 92

# Clean background bands measured on the master (see the module docstring).
LEFT_BAND = 55
RIGHT_BAND = 50
CARD_SIZE = (1600, 800)  # 2:1, trimmed from 1882x941 to keep the file small


def extrapolate(edge_cols: np.ndarray, distance: int, outward_left: bool) -> np.ndarray:
    """Per-row linear fit over a clean edge band, evaluated outward from the edge."""
    height, width, _ = edge_cols.shape
    xs = np.arange(width, dtype=np.float64)
    x_mean = xs.mean()
    denom = ((xs - x_mean) ** 2).sum()
    out = np.empty((height, distance, 3), dtype=np.float64)
    for y in range(height):
        row = edge_cols[y]
        slopes = ((xs - x_mean)[:, None] * (row - row.mean(axis=0))).sum(axis=0) / denom
        intercept = row.mean(axis=0) - slopes * x_mean
        eval_x = (
            np.arange(-distance, 0, dtype=np.float64)
            if outward_left
            else np.arange(width, width + distance, dtype=np.float64)
        )
        out[y] = intercept + slopes * eval_x[:, None]
    return np.clip(out, 0, 255)


def main() -> None:
    master = Image.open(MASTER).convert("RGB")
    width, height = master.size
    if width / height >= 2.0:
        raise SystemExit(f"{MASTER.name} is already 2:1 or wider ({width}x{height}); nothing to widen")

    master.save(ROOT / "docs" / "hero.webp", "WEBP", quality=QUALITY, method=6)
    print(f"docs/hero.webp      {width}x{height}")

    pixels = np.asarray(master).astype(np.float64)
    target_width = height * 2
    pad = (target_width - width) // 2

    wide = np.concatenate(
        [
            extrapolate(pixels[:, :LEFT_BAND, :], pad, outward_left=True),
            pixels,
            extrapolate(pixels[:, width - RIGHT_BAND :, :], pad, outward_left=False),
        ],
        axis=1,
    )
    if wide.shape[1] != target_width:
        raise SystemExit(f"widened to {wide.shape[1]}px, expected {target_width}")

    card = Image.fromarray(wide.round().astype(np.uint8)).resize(CARD_SIZE, Image.Resampling.LANCZOS)
    card.save(ROOT / "docs" / "hero-2x1.webp", "WEBP", quality=QUALITY, method=6)
    print(f"docs/hero-2x1.webp  {card.size[0]}x{card.size[1]}  (padded {pad}px per side)")


if __name__ == "__main__":
    main()
