"""Aletheia marketplace avatar — 440x440, square corners, no face.

ἀλήθεια is UNCONCEALMENT — *a-lētheia*, the un-forgetting. Heidegger: truth is not a property of
statements, it is the clearing in which a thing shows itself.

The mark is a VESICA PISCIS at dawn. Two circles overlap; the lens between them — the *mandorla* — is
where the light comes through. In classical and sacred geometry the mandorla is precisely the figure of
disclosure, and it exists ONLY where two views coincide, which is exactly how Aletheia rules: a verdict
where independent checks agree. The geometry carries the argument; the light carries the feeling.

On the register, honestly: an earlier version stamped 35,000 impasto strokes to imitate an oil painting.
It produced convincing texture and an unconvincing picture — uniform stroke fields read as wood grain or
textile, because a painting's beauty is in composition and subject, not bristle marks. Code cannot reach
an image model's canvas that way. What code renders genuinely well is LIGHT: deep gradients, cloud
strata, god-rays, bloom, grain. So this is mythic atmosphere behind crisp classical geometry.

NO HUMAN FIGURE AND NO FACE anywhere. A human head in profile is a documented instant rejection here,
and this agent was refused for exactly that once already. The reference that set this palette contained
a humanoid silhouette; that part is deliberately not borrowed.

Spec: exactly 440x440, RGB (never RGBA — an alpha channel is what renders as rounded corners), under
1 MB, no text.

    python scripts/make_avatar_440.py
"""
from __future__ import annotations

import math
import os
import sys

from PIL import Image, ImageChops, ImageDraw, ImageFilter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from atmos import (bloom, god_rays, grain, haze_bands, lerp, radial_light,  # noqa: E402
                   screen, stars, vertical_sky)

SIZE = 440
SS = 3                      # 3x is enough here: the subject is smooth light, not fine linework
W = SIZE * SS
C = W // 2

NIGHT = (11, 13, 28)
DEEP = (26, 26, 56)
VIOLET = (58, 46, 86)
EMBER = (186, 104, 58)
AMBER = (238, 168, 84)
GOLD = (252, 212, 132)
CREAM = (255, 248, 230)
VERDICT = (72, 226, 176)
VERDICT_HI = (190, 255, 234)

R = W * 0.310
DX = R * 0.5                # centres exactly R apart -> the true vesica; lens ratio is sqrt(3)


def _lens() -> list[tuple[float, float]]:
    """The intersection of the two discs.

    Arcs run only BETWEEN the meeting points at (C, C ± h), h = sqrt(R² - DX²), subtending ±phi about
    each centre with phi = atan2(h, DX). Using full half-circles self-intersects and renders a bowtie;
    sweeping the second arc away from pi renders a crescent. Both were built and thrown out first.
    """
    h = math.sqrt(max(0.0, R * R - DX * DX))
    phi = math.atan2(h, DX)
    pts: list[tuple[float, float]] = []
    steps = 320
    for i in range(steps + 1):
        a = -phi + 2 * phi * (i / steps)
        pts.append((C - DX + R * math.cos(a), C + R * math.sin(a)))
    for i in range(steps + 1):
        a = (math.pi - phi) + 2 * phi * (i / steps)
        pts.append((C + DX + R * math.cos(a), C + R * math.sin(a)))
    return pts


def build() -> Image.Image:
    # 1. Sky: night above, warm light gathering behind the break, deepening again at the base so the
    #    lower third does not go muddy brown.
    img = vertical_sky(W, [(0.0, NIGHT), (0.32, DEEP), (0.56, VIOLET),
                           (0.74, lerp(VIOLET, EMBER, 0.40)),
                           (0.88, lerp(EMBER, NIGHT, 0.30)), (1.0, NIGHT)])

    # 2. Cloud strata.
    img = screen(img, haze_bands(W, 4, lerp(VIOLET, AMBER, 0.30), count=11,
                                 blur=int(11 * SS), strength=0.42))

    # 3. Stars, kept clear of the subject — scattered across it they read as falling snow.
    stars(ImageDraw.Draw(img), W, 8, 150, CREAM, y_max=0.60, avoid=(C, C, R * 1.15))

    # 4. The light behind the break, and its shafts.
    img = screen(img, radial_light(W, C, C, W * 0.46, lerp(AMBER, CREAM, 0.35), falloff=2.1))
    img = screen(img, god_rays(W, C, C, lerp(AMBER, CREAM, 0.5), seed=6, count=30,
                               blur=int(7 * SS), strength=0.34))

    # 5. The mandorla: graded light, clipped to the lens. Built as a blurred radial mask multiplied by
    #    the lens stencil, so the falloff follows the shape instead of banding.
    core = Image.new("L", (W, W), 0)
    cd = ImageDraw.Draw(core)
    for i in range(150, 0, -1):
        s = i / 150
        rx, ry = int(W * 0.165 * s), int(W * 0.285 * s)
        cd.ellipse([C - rx, C - ry, C + rx, C + ry], fill=int(255 * (1 - s) ** 1.05))
    core = core.filter(ImageFilter.GaussianBlur(int(4 * SS)))
    stencil = Image.new("L", (W, W), 0)
    ImageDraw.Draw(stencil).polygon(_lens(), fill=255)
    img.paste(Image.new("RGB", (W, W), CREAM), (0, 0), ImageChops.multiply(core, stencil))

    # 6. The construction, crisp over the atmosphere: both generating circles plus the lens edge, so a
    #    viewer can see the light appears exactly where the two agree.
    d = ImageDraw.Draw(img)
    for cx in (C - DX, C + DX):
        d.ellipse([cx - R, C - R, cx + R, C + R], outline=lerp(AMBER, GOLD, 0.40),
                  width=int(2.4 * SS))
    lens = _lens()
    d.line(lens + [lens[0]], fill=GOLD, width=int(4.2 * SS), joint="curve")

    # 7. The ruling, standing in the light. Of the three marks only this one carries a checkmark.
    ck = [(C - int(W * 0.055), C + int(W * 0.004)),
          (C - int(W * 0.015), C + int(W * 0.043)),
          (C + int(W * 0.061), C - int(W * 0.049))]
    g = Image.new("RGB", (W, W), (0, 0, 0))
    ImageDraw.Draw(g).line(ck, fill=(24, 116, 90), width=int(18 * SS), joint="curve")
    img = screen(img, g.filter(ImageFilter.GaussianBlur(int(8 * SS))))
    d = ImageDraw.Draw(img)
    # Dark backing: saturated green over near-white light would otherwise lose its edge entirely.
    d.line(ck, fill=(14, 40, 34), width=int(14 * SS), joint="curve")
    d.line(ck, fill=VERDICT, width=int(9.5 * SS), joint="curve")
    d.line(ck, fill=VERDICT_HI, width=int(3.2 * SS), joint="curve")

    img = bloom(img, radius=int(9 * SS), strength=0.40, threshold=175)
    out = img.resize((SIZE, SIZE), Image.LANCZOS)
    grain(out, amount=5)
    return out


def main() -> None:
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "brand")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "aletheia_avatar_440.png")
    img = build()
    img.save(out, "PNG", optimize=True)
    px = img.load()
    print(f"wrote {out}")
    print(f"  {img.size[0]}x{img.size[1]} {img.mode}  bytes {os.path.getsize(out):,}")
    print(f"  corners {[px[x, y] for x, y in ((0, 0), (SIZE - 1, 0), (0, SIZE - 1), (SIZE - 1, SIZE - 1))]}")
    for n in (96, 48):
        img.resize((n, n), Image.LANCZOS).resize((n * 4, n * 4), Image.NEAREST).save(
            os.path.join(out_dir, f"_check_{n}.png"))


if __name__ == "__main__":
    main()
