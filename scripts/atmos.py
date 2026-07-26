"""Atmospheric rendering toolkit — the look code can actually achieve well.

An earlier attempt stamped tens of thousands of impasto strokes to imitate an oil painting. It produced
convincing *texture* and an unconvincing *picture*: uniform stroke fields read as wood grain, textile or
fur, because a painting's beauty lives in its composition and subject, not in its bristle marks.
Reference images made by an image model are not reachable this way.

What code renders genuinely well is LIGHT: deep smooth gradients, volumetric haze, god-rays, bloom,
grain. That is the register here — mythic atmosphere behind crisp classical geometry. Nearer a title
card than a canvas, and honest about being one.

No human figures and no faces anywhere: a human head in profile is a documented instant rejection on
this marketplace.
"""
from __future__ import annotations

import math
import random

from PIL import Image, ImageChops, ImageDraw, ImageFilter

RGB = tuple[int, int, int]


def lerp(a: RGB, b: RGB, t: float) -> RGB:
    t = max(0.0, min(1.0, t))
    return (int(a[0] + (b[0] - a[0]) * t),
            int(a[1] + (b[1] - a[1]) * t),
            int(a[2] + (b[2] - a[2]) * t))


def ramp(stops: list[tuple[float, RGB]], t: float) -> RGB:
    """Sample a multi-stop colour ramp. Stops must be sorted by position."""
    t = max(0.0, min(1.0, t))
    for i in range(len(stops) - 1):
        p0, c0 = stops[i]
        p1, c1 = stops[i + 1]
        if p0 <= t <= p1:
            span = (p1 - p0) or 1.0
            return lerp(c0, c1, (t - p0) / span)
    return stops[-1][1]


def vertical_sky(size: int, stops: list[tuple[float, RGB]]) -> Image.Image:
    """A smooth vertical gradient — what every atmospheric image starts from."""
    img = Image.new("RGB", (size, size))
    d = ImageDraw.Draw(img)
    for y in range(size):
        d.line([0, y, size, y], fill=ramp(stops, y / (size - 1)))
    return img


def radial_light(size: int, cx: float, cy: float, radius: float, colour: RGB,
                 falloff: float = 1.6, steps: int = 170) -> Image.Image:
    """A soft radial glow on black, ready to be screened over the sky."""
    layer = Image.new("RGB", (size, size), (0, 0, 0))
    d = ImageDraw.Draw(layer)
    for i in range(steps, 0, -1):
        s = i / steps
        r = radius * s
        v = (1.0 - s) ** falloff
        d.ellipse([cx - r, cy - r, cx + r, cy + r],
                  fill=(int(colour[0] * v), int(colour[1] * v), int(colour[2] * v)))
    return layer


def haze_bands(size: int, seed: int, colour: RGB, count: int = 9,
               blur: int = 40, strength: float = 0.5) -> Image.Image:
    """Drifting cloud strata. Blurred ellipses, not strokes: at this scale cloud is a density, and
    painting it as bristle marks is exactly what made the earlier version look like fabric."""
    rng = random.Random(seed)
    layer = Image.new("RGB", (size, size), (0, 0, 0))
    d = ImageDraw.Draw(layer)
    for _ in range(count):
        cy = rng.uniform(size * 0.05, size * 0.95)
        h = rng.uniform(size * 0.020, size * 0.085)
        w = rng.uniform(size * 0.40, size * 1.25)
        cx = rng.uniform(size * 0.10, size * 0.90)
        v = rng.uniform(0.35, 1.0) * strength
        d.ellipse([cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2],
                  fill=(int(colour[0] * v), int(colour[1] * v), int(colour[2] * v)))
    return layer.filter(ImageFilter.GaussianBlur(blur))


def god_rays(size: int, cx: float, cy: float, colour: RGB, seed: int = 3,
             count: int = 26, blur: int = 26, strength: float = 0.42) -> Image.Image:
    """Shafts of light from one source — the cheapest honest signal of the sacred."""
    rng = random.Random(seed)
    layer = Image.new("RGB", (size, size), (0, 0, 0))
    d = ImageDraw.Draw(layer)
    for _ in range(count):
        a = rng.uniform(0, math.tau)
        ln = size * rng.uniform(0.30, 0.95)
        spread = rng.uniform(0.010, 0.045)
        v = rng.uniform(0.30, 1.0) * strength
        col = (int(colour[0] * v), int(colour[1] * v), int(colour[2] * v))
        d.polygon([(cx, cy),
                   (cx + math.cos(a - spread) * ln, cy + math.sin(a - spread) * ln),
                   (cx + math.cos(a + spread) * ln, cy + math.sin(a + spread) * ln)], fill=col)
    return layer.filter(ImageFilter.GaussianBlur(blur))


def screen(base: Image.Image, layer: Image.Image) -> Image.Image:
    """Add light without ever darkening. Image.blend against a mostly-black layer dims the whole frame
    by the blend factor — the classic way a glow pass ruins an image."""
    return ImageChops.lighter(base, layer)


def bloom(img: Image.Image, radius: int, strength: float = 0.5, threshold: int = 170) -> Image.Image:
    grey = img.convert("L")
    mask = grey.point(lambda v: 255 if v > threshold else 0)
    lit = Image.new("RGB", img.size, (0, 0, 0))
    lit.paste(img, (0, 0), mask)
    lit = lit.filter(ImageFilter.GaussianBlur(radius))
    return ImageChops.lighter(img, Image.eval(lit, lambda v: int(v * strength)))


def grain(img: Image.Image, seed: int = 11, amount: int = 7) -> None:
    """Fine film grain. Keeps large smooth gradients from banding like flat digital fills."""
    rng = random.Random(seed)
    W, H = img.size
    px = img.load()
    for y in range(0, H, 2):
        for x in range(0, W, 2):
            v = rng.randint(-amount, amount)
            r, g, b = px[x, y]
            px[x, y] = (max(0, min(255, r + v)), max(0, min(255, g + v)), max(0, min(255, b + v)))


def stars(d: ImageDraw.ImageDraw, size: int, seed: int, count: int, colour: RGB,
          y_max: float = 0.62, avoid: tuple[float, float, float] | None = None) -> None:
    """Sparse points of light — the cosmic note from the second reference, without its humanoid figure.

    `avoid` is (cx, cy, radius): no star is placed inside it. Without that exclusion, stars scatter
    across the bright subject and read as dust or falling snow rather than as a night sky behind it.
    Radii stay under ~1.6px at final scale for the same reason — a 3px dot is a snowflake, not a star.
    """
    rng = random.Random(seed)
    placed = 0
    guard = 0
    while placed < count and guard < count * 40:
        guard += 1
        x = rng.uniform(0, size)
        y = rng.uniform(0, size * y_max)
        if avoid and math.hypot(x - avoid[0], y - avoid[1]) < avoid[2]:
            continue
        r = rng.uniform(0.5, 1.6) * (size / 440)
        v = rng.uniform(0.30, 1.0)
        d.ellipse([x - r, y - r, x + r, y + r],
                  fill=(int(colour[0] * v), int(colour[1] * v), int(colour[2] * v)))
        placed += 1
