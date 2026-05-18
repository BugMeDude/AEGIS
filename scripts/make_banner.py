"""Generate an animated hero banner GIF for the README (deterministic).

Run:  python3 scripts/make_banner.py   ->   assets/banner.gif
"""
from __future__ import annotations

import math
import os

from PIL import Image, ImageDraw, ImageFilter, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASSETS = os.path.join(ROOT, "assets")
W, H, FRAMES = 1280, 360, 36

CYAN, VIOLET, MAGENTA = (34, 211, 238), (139, 92, 246), (232, 121, 249)
INK, MUT = (233, 240, 255), (139, 155, 196)


def font(sz, bold=True):
    p = ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
         else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    return ImageFont.truetype(p, sz) if os.path.exists(p) else \
        ImageFont.load_default()


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def grad3(t):
    return lerp(CYAN, VIOLET, t * 2) if t < .5 else lerp(VIOLET, MAGENTA,
                                                         (t - .5) * 2)


def frame(k: int) -> Image.Image:
    ph = k / FRAMES
    img = Image.new("RGB", (W, H), (8, 11, 22))
    d = ImageDraw.Draw(img)
    # vertical bg gradient
    for y in range(H):
        d.line([(0, y), (W, y)],
               fill=lerp((8, 11, 22), (18, 12, 36), y / H))
    # drifting glow blobs
    glow = Image.new("RGB", (W, H), (0, 0, 0))
    gd = ImageDraw.Draw(glow)
    for i, base in enumerate(((CYAN), (VIOLET), (MAGENTA))):
        bx = int(W * (0.2 + 0.6 * ((math.sin(2 * math.pi * (ph + i / 3)) + 1) / 2)))
        by = int(H * (0.3 + 0.4 * (i / 3)))
        for r in range(220, 0, -18):
            gd.ellipse([bx - r, by - r, bx + r, by + r],
                       fill=tuple(int(c * (1 - r / 220) * 0.5) for c in base))
    glow = glow.filter(ImageFilter.GaussianBlur(60))
    img = Image.blend(img, Image.composite(
        glow, img, glow.convert("L").point(lambda v: min(255, v * 3))), 0.55)
    d = ImageDraw.Draw(img)

    # logo mark
    mp = os.path.join(ASSETS, "aegis_mark.png")
    if os.path.exists(mp):
        m = Image.open(mp).convert("RGBA").resize((220, 220), Image.LANCZOS)
        pulse = 1 + 0.03 * math.sin(2 * math.pi * ph)
        ms = m.resize((int(220 * pulse), int(220 * pulse)), Image.LANCZOS)
        img.paste(ms, (70, (H - ms.height) // 2), ms)

    # animated gradient wordmark with moving sweep
    word = "AEGIS"
    f = font(150)
    bb = d.textbbox((0, 0), word, font=f)
    tw, th = bb[2] - bb[0], bb[3] - bb[1]
    tile = Image.new("RGB", (tw, th))
    tp = tile.load()
    for x in range(tw):
        t = (x / tw + ph) % 1.0
        for y in range(th):
            tp[x, y] = grad3(t)
    mask = Image.new("L", (tw, th), 0)
    ImageDraw.Draw(mask).text((-bb[0], -bb[1]), word, font=f, fill=255)
    x0, y0 = 330, 70
    img.paste(tile, (x0, y0), mask)

    d.text((x0 + 4, y0 + 165),
           "AUTONOMOUS  API  STRESS  &  SECURITY  INTELLIGENCE",
           font=font(26), fill=INK)
    d.text((x0 + 4, y0 + 205),
           "AI-driven  ·  Offensive + Defensive  ·  Education & Research",
           font=font(22, bold=False), fill=grad3((ph * 1.5) % 1.0))

    # moving underline shimmer
    for i in range(tw):
        t = (i / tw + ph * 2) % 1.0
        d.line([(x0 + i, y0 + 158), (x0 + i, y0 + 162)], fill=grad3(t))
    return img


def main():
    frames = [frame(k) for k in range(FRAMES)]
    frames[0].save(os.path.join(ASSETS, "banner.gif"), save_all=True,
                   append_images=frames[1:], duration=70, loop=0,
                   optimize=True)
    frames[0].save(os.path.join(ASSETS, "banner.png"))
    print("wrote assets/banner.gif (%d frames) + banner.png" % FRAMES)


if __name__ == "__main__":
    main()
