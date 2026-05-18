"""Generate the AEGIS brand assets (deterministic, no network).

Outputs into ./assets:
  aegis_mark.png   512x512 shield mark (used by the GUI header)
  aegis_logo.png   1280x320 mark + wordmark (docs / app about)
Run:  python3 assets/make_logo.py
"""

from __future__ import annotations

import math
import os

from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))

# Brand palette --------------------------------------------------------------
BG = (11, 15, 28, 0)
CYAN = (34, 211, 238)
VIOLET = (139, 92, 246)
MAGENTA = (232, 121, 249)
LIME = (163, 230, 53)
INK = (233, 240, 255)


def _font(size: int, bold: bool = True):
    for p in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ):
        if os.path.exists(p):
            return ImageFont.truetype(p, size)
    return ImageFont.load_default()


def _lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _grad_poly(size, pts, c0, c1, c2):
    """Diagonal 3-stop gradient clipped to a polygon."""
    w, h = size
    grad = Image.new("RGB", (w, h))
    px = grad.load()
    for y in range(h):
        for x in range(w):
            t = (x + y) / (w + h)
            px[x, y] = _lerp(c0, c1, t * 2) if t < 0.5 else _lerp(c1, c2, (t - 0.5) * 2)
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).polygon(pts, fill=255)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out.paste(grad, (0, 0), mask)
    return out


def _hexagon(cx, cy, r, rot=math.pi / 6):
    return [
        (cx + r * math.cos(rot + i * math.pi / 3),
         cy + r * math.sin(rot + i * math.pi / 3))
        for i in range(6)
    ]


def make_mark(px: int = 512) -> Image.Image:
    S = px * 3  # supersample
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    cx = cy = S / 2

    # Outer glow rings
    for i, col in enumerate((VIOLET, CYAN)):
        ring = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        ImageDraw.Draw(ring).polygon(
            _hexagon(cx, cy, S * (0.46 - i * 0.015)), outline=col + (160,),
            width=int(S * 0.012))
        ring = ring.filter(ImageFilter.GaussianBlur(S * 0.02))
        img = Image.alpha_composite(img, ring)

    d = ImageDraw.Draw(img)
    hex_pts = _hexagon(cx, cy, S * 0.44)
    # Glass body
    body = _grad_poly((S, S), hex_pts, (18, 24, 44), (26, 22, 56), (40, 18, 60))
    img = Image.alpha_composite(img, body)
    d = ImageDraw.Draw(img)
    d.polygon(hex_pts, outline=CYAN + (220,), width=int(S * 0.01))

    # Shield silhouette
    sw, sh = S * 0.30, S * 0.36
    shield = [
        (cx, cy - sh * 0.95),
        (cx + sw, cy - sh * 0.55),
        (cx + sw, cy + sh * 0.15),
        (cx, cy + sh),
        (cx - sw, cy + sh * 0.15),
        (cx - sw, cy - sh * 0.55),
    ]
    sh_grad = _grad_poly((S, S), shield, CYAN, VIOLET, MAGENTA)
    img = Image.alpha_composite(img, sh_grad)
    d = ImageDraw.Draw(img)

    # Stylised "A" / chevron lock
    lw = int(S * 0.028)
    d.line([(cx, cy - sh * 0.55), (cx - sw * 0.62, cy + sh * 0.55)],
           fill=(11, 15, 28, 255), width=lw)
    d.line([(cx, cy - sh * 0.55), (cx + sw * 0.62, cy + sh * 0.55)],
           fill=(11, 15, 28, 255), width=lw)
    d.line([(cx - sw * 0.34, cy + sh * 0.06), (cx + sw * 0.34, cy + sh * 0.06)],
           fill=(11, 15, 28, 255), width=lw)
    d.ellipse([cx - S * 0.022, cy - sh * 0.62, cx + S * 0.022, cy - sh * 0.40],
              fill=LIME + (255,))

    # Top sheen
    sheen = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(sheen).polygon(
        [(cx - S * 0.30, cy - S * 0.40), (cx + S * 0.18, cy - S * 0.42),
         (cx - S * 0.05, cy - S * 0.06), (cx - S * 0.34, cy - S * 0.05)],
        fill=(255, 255, 255, 26))
    img = Image.alpha_composite(img, sheen.filter(ImageFilter.GaussianBlur(S * 0.01)))

    return img.resize((px, px), Image.LANCZOS)


def make_logo() -> Image.Image:
    W, H = 1280, 320
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    mark = make_mark(260)
    img.alpha_composite(mark, (28, (H - 260) // 2))

    d = ImageDraw.Draw(img)
    f = _font(132)
    word = "AEGIS"
    x0, y0 = 320, 70
    # Gradient wordmark
    bbox = d.textbbox((0, 0), word, font=f)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tile = Image.new("RGB", (tw, th))
    tp = tile.load()
    for x in range(tw):
        t = x / max(1, tw)
        c = _lerp(CYAN, VIOLET, t * 2) if t < 0.5 else _lerp(VIOLET, MAGENTA, (t - .5) * 2)
        for y in range(th):
            tp[x, y] = c
    m = Image.new("L", (tw, th), 0)
    ImageDraw.Draw(m).text((-bbox[0], -bbox[1]), word, font=f, fill=255)
    img.paste(tile, (x0, y0), m)

    d.text((x0 + 4, y0 + 150), "AUTONOMOUS API STRESS & SECURITY INTELLIGENCE",
           font=_font(31, bold=True), fill=INK)
    d.text((x0 + 4, y0 + 196),
           "Offensive  +  Defensive   ·   Education & Research Edition",
           font=_font(26, bold=False), fill=CYAN)
    return img


def main() -> None:
    os.makedirs(HERE, exist_ok=True)
    make_mark(512).save(os.path.join(HERE, "aegis_mark.png"))
    make_logo().save(os.path.join(HERE, "aegis_logo.png"))
    # GUI uses a 128px mark; pre-size for crispness.
    make_mark(128).save(os.path.join(HERE, "aegis_mark_128.png"))
    print("wrote assets/aegis_mark.png, aegis_mark_128.png, aegis_logo.png")


if __name__ == "__main__":
    main()
