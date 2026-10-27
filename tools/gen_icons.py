"""Generates the app's vector icons and logo as Android VectorDrawable XML.

Everything is drawn from a few geometric helpers on a 24-unit grid (line icons: 1.8 stroke, round caps and joins),
so the set stays consistent and is reproducible. Only the path commands M L H V C Q Z are used (no arcs), which keeps
the data valid for Android's parser and for tools/IconPreview.java, the host renderer used to check the shapes.

Run:  python tools/gen_icons.py        (writes app/src/main/res/drawable/ic_*.xml and mipmap-anydpi-v26/ic_launcher*.xml)
Original artwork for this project; no third-party icon data is used.
"""
import math
import os
from pathlib import Path

RES = Path(__file__).resolve().parents[1] / "app/src/main/res"
K = 0.5522847498  # cubic approximation of a quarter circle


def n(v):
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s


def P(*cmds):
    return " ".join(cmds)


def M(x, y): return f"M{n(x)} {n(y)}"
def L(x, y): return f"L{n(x)} {n(y)}"
def H(x): return f"H{n(x)}"
def V(y): return f"V{n(y)}"
def Q(cx, cy, x, y): return f"Q{n(cx)} {n(cy)} {n(x)} {n(y)}"
def C(a, b, c, d, x, y): return f"C{n(a)} {n(b)} {n(c)} {n(d)} {n(x)} {n(y)}"
Z = "Z"


def circle(cx, cy, r):
    k = K * r
    return P(M(cx + r, cy), C(cx + r, cy + k, cx + k, cy + r, cx, cy + r), C(cx - k, cy + r, cx - r, cy + k, cx - r, cy),
             C(cx - r, cy - k, cx - k, cy - r, cx, cy - r), C(cx + k, cy - r, cx + r, cy - k, cx + r, cy), Z)


def arc(cx, cy, r, a0, a1, move=True):
    """Arc from angle a0 to a1 (degrees, 0 = right, 90 = down) as cubic segments of at most 90 degrees."""
    out = []
    steps = max(1, int(math.ceil(abs(a1 - a0) / 90.0)))
    da = math.radians((a1 - a0) / steps)
    t = 4.0 / 3.0 * math.tan(da / 4.0)
    a = math.radians(a0)
    x0, y0 = cx + r * math.cos(a), cy + r * math.sin(a)
    if move:
        out.append(M(x0, y0))
    for _ in range(steps):
        b = a + da
        x1, y1 = x0 - t * r * math.sin(a), y0 + t * r * math.cos(a)
        x3, y3 = cx + r * math.cos(b), cy + r * math.sin(b)
        x2, y2 = x3 + t * r * math.sin(b), y3 - t * r * math.cos(b)
        out.append(C(x1, y1, x2, y2, x3, y3))
        a, x0, y0 = b, x3, y3
    return P(*out)


def rrect(x, y, w, h, r):
    k = K * r
    return P(M(x + r, y), H(x + w - r), C(x + w - r + k, y, x + w, y + r - k, x + w, y + r), V(y + h - r),
             C(x + w, y + h - r + k, x + w - r + k, y + h, x + w - r, y + h), H(x + r),
             C(x + r - k, y + h, x, y + h - r + k, x, y + h - r), V(y + r), C(x, y + r - k, x + r - k, y, x + r, y), Z)


def dot(x, y):  # a round-capped zero-length line renders as a dot in stroke icons
    return P(M(x, y), L(x, y + .01))


STROKE = 'android:strokeColor="#FFFFFFFF" android:strokeWidth="{w}" android:strokeLineCap="round" android:strokeLineJoin="round"'


def vector(paths, size=24, viewport=24):
    body = "\n".join("    " + p for p in paths)
    return (f'<vector xmlns:android="http://schemas.android.com/apk/res/android"\n    android:width="{size}dp" android:height="{size}dp"\n'
            f'    android:viewportWidth="{viewport}" android:viewportHeight="{viewport}">\n{body}\n</vector>\n')


def stroke(d, w=1.8):
    return f'<path android:pathData="{d}" {STROKE.format(w=n(w))}/>'


def fill(d, color="#FFFFFFFF", extra=""):
    return f'<path android:pathData="{d}" android:fillColor="{color}"{(" " + extra) if extra else ""}/>'


SHIELD = P(M(12, 2.8), L(19.6, 5.7), V(11.4), C(19.6, 16.1, 16.5, 19.7, 12, 21.2), C(7.5, 19.7, 4.4, 16.1, 4.4, 11.4), V(5.7), Z)

ICONS = {
    "ic_home": [stroke(P(M(3.8, 11.2), L(12, 4), L(20.2, 11.2))), stroke(P(M(6, 9.6), V(19.2), Q(6, 20.3, 7.1, 20.3), H(16.9), Q(18, 20.3, 18, 19.2), V(9.6))), stroke(P(M(10, 20.3), V(14.6), H(14), V(20.3)))],
    "ic_check": [stroke(circle(10.5, 10.5, 6.3)), stroke(P(M(15.2, 15.2), L(20.2, 20.2))), stroke(P(M(7.9, 10.7), L(9.9, 12.7), L(13.2, 8.7)))],
    "ic_shield": [stroke(SHIELD), stroke(P(M(8.7, 11.8), L(11, 14.1), L(15.4, 9.4)))],
    "ic_more": [fill(circle(5.5, 12, 1.7)), fill(circle(12, 12, 1.7)), fill(circle(18.5, 12, 1.7))],
    "ic_link": [stroke(P(M(11, 8.8), H(6.2), Q(3.2, 8.8, 3.2, 12), Q(3.2, 15.2, 6.2, 15.2), H(11))), stroke(P(M(13, 8.8), H(17.8), Q(20.8, 8.8, 20.8, 12), Q(20.8, 15.2, 17.8, 15.2), H(13))), stroke(P(M(8.6, 12), H(15.4)))],
    "ic_message": [stroke(P(M(7, 4.5), H(17), Q(19.5, 4.5, 19.5, 7), V(13.5), Q(19.5, 16, 17, 16), H(11.8), L(7.6, 19.6), V(16), Q(4.5, 16, 4.5, 13.5), V(7), Q(4.5, 4.5, 7, 4.5), Z)), stroke(P(M(8.6, 9), H(15.4), M(8.6, 12), H(13)))],
    "ic_file": [stroke(P(M(12, 3.4), L(19.6, 7.6), V(16.4), L(12, 20.6), L(4.4, 16.4), V(7.6), Z)), stroke(P(M(4.7, 7.8), L(12, 12), L(19.3, 7.8), M(12, 12), V(20.4)))],
    "ic_globe": [stroke(circle(12, 12, 8.6)), stroke(P(M(3.4, 12), H(20.6))), stroke(P(M(12, 3.4), C(9.2, 6, 8.3, 9, 8.3, 12), C(8.3, 15, 9.2, 18, 12, 20.6), C(14.8, 18, 15.7, 15, 15.7, 12), C(15.7, 9, 14.8, 6, 12, 3.4), Z))],
    "ic_agent": [stroke(rrect(5, 8.2, 14, 10.2, 3)), stroke(P(M(12, 8.2), V(5.6))), fill(circle(12, 4.6, 1.3)), fill(circle(9.2, 13.2, 1.15)), fill(circle(14.8, 13.2, 1.15)), stroke(P(M(2.9, 12), V(14.6), M(21.1, 12), V(14.6)))],
    "ic_database": [stroke(P(M(5, 6.6), C(5, 5.1, 8.1, 4, 12, 4), C(15.9, 4, 19, 5.1, 19, 6.6), C(19, 8.1, 15.9, 9.2, 12, 9.2), C(8.1, 9.2, 5, 8.1, 5, 6.6), Z)), stroke(P(M(5, 6.6), V(17.4), C(5, 18.9, 8.1, 20, 12, 20), C(15.9, 20, 19, 18.9, 19, 17.4), V(6.6))), stroke(P(M(5, 12), C(5, 13.5, 8.1, 14.6, 12, 14.6), C(15.9, 14.6, 19, 13.5, 19, 12)))],
    "ic_phone": [stroke(rrect(6.8, 3, 10.4, 18, 2.6)), stroke(P(M(10.4, 18), H(13.6)))],
    "ic_sparkle": [stroke(P(M(12, 3.2), C(12.6, 8.2, 15.8, 11.4, 20.8, 12), C(15.8, 12.6, 12.6, 15.8, 12, 20.8), C(11.4, 15.8, 8.2, 12.6, 3.2, 12), C(8.2, 11.4, 11.4, 8.2, 12, 3.2), Z)), stroke(P(M(19, 3.6), V(6.4), M(17.6, 5), H(20.4)), 1.5)],
    "ic_lock": [stroke(rrect(5.4, 10.4, 13.2, 9.8, 2.6)), stroke(P(M(8.4, 10.4), V(8), C(8.4, 6, 9.9, 4.4, 12, 4.4), C(14.1, 4.4, 15.6, 6, 15.6, 8), V(10.4))), stroke(dot(12, 15.3), 2.2)],
    "ic_info": [stroke(circle(12, 12, 8.8)), stroke(P(M(12, 11.2), V(16.4))), stroke(dot(12, 7.9), 2.1)],
    "ic_alert": [stroke(circle(12, 12, 8.8)), stroke(P(M(12, 7.4), V(12.9))), stroke(dot(12, 16.4), 2.1)],
    "ic_warn": [stroke(P(M(12, 3.9), L(21, 19.4), H(3), Z)), stroke(P(M(12, 9.6), V(14))), stroke(dot(12, 16.7), 2.1)],
    "ic_cross": [stroke(circle(12, 12, 8.8)), stroke(P(M(8.8, 8.8), L(15.2, 15.2), M(15.2, 8.8), L(8.8, 15.2)))],
    "ic_help": [stroke(circle(12, 12, 8.8)), stroke(P(M(9.6, 9.7), C(9.6, 8.3, 10.7, 7.5, 12, 7.5), C(13.3, 7.5, 14.4, 8.3, 14.4, 9.5), C(14.4, 11, 12, 11.2, 12, 13.2)), 1.7), stroke(dot(12, 16.4), 2.1)],
    "ic_chevron": [stroke(P(M(9.4, 5.6), L(15.8, 12), L(9.4, 18.4)))],
    "ic_paste": [stroke(rrect(5.6, 5.2, 12.8, 15.4, 2.2)), stroke(rrect(9, 3, 6, 4.2, 1.4)), stroke(P(M(9, 11.4), H(15), M(9, 14.6), H(13.2)))],
    "ic_power": [stroke(P(M(12, 3.6), V(11))), stroke(arc(12, 13, 7.6, -52, 232))],
}


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def thick_polyline(points, w):
    """Closed polygon around a polyline of the given width (butt ends, averaged normals at joints)."""
    left, right = [], []
    for i, (x, y) in enumerate(points):
        if i == 0: dx, dy = points[1][0] - x, points[1][1] - y
        elif i == len(points) - 1: dx, dy = x - points[i - 1][0], y - points[i - 1][1]
        else: dx, dy = points[i + 1][0] - points[i - 1][0], points[i + 1][1] - points[i - 1][1]
        ln = math.hypot(dx, dy) or 1
        nx, ny = -dy / ln * w / 2, dx / ln * w / 2
        left.append((x + nx, y + ny)); right.append((x - nx, y - ny))
    pts = left + right[::-1]
    return P(M(*pts[0]), *[L(*q) for q in pts[1:]], Z)


MARK_SCALE = 1.2  # the mark fills about 60% of the 108-unit adaptive-icon canvas (safe zone is 61%)


def mk(v):  # scale a coordinate of the mark around the canvas centre
    return 54 + (v - 54) * MARK_SCALE


def mpts(*pts):
    return [(mk(x), mk(y)) for x, y in pts]


def mark_geometry():
    top, bottom, left, right, side = 30, 78, 34, 74, 55
    sh_l = P(M(mk(54), mk(top)), L(mk(left), mk(38)), V(mk(side)), C(mk(left), mk(66), mk(42), mk(74), mk(54), mk(bottom)), Z)
    sh_r = P(M(mk(54), mk(top)), L(mk(right), mk(38)), V(mk(side)), C(mk(right), mk(66), mk(66), mk(74), mk(54), mk(bottom)), Z)
    shield = P(M(mk(54), mk(top)), L(mk(right), mk(38)), V(mk(side)), C(mk(right), mk(66), mk(66), mk(74), mk(54), mk(bottom)),
               C(mk(42), mk(74), mk(left), mk(66), mk(left), mk(side)), V(mk(38)), Z)
    cx, cy, r = mk(53), mk(52), 10.5 * MARK_SCALE
    handle_pts = mpts((60.6, 59.6), (67, 66))
    tick_pts = mpts((48.2, 52.4), (51.7, 55.9), (58, 48.6))
    return sh_l, sh_r, shield, (cx, cy, r), handle_pts, tick_pts


def launcher():
    sh_l, sh_r, shield, (cx, cy, r), handle_pts, tick_pts = mark_geometry()
    navy = "#FF0A1118"
    lens = stroke(circle(cx, cy, r), 3.4 * MARK_SCALE).replace("#FFFFFFFF", navy)
    handle = stroke(P(M(*handle_pts[0]), L(*handle_pts[1])), 3.8 * MARK_SCALE).replace("#FFFFFFFF", navy)
    tick = stroke(P(M(*tick_pts[0]), L(*tick_pts[1]), L(*tick_pts[2])), 3.2 * MARK_SCALE).replace("#FFFFFFFF", navy)
    fg = vector([fill(sh_l, "#FF8CF0C8"), fill(sh_r, "#FF4FD2A0"), lens, handle, tick], 108, 108)
    # Monochrome (themed icons): one shape, with the lens ring, handle and tick cut out by even-odd winding.
    ring = circle(cx, cy, r + 1.7 * MARK_SCALE) + " " + circle(cx, cy, r - 1.7 * MARK_SCALE)
    mono = vector([fill(shield + " " + ring + " " + thick_polyline(handle_pts, 3.8 * MARK_SCALE) + " " + thick_polyline(tick_pts, 3.2 * MARK_SCALE), "#FF000000", 'android:fillType="evenOdd"')], 108, 108)
    stat = vector([fill(shield + " " + ring + " " + thick_polyline(handle_pts, 3.8 * MARK_SCALE) + " " + thick_polyline(tick_pts, 3.2 * MARK_SCALE), "#FFFFFFFF", 'android:fillType="evenOdd"')], 108, 108)
    bg = vector([fill(P(M(0, 0), H(108), V(108), H(0), Z), "#FF0A1118"), fill(P(M(0, 108), L(108, 0), V(108), Z), "#FF0F1D29")], 108, 108)
    write(RES / "drawable/ic_launcher_foreground.xml", fg)
    write(RES / "drawable/ic_launcher_background.xml", bg)
    write(RES / "drawable/ic_launcher_monochrome.xml", mono)
    write(RES / "drawable/ic_logo.xml", fg)
    write(RES / "drawable/ic_stat_aegis.xml", stat)
    adaptive = ('<?xml version="1.0" encoding="utf-8"?>\n<adaptive-icon xmlns:android="http://schemas.android.com/apk/res/android">\n'
                '    <background android:drawable="@drawable/ic_launcher_background" />\n    <foreground android:drawable="@drawable/ic_launcher_foreground" />\n'
                '    <monochrome android:drawable="@drawable/ic_launcher_monochrome" />\n</adaptive-icon>\n')
    write(RES / "mipmap-anydpi-v26/ic_launcher.xml", adaptive)
    write(RES / "mipmap-anydpi-v26/ic_launcher_round.xml", adaptive)


def main():
    for name, paths in ICONS.items():
        write(RES / f"drawable/{name}.xml", vector(paths))
    launcher()
    print(f"wrote {len(ICONS)} icons + launcher/logo/status-bar assets under {RES}")


if __name__ == "__main__":
    main()
