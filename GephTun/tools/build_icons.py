#!/usr/bin/env python3
"""Rebuild GephTun's tunnel badge. Requires Pillow for authoring only."""
from pathlib import Path
import struct

from PIL import Image, ImageDraw


ASSETS = Path(__file__).resolve().parents[1] / 'assets'
SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)
COLORS = {
    'GephTun': ('#12243D', '#70C9FF'),
    'GephTun-Idle': ('#6B7788', '#12243D'),
    'GephTun-Busy': ('#1767D2', '#12243D'),
    'GephTun-Connected': ('#167348', '#12243D'),
    'GephTun-Warning': ('#956200', '#12243D'),
    'GephTun-Error': ('#B42B37', '#12243D'),
}


def badge(background, route):
    # Draw at 8x the 100-unit SVG grid, then antialias for each Windows size.
    scale = 8
    canvas = Image.new('RGBA', (800, 800))
    draw = ImageDraw.Draw(canvas)

    def box(coords):
        return tuple(round(v * scale) for v in coords)

    draw.ellipse(box((2, 2, 98, 98)), fill=background)
    draw.pieslice(box((24, 20, 76, 72)), 180, 360, fill='white')
    draw.rectangle(box((24, 46, 76, 76)), fill='white')
    draw.pieslice(box((38, 34, 62, 58)), 180, 360, fill=background)
    draw.rectangle(box((38, 46, 62, 77)), fill=background)
    draw.polygon([box(p) for p in ((49, 58), (70, 58), (70, 49),
                                 (85, 64), (70, 79), (70, 70), (49, 70))], fill=route)
    return canvas


def main():
    ASSETS.mkdir(exist_ok=True)
    for name, (background, route) in COLORS.items():
        bitmap = badge(background, route)
        # .NET Framework's Icon.ToBitmap cannot reliably read PNG-compressed
        # ICO entries. Use 32-bit Windows DIB frames with alpha and AND masks.
        frames = []
        for size in SIZES:
            frame = bitmap.resize((size, size), Image.Resampling.LANCZOS)
            flipped = frame.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
            pixels = flipped.tobytes('raw', 'BGRA')
            alpha = flipped.getchannel('A')
            stride = ((size + 31) // 32) * 4
            mask = bytearray(stride * size)
            for y in range(size):
                for x in range(size):
                    if alpha.getpixel((x, y)) == 0:
                        mask[y * stride + x // 8] |= 0x80 >> (x % 8)
            header = struct.pack('<IiiHHIIiiII', 40, size, size * 2, 1, 32,
                                 0, len(pixels), 0, 0, 0, 0)
            frames.append(header + pixels + mask)
        offset = 6 + 16 * len(SIZES)
        directory = bytearray(struct.pack('<HHH', 0, 1, len(SIZES)))
        for size, frame in zip(SIZES, frames):
            directory.extend(struct.pack('<BBBBHHII', size % 256, size % 256,
                                         0, 0, 1, 32, len(frame), offset))
            offset += len(frame)
        (ASSETS / f'{name}.ico').write_bytes(directory + b''.join(frames))
        if name == 'GephTun':
            bitmap.resize((512, 512), Image.Resampling.LANCZOS).save(ASSETS / 'GephTun.png')
            svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <title>GephTun tunnel badge</title>
  <circle cx="50" cy="50" r="48" fill="{background}"/>
  <path fill="#FFFFFF" d="M24 76V46a26 26 0 0 1 52 0v30H62V46a12 12 0 0 0-24 0v30Z"/>
  <path fill="{route}" d="M49 58H70V49L85 64L70 79V70H49Z"/>
</svg>
'''
            (ASSETS / 'GephTun.svg').write_text(svg, encoding='utf-8')
    print(f'Built 6 ICO files with {len(SIZES)} sizes each, plus PNG and SVG in {ASSETS}')


if __name__ == '__main__':
    main()
