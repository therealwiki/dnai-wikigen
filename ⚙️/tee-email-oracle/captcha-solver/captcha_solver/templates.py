"""Template-based character recognition for cock.li captchas.

The captcha uses a fixed-width pixel font:
  - Each character: exactly 10 pixels wide
  - Characters separated by 1+ pixel gaps (columns with no bright pixels)
  - Vertical range: rows 6-24 (19 pixels tall) at native 99x39 resolution
  - Light text on black background

Strategy:
  1. Binarize the image (threshold > 80 = text)
  2. Segment characters by finding column gaps
  3. Extract each character as a 10x19 binary bitmap
  4. Match against stored templates using hamming distance
"""

import json
from pathlib import Path

from PIL import Image

TEMPLATES_PATH = Path(__file__).parent / "template_db.json"

# Vertical crop range at native resolution
ROW_START = 4
ROW_END = 27  # inclusive — generous range to capture all chars including descenders
CHAR_HEIGHT = ROW_END - ROW_START + 1  # 24 rows
CHAR_WIDTH = 10
THRESHOLD = 80


def _to_native(img: Image.Image) -> Image.Image:
    """Ensure image is at native ~99x39 resolution."""
    if img.width > 200:
        # Likely 4x scaled, downsample
        scale = round(img.width / 99)
        return img.resize((img.width // scale, img.height // scale), Image.NEAREST)
    return img


def binarize(img: Image.Image) -> list[list[int]]:
    """Convert to 2D binary grid (1 = text pixel, 0 = background)."""
    native = _to_native(img)
    gray = native.convert("L")
    px = gray.load()
    w, h = gray.size
    return [
        [1 if px[x, y] > THRESHOLD else 0 for x in range(w)]
        for y in range(h)
    ]


def segment_characters(grid: list[list[int]]) -> list[list[list[int]]]:
    """Segment the grid into individual character bitmaps.

    Returns list of character grids, each CHAR_HEIGHT x CHAR_WIDTH.
    """
    h = len(grid)
    w = len(grid[0]) if grid else 0

    # Column activity
    col_has_text = []
    for x in range(w):
        has = any(grid[y][x] for y in range(h))
        col_has_text.append(has)

    # Find character column ranges
    chars = []
    in_char = False
    start = 0
    for x in range(w):
        if col_has_text[x] and not in_char:
            start = x
            in_char = True
        elif not col_has_text[x] and in_char:
            chars.append((start, x))
            in_char = False
    if in_char:
        chars.append((start, w))

    # Extract character bitmaps, cropped to vertical range
    result = []
    for col_start, col_end in chars:
        char_w = col_end - col_start
        # Pad or crop to CHAR_WIDTH
        bitmap = []
        for y in range(ROW_START, min(ROW_END + 1, h)):
            row = []
            for x in range(CHAR_WIDTH):
                src_x = col_start + x
                if src_x < col_end and src_x < w:
                    row.append(grid[y][src_x])
                else:
                    row.append(0)
            bitmap.append(row)
        # Pad rows if needed
        while len(bitmap) < CHAR_HEIGHT:
            bitmap.append([0] * CHAR_WIDTH)
        result.append(bitmap)

    return result


def bitmap_to_key(bitmap: list[list[int]]) -> str:
    """Convert bitmap to a compact string key for storage."""
    return "".join(
        str(bitmap[y][x])
        for y in range(len(bitmap))
        for x in range(len(bitmap[0]))
    )


def key_to_bitmap(key: str, width: int = CHAR_WIDTH, height: int = CHAR_HEIGHT) -> list[list[int]]:
    """Convert string key back to bitmap."""
    return [
        [int(key[y * width + x]) for x in range(width)]
        for y in range(height)
    ]


def hamming_distance(a: str, b: str) -> int:
    """Count differing bits between two bitmap keys."""
    if len(a) != len(b):
        return max(len(a), len(b))
    return sum(1 for i in range(len(a)) if a[i] != b[i])


class TemplateDB:
    """Database of character templates for matching."""

    def __init__(self):
        # Maps character → list of bitmap keys (multiple templates per char)
        self.templates: dict[str, list[str]] = {}

    def add(self, char: str, bitmap: list[list[int]]):
        """Add a character template."""
        key = bitmap_to_key(bitmap)
        if char not in self.templates:
            self.templates[char] = []
        if key not in self.templates[char]:
            self.templates[char].append(key)

    def match(self, bitmap: list[list[int]], max_distance: int = 30) -> tuple[str, int]:
        """Find the best matching character for a bitmap.

        Returns (character, distance). Returns ('?', 999) if no match found.
        """
        key = bitmap_to_key(bitmap)
        best_char = "?"
        best_dist = 999

        for char, keys in self.templates.items():
            for tmpl_key in keys:
                dist = hamming_distance(key, tmpl_key)
                if dist < best_dist:
                    best_dist = dist
                    best_char = char

        if best_dist > max_distance:
            return "?", best_dist
        return best_char, best_dist

    def save(self, path: Path | None = None):
        """Save templates to JSON."""
        p = path or TEMPLATES_PATH
        p.write_text(json.dumps(self.templates, indent=2))

    def load(self, path: Path | None = None):
        """Load templates from JSON."""
        p = path or TEMPLATES_PATH
        if p.exists():
            self.templates = json.loads(p.read_text())

    @property
    def char_count(self) -> int:
        return len(self.templates)

    @property
    def template_count(self) -> int:
        return sum(len(v) for v in self.templates.values())


def extract_labeled_templates(
    img: Image.Image, label: str
) -> list[tuple[str, list[list[int]]]]:
    """Extract character templates from a labeled captcha image.

    Args:
        img: Captcha image (any scale).
        label: The known solution string.

    Returns:
        List of (char, bitmap) pairs.
    """
    grid = binarize(img)
    chars = segment_characters(grid)

    if len(chars) != len(label):
        raise ValueError(
            f"Segmented {len(chars)} chars but label has {len(label)}: {label!r}"
        )

    return [(label[i], chars[i]) for i in range(len(chars))]


def build_initial_db(labeled_samples: list[tuple[str, str]]) -> TemplateDB:
    """Build template DB from labeled (image_path, label) pairs."""
    db = TemplateDB()
    for path, label in labeled_samples:
        img = Image.open(path)
        try:
            pairs = extract_labeled_templates(img, label)
            for char, bitmap in pairs:
                db.add(char, bitmap)
        except ValueError as e:
            print(f"Skipping {path}: {e}")
    return db
