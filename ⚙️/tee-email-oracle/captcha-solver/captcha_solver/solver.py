"""CPU-only captcha solver for cock.li registration captchas.

The captcha is a simple pixelated text (5-6 alphanumeric chars) rendered as
CSS box-shadow pixels: light text on a black background, 99x39 native resolution.

Primary method: template matching against a stored bitmap font database.
Fallback: Tesseract OCR with tuned preprocessing (for unknown characters).
"""

import re
from pathlib import Path

import pytesseract
from PIL import Image, ImageFilter, ImageOps

from captcha_solver.parser import extract_captcha_image
from captcha_solver.templates import (
    TemplateDB,
    binarize,
    segment_characters,
)

CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

# Max hamming distance to accept a template match
MAX_MATCH_DISTANCE = 25

_db: TemplateDB | None = None


def _get_db() -> TemplateDB:
    """Lazy-load the template database."""
    global _db
    if _db is None:
        _db = TemplateDB()
        _db.load()
    return _db


def solve_template(img: Image.Image) -> tuple[str, list[int]]:
    """Solve using template matching.

    Returns (solution, distances) where distances[i] is the match
    distance for character i. A distance of 999 means no match found.
    """
    db = _get_db()
    grid = binarize(img)
    chars = segment_characters(grid)

    result = []
    distances = []
    for bitmap in chars:
        char, dist = db.match(bitmap, max_distance=MAX_MATCH_DISTANCE)
        result.append(char)
        distances.append(dist)

    return "".join(result), distances


def solve_tesseract(img: Image.Image) -> str:
    """Fallback: solve using Tesseract OCR with tuned preprocessing."""
    gray = img.convert("L")
    scaled = gray.resize(
        (gray.width * 4, gray.height * 4),
        Image.LANCZOS,
    )
    binary = scaled.point(lambda p: 0 if p > 120 else 255, mode="L")
    padded = ImageOps.expand(binary, border=20, fill=255)
    config = (
        "--psm 7 "
        "--oem 3 "
        f"-c tessedit_char_whitelist={CHARSET} "
        "-c page_separator=''"
    )
    text = pytesseract.image_to_string(padded, config=config)
    return re.sub(r"[^a-zA-Z0-9]", "", text.strip())


def solve_from_image(img: Image.Image) -> str:
    """Solve a captcha from a PIL Image.

    Uses template matching as primary. Falls back to Tesseract for
    any characters that couldn't be matched (distance > threshold).
    """
    solution, distances = solve_template(img)

    # If all characters matched well, return template result
    if "?" not in solution:
        return solution

    # Partial match — try Tesseract for the unknown chars
    tess_result = solve_tesseract(img)

    # Merge: use template matches where confident, Tesseract elsewhere
    merged = list(solution)
    for i, ch in enumerate(merged):
        if ch == "?" and i < len(tess_result):
            merged[i] = tess_result[i]

    return "".join(merged)


def solve_from_html(html: str) -> str:
    """Solve a captcha by parsing CSS box-shadow data from the registration HTML."""
    img = extract_captcha_image(html, scale=1)
    return solve_from_image(img)


def solve_from_file(path: str | Path) -> str:
    """Solve a captcha from an image file."""
    img = Image.open(path)
    return solve_from_image(img)
