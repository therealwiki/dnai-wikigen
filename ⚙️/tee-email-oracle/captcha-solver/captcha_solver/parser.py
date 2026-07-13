"""Parse cock.li CSS box-shadow captcha from HTML into a PIL Image."""

import re
from PIL import Image


def parse_box_shadow_pixels(html: str) -> list[tuple[int, int, str]]:
    """Extract pixel data from CSS box-shadow divs in the registration form.

    The captcha is rendered as ~39 divs, each with a box-shadow property
    containing pixel color+position data in the format:
        #RRGGBB Xpx Ypx 1px 1px

    Returns list of (x, y, hex_color) tuples.
    """
    # Match all box-shadow style attributes in the form
    # Each div's style looks like:
    #   float:right;clear:both;width:1px;height:0;margin-right:120px;
    #   box-shadow:#000000 0px 0px 1px 1px,#000000 1px 0px 1px 1px,...
    shadow_pattern = re.compile(
        r"style=[\"'][^\"']*box-shadow:([^\"']+)[\"']"
    )
    pixel_pattern = re.compile(
        r'(#[0-9a-fA-F]{6})\s+(\d+)px\s+(\d+)px'
    )

    pixels = []
    for shadow_match in shadow_pattern.finditer(html):
        shadow_str = shadow_match.group(1)
        for px_match in pixel_pattern.finditer(shadow_str):
            color = px_match.group(1)
            x = int(px_match.group(2))
            y = int(px_match.group(3))
            pixels.append((x, y, color))

    return pixels


def pixels_to_image(pixels: list[tuple[int, int, str]], scale: int = 1) -> Image.Image:
    """Convert pixel data into a PIL Image.

    Args:
        pixels: List of (x, y, hex_color) tuples.
        scale: Upscale factor (each pixel becomes scale x scale).

    Returns:
        PIL Image in RGB mode.
    """
    if not pixels:
        raise ValueError("No pixel data to render")

    max_x = max(p[0] for p in pixels)
    max_y = max(p[1] for p in pixels)
    width = max_x + 1
    height = max_y + 1

    img = Image.new("RGB", (width * scale, height * scale), (0, 0, 0))
    px = img.load()

    for x, y, color in pixels:
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        for dy in range(scale):
            for dx in range(scale):
                px[x * scale + dx, y * scale + dy] = (r, g, b)

    return img


def extract_captcha_image(html: str, scale: int = 4) -> Image.Image:
    """Parse HTML and return the captcha as a scaled PIL Image."""
    pixels = parse_box_shadow_pixels(html)
    return pixels_to_image(pixels, scale=scale)


def extract_captcha_key(html: str) -> str:
    """Extract the captcha_key hidden field value from the form."""
    # Handles both single and double quotes, and unquoted attributes
    match = re.search(r"name=captcha_key\s+value=['\"]([^'\"]+)['\"]", html)
    if not match:
        match = re.search(r"value=['\"]([^'\"]+)['\"]\s+name=captcha_key", html)
    if not match:
        match = re.search(r"name=['\"]captcha_key['\"]\s+value=['\"]([^'\"]+)['\"]", html)
    if match:
        return match.group(1)
    raise ValueError("Could not find captcha_key in HTML")
