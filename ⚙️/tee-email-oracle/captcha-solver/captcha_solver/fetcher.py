"""Fetch cock.li registration page and extract captcha data."""

import re

import httpx

from captcha_solver.parser import extract_captcha_key

REGISTER_URL = "https://cock.li/register.php"


def fetch_captcha(
    timeout: float = 15.0,
) -> tuple[str, str]:
    """Fetch the registration page and return (html, captcha_key).

    Returns the raw HTML and the captcha_key hidden field value
    needed for form submission.
    """
    with httpx.Client(
        follow_redirects=True,
        timeout=timeout,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        },
    ) as client:
        resp = client.get(REGISTER_URL)
        resp.raise_for_status()

    html = resp.text
    captcha_key = extract_captcha_key(html)
    return html, captcha_key


def _extract_field(html: str, name: str) -> str:
    """Extract a form field value, handling quoted and unquoted attributes."""
    # Unquoted: name=csrf value=abc123
    m = re.search(rf"name={name}\s+value=([^\s/>]+)", html)
    if m:
        return m.group(1).strip("'\"")
    # Quoted: name='csrf' value='abc123'
    m = re.search(rf"name=['\"]?{name}['\"]?\s+value=['\"]([^'\"]+)['\"]", html)
    if m:
        return m.group(1)
    return ""


def fetch_and_solve() -> tuple[str, str, str]:
    """Fetch a captcha and solve it.

    Returns (solution, captcha_key, csrf_token).
    """
    from captcha_solver.parser import parse_box_shadow_pixels, pixels_to_image
    from captcha_solver.solver import solve_from_image

    html, captcha_key = fetch_captcha()

    csrf = _extract_field(html, "csrf")

    pixels = parse_box_shadow_pixels(html)
    img = pixels_to_image(pixels, scale=1)
    solution = solve_from_image(img)

    return solution, captcha_key, csrf
