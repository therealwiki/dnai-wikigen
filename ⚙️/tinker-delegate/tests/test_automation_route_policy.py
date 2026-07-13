from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]

RUNTIME_FILES = [
    ROOT / "pyproject.toml",
    ROOT / "tinker_delegate" / "browser_ready.py",
    ROOT / "tinker_delegate" / "signup.py",
    ROOT / "tinker_delegate" / "billing.py",
    ROOT / "docker-compose.yaml",
    ROOT / "docker-compose.dstack.yaml",
    ROOT / "docker-compose.all.yaml",
    ROOT / "docker-compose.all.dstack.yaml",
    ROOT / "docker-compose.all.phala.yaml",
]

FORBIDDEN_EVASION_TERMS = {
    "playwright-stealth",
    "selenium-stealth",
    "undetected_chromedriver",
    "undetected-chromedriver",
    "puppeteer-extra-plugin-stealth",
    "automationcontrolled",
    "navigator.webdriver",
    "--disable-blink-features=automationcontrolled",
    "--proxy-server",
    "2captcha",
    "anti-captcha",
    "anticaptcha",
    "capsolver",
    "deathbycaptcha",
}


class AutomationRoutePolicyTest(unittest.TestCase):
    def test_no_stealth_or_captcha_evasion_in_runtime_surfaces(self):
        offenders: list[str] = []
        for path in RUNTIME_FILES:
            text = path.read_text(encoding="utf-8").lower()
            for term in FORBIDDEN_EVASION_TERMS:
                if term in text:
                    offenders.append(f"{path.relative_to(ROOT)}: {term}")

        self.assertEqual(
            offenders,
            [],
            "Tinker automation must fail closed or use an approved route, "
            "not add stealth, CAPTCHA-solving, or proxy evasion surfaces.",
        )

    def test_policy_doc_records_approved_route_and_no_evasion_rule(self):
        text = (ROOT / "docs" / "TINKER-AUTOMATION-ROUTE.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("official Tinker API", text)
        self.assertIn("Browser automation is acceptable only as a bounded", text)
        self.assertIn("No-Evasion Rule", text)
        self.assertIn("fail closed", text)


if __name__ == "__main__":
    unittest.main()
