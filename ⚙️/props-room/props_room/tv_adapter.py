"""Adapter for the raw scrape entrypoints in the tv corpus repo."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import subprocess


@dataclass
class TVRawScrapeRequest:
    mode: str
    pilot: bool = False
    book: int | None = None
    publication_code: str | None = None
    docids: list[str] = field(default_factory=list)
    library: bool = False
    library_category: str | None = None
    year: int | None = None
    start_date: str | None = None
    end_date: str | None = None
    run_name: str | None = None


@dataclass
class TVCommandPlan:
    mode: str
    description: str
    argv: list[str]
    cwd: str
    expected_outputs: list[str]


@dataclass
class TVRunResult:
    plan: TVCommandPlan
    executed: bool
    exit_code: int | None
    stdout: str
    stderr: str


class TVIngestionAdapter:
    def __init__(self, repo_root: str | Path, allow_subprocess: bool) -> None:
        self.repo_root = Path(repo_root).resolve()
        self.allow_subprocess = allow_subprocess

    def plan_raw_scrape(self, request: TVRawScrapeRequest) -> TVCommandPlan:
        mode = request.mode
        base = ["uv", "run", "python"]

        if mode == "bible":
            argv = base + ["scripts/scrape_bible.py"]
            if request.pilot:
                argv.append("--pilot")
                description = "tv Bible pilot scrape"
            elif request.book is not None:
                argv.extend(["--book", str(request.book)])
                description = f"tv Bible book scrape ({request.book})"
            else:
                argv.append("--full")
                description = "tv Bible full scrape"
            outputs = [
                "data/raw/wol_tvl",
                "data/raw/wol_en",
                "data/aligned/bible_verses.jsonl",
            ]
        elif mode == "articles":
            argv = base + ["scripts/scrape_articles.py"]
            if request.pilot:
                argv.append("--pilot")
                description = "tv article pilot scrape"
            elif request.publication_code:
                argv.extend(["--pub", request.publication_code])
                description = f"tv publication scrape ({request.publication_code})"
            elif request.docids:
                argv.extend(["--docids", *request.docids])
                description = f"tv article docId scrape ({len(request.docids)} docs)"
            elif request.library_category:
                argv.extend(["--library-cat", request.library_category])
                description = f"tv library category scrape ({request.library_category})"
            else:
                argv.append("--library")
                description = "tv library article scrape"
            outputs = [
                "data/raw/wol_tvl",
                "data/raw/wol_en",
                "data/aligned/articles.jsonl",
            ]
        elif mode == "daily":
            argv = base + ["scripts/scrape_daily_text.py"]
            if request.year is not None:
                argv.extend(["--year", str(request.year)])
                description = f"tv daily text scrape ({request.year})"
            elif request.start_date and request.end_date:
                argv.extend(["--range", request.start_date, request.end_date])
                description = f"tv daily text scrape ({request.start_date}..{request.end_date})"
            else:
                raise ValueError("daily mode requires either year or start_date + end_date")
            outputs = [
                "data/raw/wol_tvl",
                "data/raw/wol_en",
                "data/aligned/daily_text.jsonl",
            ]
        elif mode == "unstructured":
            argv = base + ["scripts/run_unstructured_datamining.py"]
            if request.run_name:
                argv.extend(["--run-name", request.run_name])
            description = "tv unstructured raw ingest"
            outputs = [
                "data/external/raw",
                "data/external/ocr_scans",
                "data/external/stage_a_seed",
                "data/external/stage_b_seed",
            ]
        else:
            raise ValueError(f"Unsupported tv raw scrape mode: {mode}")

        return TVCommandPlan(
            mode=mode,
            description=description,
            argv=argv,
            cwd=str(self.repo_root),
            expected_outputs=outputs,
        )

    def execute(self, plan: TVCommandPlan) -> TVRunResult:
        if not self.allow_subprocess:
            raise RuntimeError(
                "Subprocess execution disabled. Set PROPS_ROOM_ALLOW_HOST_SUBPROCESS=true"
            )
        completed = subprocess.run(
            plan.argv,
            cwd=plan.cwd,
            capture_output=True,
            text=True,
        )
        return TVRunResult(
            plan=plan,
            executed=True,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
