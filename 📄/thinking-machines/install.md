---
source: https://tinker-docs.thinkingmachines.ai/install
scraped: 2026-03-08
---

# Installing Tinker

## Installation

Set up the Tinker SDK using:

```
pip install tinker
```

This command makes available both the Python SDK and the tinker CLI tool.

### Python SDK

The Python SDK provides fundamental operations including `forward_backward`, `sample`, `optim_step`, and `save_state`.

### Tinker CLI

Access the CLI via `tinker` or `python -m tinker`. It offers administrative capabilities comparable to the web console interface. Check available commands with `tinker --help`.

## Tinker Cookbook

The [tinker-cookbook repository](https://github.com/thinking-machines-lab/tinker-cookbook) contains training code and experiment utilities built on Tinker. For this component, local editable installation is recommended:

```
git clone https://github.com/thinking-machines-lab/tinker-cookbook.git
cd tinker-cookbook
# Switch to your virtual environment
pip install -e .
```

## Getting an API Key

Generate an API key through the [console](https://tinker-console.thinkingmachines.ai). Configure the `TINKER_API_KEY` environment variable to your newly created key.
