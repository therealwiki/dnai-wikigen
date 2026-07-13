---
source: https://tinker-docs.thinkingmachines.ai/download-weights
scraped: 2026-03-08
---

# Downloading Weights

## CLI

```
tinker checkpoint download $TINKER_CHECKPOINT_PATH
```

See `tinker checkpoint download --help` for more details.

## SDK

You can also download checkpoints using the SDK.

```python
import tinker
import urllib.request

sc = tinker.ServiceClient()
rc = sc.create_rest_client()
future = rc.get_checkpoint_archive_url_from_tinker_path("tinker://<unique_id>/sampler_weights/final")
checkpoint_archive_url_response = future.result()

# `checkpoint_archive_url_response.url` is a signed URL that can be downloaded
# until checkpoint_archive_url_response.expires
urllib.request.urlretrieve(checkpoint_archive_url_response.url, "archive.tar")
```

Replace `<unique_id>` with your Training Run ID. This procedure will save the LoRA adapter weights and configuration inside the `archive.tar` file.
