---
source: https://tinker-docs.thinkingmachines.ai/publish-weights
scraped: 2026-03-08
---

# Publishing Weights

## Publishing

To share a trained model checkpoint with the community, use:

```
tinker checkpoint publish $TINKER_CHECKPOINT_PATH
```

The path should follow the format: `tinker://14bdf3a1-0b95-55c7-8659-5edb1bc870af:train:17/weights/checkpoint_id_to_publish`

Once published, any Tinker user can access and utilize the checkpoint for additional training or sampling purposes.

### Verification

Confirm publication status by checking checkpoint information:

```
tinker checkpoint info tinker://14bdf3a1-0b95-55c7-8659-5edb1bc870af/weights/checkpoint_id_to_publish
```

The output displays a table with properties including a "Public" field indicating publication status.

## Unpublishing

Remove a checkpoint from public availability:

```
tinker checkpoint unpublish $TINKER_CHECKPOINT_PATH
```

## Loading Public Weights

Accessing published weights mirrors the standard loading process:

```python
ckpt_path = ...
training_client = service_client.create_training_client_from_state(ckpt_path)
```

The loading mechanism remains identical whether weights are publicly shared or private.
