---
source: https://tinker-docs.thinkingmachines.ai/api-reference/restclient
scraped: 2026-03-08
---

# RestClient

The `RestClient` provides REST API operations for querying model information, managing checkpoints, and accessing session data.

```python
class RestClient(TelemetryProvider)
```

## Training Run Operations

- **`get_training_run(training_run_id)`** -- Returns training run information including run ID and base model details.
- **`get_training_run_by_tinker_path(tinker_path)`** -- Retrieves training run info using tinker path format.
- **`list_training_runs(limit=20, offset=0)`** -- Lists training runs with pagination support.

## Checkpoint Management

- **`list_checkpoints(training_run_id)`** -- Returns available checkpoints distinguishing between "training" and "sampler" checkpoint types.
- **`list_user_checkpoints(limit=100, offset=0)`** -- Lists checkpoints across all user's training runs, sorted by time (newest first).
- **`get_checkpoint_archive_url(training_run_id, checkpoint_id)`** -- Provides signed download URL with expiration timestamp.
- **`delete_checkpoint(training_run_id, checkpoint_id)`** -- Removes a checkpoint from a training run.

## Publishing Operations

- **`publish_checkpoint_from_tinker_path(tinker_path)`** -- Makes a checkpoint publicly accessible. Only the training run owner can perform this operation. Raises HTTPException (400, 404, 409, or 500) for various error conditions.
- **`unpublish_checkpoint_from_tinker_path(tinker_path)`** -- Reverts public checkpoint to private status.

## Session and Sampler Access

- **`get_session(session_id)`** -- Returns GetSessionResponse with training_run_ids and sampler_ids.
- **`list_sessions(limit=20, offset=0)`** -- Retrieves sessions with pagination support.
- **`get_sampler(sampler_id)`** -- Returns GetSamplerResponse containing base_model and model_path information.

All methods have corresponding `_async` variants. Methods return either `ConcurrentFuture[T]` (supporting `.result()`) or `APIFuture[T]` (supporting both `.result()` and `await`).
