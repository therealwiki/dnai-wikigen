---
source: https://tinker-docs.thinkingmachines.ai/api-reference/apifuture
scraped: 2026-03-08
---

# APIFuture

Abstract base classes for managing asynchronous operations with retry logic.

## APIFuture Objects

```python
class APIFuture(ABC, Generic[T])
```

A unified interface for handling async operations that can be accessed both synchronously and asynchronously.

### Methods

**`result_async()`**

```python
async def result_async(timeout: float | None = None) -> T
```

Retrieves results asynchronously with optional timeout. Raises `TimeoutError` if exceeded.

**`result()`**

```python
def result(timeout: float | None = None) -> T
```

Retrieves results synchronously with optional timeout. Raises `TimeoutError` if exceeded.

### Usage Patterns

```python
result = await api_future    # Async access
result = api_future.result() # Sync access (blocking)
```

## AwaitableConcurrentFuture Objects

```python
class AwaitableConcurrentFuture(APIFuture[T])
```

Wraps a `concurrent.futures.Future`, bridging Python's concurrent.futures with asyncio.

**`future()`**

```python
def future() -> ConcurrentFuture[T]
```

Accesses the underlying concurrent.futures.Future.
