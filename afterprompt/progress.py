"""Live progress from the stages that can measure it, for the browser view (a no-op without one).

Only the orchestrating process publishes: the pool's parent loop knows how many items are done, a pattern pass
knows which pattern it is on. Worker processes do not call back — their own lines reach the host as text.

A stage that cannot know its total says so by passing total=None, and the view shows a spinner and a counter
instead of a bar. Nothing here estimates or smooths: a made-up total is worse than an honest "total unknown".
"""
_SINK = None


def set_sink(fn):
    """fn(stage, done, total, note) or None to stop publishing."""
    global _SINK
    _SINK = fn


def emit(stage, done, total=None, note=None):
    if _SINK is None:
        return
    try:
        _SINK(stage, done, total, note)
    except Exception:  # noqa: BLE001 - a view must never break a scan
        pass
