import dataclasses
import json
from types import SimpleNamespace

import pytest

from redatlas.chat import advisor
from redatlas.chat.advisor import trim_history
from redatlas.chat.tools import MAX_SEARCH_RESULTS, dispatch
from redatlas.llm.client import MissingAPIKeyError, get_client


def test_dispatch_search_techniques(sample_store):
    result = json.loads(dispatch(sample_store, "search_techniques", {"query": "phishing"}))
    assert result == [{"id": "T1566", "name": "Phishing", "framework": "attack"}]


def test_dispatch_get_technique_known(sample_store):
    result = json.loads(dispatch(sample_store, "get_technique", {"technique_id": "T1566"}))
    assert result["id"] == "T1566"
    assert result["mitigation_ids"] == ["M1017"]


def test_dispatch_get_technique_unknown(sample_store):
    result = json.loads(dispatch(sample_store, "get_technique", {"technique_id": "nope"}))
    assert "error" in result


def test_dispatch_get_mitigations(sample_store):
    result = json.loads(dispatch(sample_store, "get_mitigations", {"technique_id": "T1566"}))
    assert result == [
        {"id": "M1017", "name": "User Training", "description": "Train users against phishing."}
    ]


def test_dispatch_unknown_tool(sample_store):
    result = json.loads(dispatch(sample_store, "not_a_real_tool", {}))
    assert "error" in result


def test_get_client_raises_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(MissingAPIKeyError):
        get_client()


class _FakeAnthropicClient:
    """Returns a canned tool_use turn followed by an end_turn turn."""

    def __init__(self):
        self.calls = 0
        self.requests = []

    class _Messages:
        def __init__(self, outer):
            self.outer = outer

        def create(self, **kwargs):
            self.outer.calls += 1
            self.outer.requests.append(kwargs)
            usage = SimpleNamespace(
                input_tokens=10,
                cache_read_input_tokens=1000,
                cache_creation_input_tokens=50,
                output_tokens=20,
            )
            if self.outer.calls == 1:
                return SimpleNamespace(
                    stop_reason="tool_use",
                    usage=usage,
                    content=[
                        SimpleNamespace(
                            type="tool_use",
                            id="tool_1",
                            name="search_techniques",
                            input={"query": "phishing"},
                        )
                    ],
                )
            return SimpleNamespace(
                stop_reason="end_turn",
                usage=usage,
                content=[SimpleNamespace(type="text", text="Based on T1566, watch for phishing.")],
            )

    @property
    def messages(self):
        return self._Messages(self)


def test_run_repl_dispatches_tool_and_prints_final_answer(monkeypatch, sample_store, capsys):
    fake_client = _FakeAnthropicClient()
    monkeypatch.setattr(advisor, "get_client", lambda: fake_client)

    inputs = iter(["What techniques involve phishing?", "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    advisor.run_repl(sample_store)

    captured = capsys.readouterr()
    assert "Based on T1566" in captured.out
    assert fake_client.calls == 2


def test_run_repl_enables_caching_and_prints_token_usage(monkeypatch, sample_store, capsys):
    fake_client = _FakeAnthropicClient()
    monkeypatch.setattr(advisor, "get_client", lambda: fake_client)

    inputs = iter(["What techniques involve phishing?", "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    advisor.run_repl(sample_store)

    assert all(r["cache_control"] == {"type": "ephemeral"} for r in fake_client.requests)
    out = capsys.readouterr().out
    assert "[tokens this turn] 2 API call(s) | input 20 | cache read 2,000" in out
    assert "cache write 100 | output 40" in out
    assert "[tokens this session]" in out


def _exchange(n: int) -> list[dict]:
    return [
        {"role": "user", "content": f"question {n}"},
        {"role": "assistant", "content": [{"type": "tool_use", "id": f"t{n}"}]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": f"t{n}"}]},
        {"role": "assistant", "content": [{"type": "text", "text": f"answer {n}"}]},
    ]


def test_trim_history_leaves_short_history_alone():
    messages = [m for n in range(3) for m in _exchange(n)]
    assert trim_history(messages, max_exchanges=3, keep_exchanges=2) is messages


def test_trim_history_drops_whole_old_exchanges():
    messages = [m for n in range(5) for m in _exchange(n)]
    trimmed = trim_history(messages, max_exchanges=4, keep_exchanges=2)
    assert trimmed[0] == {"role": "user", "content": "question 3"}
    assert len(trimmed) == 8


def test_dispatch_caps_search_results(sample_store, monkeypatch):
    seen = {}

    def fake_search(query, *, framework=None, domain=None, limit=10):
        seen["limit"] = limit
        return []

    monkeypatch.setattr(sample_store, "search", fake_search)
    dispatch(sample_store, "search_techniques", {"query": "x", "top_k": 500})
    assert seen["limit"] == MAX_SEARCH_RESULTS


def test_dispatch_truncates_long_descriptions(sample_store, monkeypatch):
    long_text = "a" * 5000
    technique = sample_store.get_technique("T1566")
    long_technique = dataclasses.replace(technique, description=long_text)
    monkeypatch.setattr(sample_store, "get_technique", lambda _id: long_technique)
    result = json.loads(dispatch(sample_store, "get_technique", {"technique_id": "T1566"}))
    assert len(result["description"]) < 1600
    assert result["description"].endswith("[...truncated]")


class _RefusingClient:
    def __init__(self):
        self.requests = []

    @property
    def messages(self):
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.requests.append([dict(m) for m in kwargs["messages"]])
                if len(outer.requests) == 1:
                    return SimpleNamespace(stop_reason="refusal", content=[], usage=None)
                return SimpleNamespace(
                    stop_reason="end_turn",
                    content=[SimpleNamespace(type="text", text="Here is a safe answer.")],
                    usage=None,
                )

        return _Messages()


def test_run_repl_reports_refusal_and_drops_declined_question(monkeypatch, sample_store, capsys):
    fake_client = _RefusingClient()
    monkeypatch.setattr(advisor, "get_client", lambda: fake_client)

    inputs = iter(["declined question", "next question", "exit"])
    monkeypatch.setattr("builtins.input", lambda *_: next(inputs))

    advisor.run_repl(sample_store)

    out = capsys.readouterr().out
    assert "The model declined this request" in out
    assert "Here is a safe answer." in out
    assert fake_client.requests[1] == [{"role": "user", "content": "next question"}]
