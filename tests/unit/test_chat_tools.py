import json
from types import SimpleNamespace

import pytest

from redatlas.chat import advisor
from redatlas.chat.tools import dispatch
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

    class _Messages:
        def __init__(self, outer):
            self.outer = outer

        def create(self, **kwargs):
            self.outer.calls += 1
            if self.outer.calls == 1:
                return SimpleNamespace(
                    stop_reason="tool_use",
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
