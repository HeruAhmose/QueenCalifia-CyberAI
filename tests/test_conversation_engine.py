import requests

import backend.modules.conversation.engine as conversation_engine
from backend.modules.conversation.engine import _detect_intent, _local_reply


def test_detects_capabilities_question():
    assert _detect_intent("what exactly can you do?", "cyber") == "capabilities"


def test_detects_clarify_question():
    assert _detect_intent("what do you mean", "cyber") == "clarify"


def test_capabilities_reply_is_direct_and_honest():
    reply = _local_reply("what exactly can you do?", "cyber", memories=[], recent_turns=[])
    low = reply.lower()
    assert "run authorized vulnerability workflows" in low
    assert "local symbolic core" in low or "external model" in low
    assert "i hear you clearly" not in low


def test_clarify_reply_gives_examples_instead_of_parroting():
    reply = _local_reply(
        "what do you mean",
        "cyber",
        memories=[],
        recent_turns=[{"role": "assistant", "content": "Give me a concrete objective."}],
    )
    low = reply.lower()
    assert "concrete and testable" in low
    assert "localhost scan" in low
    assert "what do mean" not in low


def test_provider_auto_detects_anthropic(monkeypatch):
    monkeypatch.setattr(conversation_engine, "LLM_PROVIDER", "auto")
    monkeypatch.setattr(conversation_engine, "LLM_URL", "https://api.anthropic.com/v1/messages")
    monkeypatch.setattr(conversation_engine, "LLM_MODEL", "claude-3-5-sonnet-latest")
    assert conversation_engine._resolved_llm_provider() == "anthropic"
    assert conversation_engine._resolved_llm_url() == "https://api.anthropic.com/v1/messages"


def test_native_anthropic_call_uses_messages_api(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200

        @staticmethod
        def json():
            return {
                "content": [{"type": "text", "text": "Direct Claude reply."}],
                "usage": {"input_tokens": 21, "output_tokens": 9},
            }

    def _fake_post(url, headers=None, json=None, timeout=None):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        captured["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(conversation_engine, "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(conversation_engine, "LLM_URL", "https://api.anthropic.com/v1/messages")
    monkeypatch.setattr(conversation_engine, "LLM_API_KEY", "anthropic-test-key")
    monkeypatch.setattr(conversation_engine, "LLM_MODEL", "claude-3-5-sonnet-latest")
    monkeypatch.setattr(conversation_engine, "LLM_MAX_TOKENS", 2048)
    monkeypatch.setattr(conversation_engine, "LLM_ANTHROPIC_VERSION", "2023-06-01")
    monkeypatch.setattr(requests, "post", _fake_post)

    reply, tokens_in, tokens_out = conversation_engine._call_external_llm(
        "system prompt",
        [{"role": "user", "content": "hello"}],
    )

    assert reply == "Direct Claude reply."
    assert tokens_in == 21
    assert tokens_out == 9
    assert captured["url"] == "https://api.anthropic.com/v1/messages"
    assert captured["headers"]["x-api-key"] == "anthropic-test-key"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert captured["json"]["system"] == "system prompt"
    assert captured["json"]["messages"] == [{"role": "user", "content": "hello"}]
