import requests

import backend.modules.conversation.engine as conversation_engine
from backend.modules.conversation.engine import _detect_intent, _local_reply


def test_detects_capabilities_question():
    assert _detect_intent("what exactly can you do?", "cyber") == "capabilities"


def test_detects_capabilities_followup():
    assert _detect_intent("what else?", "cyber") == "capabilities_followup"


def test_detects_self_knowledge_typo_wan():
    assert _detect_intent("i wan to know what you know", "cyber") == "self_knowledge"


def test_capabilities_followup_is_substantive():
    reply = _local_reply("what else", "cyber", memories=[], recent_turns=[])
    low = reply.lower()
    assert "beyond" in low
    assert "tight loop" not in low
    assert "current topic is" not in low


def test_self_knowledge_no_garbled_focus():
    reply = _local_reply("i wan to know what you know", "cyber", memories=[], recent_turns=[])
    assert "wan know" not in reply.lower()
    assert "session keys" in reply.lower() or "symbolic core" in reply.lower()


def test_financial_capabilities_uses_cross_intent_not_generic_cyber():
    assert _detect_intent("cool any financial capabilities", "cyber") == "financial_cross_capabilities"
    reply = _local_reply("cool any financial capabilities", "cyber", memories=[], recent_turns=[])
    assert "research & quant" in reply.lower()
    assert "external model" not in reply.lower()


def test_common_vulnerabilities_is_education_not_scan_lecture():
    msg = "what are some common vulnerabilities?"
    assert _detect_intent(msg, "cyber") == "vuln_education"
    reply = _local_reply(msg, "cyber", memories=[], recent_turns=[])
    assert "owasp" in reply.lower()
    assert "authorized scan" in reply.lower()
    assert "need an authorized target" not in reply.lower()


def test_user_frustration_apologizes():
    reply = _local_reply("you are not making any sense", "cyber", memories=[], recent_turns=[])
    assert "right to call that out" in reply.lower() or "call that out" in reply.lower()


def test_vuln_followup_after_education():
    turns = [
        {"role": "user", "content": "what are some common vulnerabilities?"},
        {"role": "assistant", "content": "OWASP Top 10 ..."},
    ]
    assert _detect_intent("OK but what is it?", "cyber", recent_turns=turns) == "vuln_education_followup"


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


def test_detects_authorization_confirmation():
    assert _detect_intent("i have authority", "cyber") == "authorization_confirmation"


def test_authorization_confirmation_routes_to_live_localhost_workflow():
    reply = _local_reply(
        "i have authority",
        "cyber",
        memories=[],
        recent_turns=[
            {
                "role": "assistant",
                "content": "To run a real vulnerability workflow, I need an authorized target. For localhost use `127.0.0.1`.",
            }
        ],
    )
    low = reply.lower()
    assert "127.0.0.1" in low
    assert "quick scan" in low or "vulnerability scanner" in low
    assert "current topic is authority" not in low


def test_context_recovery_keeps_scan_thread_direct():
    reply = _local_reply(
        "u forgot",
        "cyber",
        memories=[],
        recent_turns=[
            {"role": "user", "content": "run vulnerability scan on local host"},
            {"role": "assistant", "content": "For localhost use `127.0.0.1` and confirm authorization."},
        ],
    )
    low = reply.lower()
    assert "127.0.0.1" in low
    assert "quick scan" in low
    assert "current topic is u forgot" not in low


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
