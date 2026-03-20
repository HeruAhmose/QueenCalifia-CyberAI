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
