from conftest import ev


def answers(r):
    return r.instance.context["answers"]


def test_tap_records_no(load, profile, runner):
    r = runner(load("introduction"), profile)
    r.send(ev("show_question"))
    s = r.send(ev("tap", at="2026-10-12T20:00:05Z"))
    assert r.state == "recorded"
    assert answers(r) == [{"question": "interruptions", "answer": "no", "channel": "tap",
                           "at": "2026-10-12T20:00:05Z", "corrects": None}]
    assert s.record["outputs"] == [{"kind": "say", "message": "introduction.recorded_no"}]


def test_escape_is_keyboard_no(load, profile, runner):
    r = runner(load("introduction"), profile)
    r.send(ev("show_question"))
    r.send(ev("escape"))
    assert answers(r)[-1]["answer"] == "no" and answers(r)[-1]["channel"] == "escape"


def test_reading_past_is_yes_by_silence(load, profile, runner):
    r = runner(load("introduction"), profile)
    r.send(ev("show_question"))
    s = r.send(ev("read_past"))
    assert answers(r)[-1]["answer"] == "yes" and answers(r)[-1]["channel"] == "silence"
    assert s.record["outputs"] == [{"kind": "say", "message": "introduction.recorded_yes"}]


def test_reask_appends_a_correction_that_names_what_it_corrects(load, profile, runner):
    r = runner(load("introduction"), profile)
    r.send(ev("show_question"))
    r.send(ev("read_past"))
    r.send(ev("reask"))
    assert r.state == "asking"
    r.send(ev("tap"))
    assert [a["answer"] for a in answers(r)] == ["yes", "no"]
    assert answers(r)[1]["corrects"] == 0


def test_forget_erases_the_model_and_starts_over(load, profile, runner):
    r = runner(load("introduction"), profile)
    r.send(ev("show_question"))
    r.send(ev("tap"))
    s = r.send(ev("forget"))
    assert r.state == "unmet" and answers(r) == []
    assert s.record["outputs"] == [{"kind": "say", "message": "introduction.forgotten"}]
    r.send(ev("show_question"))
    r.send(ev("tap"))
    assert answers(r)[0]["corrects"] is None


def test_event_with_no_transition_is_recorded_not_ignored(load, profile, runner):
    r = runner(load("introduction"), profile)
    s = r.send(ev("tap"))  # nothing has been asked yet
    assert s.record["outcome"] == "not_accepted"
    assert r.state == "unmet" and r.instance.seq == 1
