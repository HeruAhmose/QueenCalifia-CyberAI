from celery_app import make_celery


def test_celery_redis_broker_backend_configuration(monkeypatch):
    redis_url = "redis://:redacted-password@localhost:6379/7"
    monkeypatch.setenv("QC_REDIS_URL", redis_url)
    monkeypatch.delenv("QC_CELERY_BROKER_URL", raising=False)
    monkeypatch.delenv("QC_CELERY_RESULT_BACKEND", raising=False)
    monkeypatch.setenv("QC_SCAN_QUEUE_NAME", "security-scans")

    app = make_celery()

    assert app.conf.broker_url == redis_url
    assert app.conf.result_backend == redis_url
    assert app.conf.task_default_queue == "security-scans"
    assert app.conf.task_routes["qc.run_vuln_scan"]["queue"] == "security-scans"
