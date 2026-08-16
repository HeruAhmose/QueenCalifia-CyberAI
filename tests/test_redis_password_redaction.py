from redis import Redis


def test_redis_connection_pool_repr_redacts_password():
    password = "qc-super-secret-password"
    client = Redis.from_url(
        f"redis://:{password}@localhost:6379/0",
        decode_responses=True,
        socket_timeout=2,
        socket_connect_timeout=2,
    )

    representation = repr(client.connection_pool)

    assert password not in representation
    assert "password" in representation.lower()
