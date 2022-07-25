import redis
import json


def main():
    rd = redis.StrictRedis(
        host="localhost",
        port=6379,
        db=0,
        username="leka",
        password="test1234",
    )

    print(rd)

    print(rd.keys())

    rd.set(
        "set",
        json.dumps(
            {
                "key1": 2,
                "key2": "token",
            },
        ),
    )

    s = rd.get("set")
    print(s)
    print(type(s))
    j = json.loads(s.decode("utf-8"))
    print(j)
    print(j["key1"])
    print(j["key2"])


main()
