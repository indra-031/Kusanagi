"""
Task — a single HTTP test unit.

Replaces direct send() calls; allows batching many tests and
executing them concurrently via ThreadPoolExecutor.
"""


class Task:
    __slots__ = ("desc", "method", "url", "headers", "http_version")

    def __init__(self, desc, method, url, headers=None, http_version="1.1"):
        self.desc = desc
        self.method = method
        self.url = url
        self.headers = dict(headers or {})
        self.http_version = http_version

    def __repr__(self):
        return f"Task({self.method} {self.url} :: {self.desc})"