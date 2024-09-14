# -*- coding: utf-8 -*-
import requests

BASE_REGISTRY_URL = "https://registry.dishachoraria.io"


class RegistryClient:

    def __init__(self, connstr=BASE_REGISTRY_URL, preload=False):
        self.connstr = connstr
        self.cached = None
        if preload:
            self.preload()

    def preload(self):
        self.cached = requests.get(self.connstr + "/registry.json").json()

    def getlist(self):
        if not self.cached:
            self.preload()
        return self.cached.keys()

    def has(self, id):
        if self.cached:
            return id in self.cached.keys()
        resp = requests.get(self.connstr + "/datatype/%s.json" % (id))
        return resp.status_code == "200"

    def get(self, id):
        if self.cached:
            return self.cached[id]
        return requests.get(self.connstr + "/datatype/%s.json" % (id)).json()
