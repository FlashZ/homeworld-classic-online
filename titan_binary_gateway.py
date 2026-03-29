#!/usr/bin/env python3
"""Compatibility shim for the split gateway package."""

from gateway import admin as _admin
from gateway import firewall as _firewall
from gateway import protocol as _protocol
from gateway import product_profile as _product_profile
from gateway import repo_monitor as _repo_monitor
from gateway import routing as _routing
from gateway import titan_service as _titan_service

for _module in (_protocol, _routing, _admin, _firewall, _repo_monitor, _product_profile, _titan_service):
    for _name in dir(_module):
        if _name.startswith("__"):
            continue
        globals()[_name] = getattr(_module, _name)


if __name__ == "__main__":
    start_gateway()
