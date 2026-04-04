#!/usr/bin/env python3
"""
Entry-point shim – run `sudo python3 main.py` from the repo root.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wifi_killer.main import main

if __name__ == "__main__":
    main()
