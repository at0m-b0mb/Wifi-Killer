#!/usr/bin/env python3
"""
gui.py – Entry-point for the Wifi-Killer GUI.

Run with:  sudo python3 gui.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wifi_killer.gui import run_gui

if __name__ == "__main__":
    run_gui()
