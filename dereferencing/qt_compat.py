#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# deREferencing - by @danigargu
#

try:
    # IDA >= 9.2 uses PySide6.
    from PySide6 import QtGui, QtCore, QtWidgets
    from PySide6.QtCore import Qt
except ImportError:
    # Older versions use PyQt5.
    from PyQt5 import QtGui, QtCore, QtWidgets
    from PyQt5.QtCore import Qt

__all__ = [
    'Qt',
    'QtCore',
    'QtGui',
    'QtWidgets',
]
