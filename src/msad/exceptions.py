# msad - Active Directory tool
# Copyright (C) 2025 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Typed exceptions for the msad library.

The library raises these instead of calling ``sys.exit`` so that callers
(CLI, MCP server, tests) can decide how to handle failures.
"""

from __future__ import annotations


class MsadError(Exception):
    """Base class for all msad errors."""


class MsadConfigError(MsadError):
    """Raised when the configuration file is missing, unreadable or invalid."""


class MsadConnectionError(MsadError):
    """Raised when binding to the Active Directory server fails."""


class MsadNotFoundError(MsadError):
    """Raised when a requested entry (user, group, ...) is not found."""
