# msad - Active Directory tool
# Copyright (C) 2025 - matteo.redaelli@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
"""Helpers for emitting consistent deprecation warnings."""

from __future__ import annotations

import warnings


def warn_deprecated(old: str, new: str) -> None:
    """Emit a DeprecationWarning telling the caller to use ``new`` instead.

    Args:
        old: the deprecated name (e.g. ``"group_member()"``).
        new: the replacement to use (e.g. ``"is_member()"``).
    """
    warnings.warn(
        f"{old} is deprecated and will be removed in the next release; use {new} instead.",
        DeprecationWarning,
        stacklevel=3,
    )
