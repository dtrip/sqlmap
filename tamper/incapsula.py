#!/usr/bin/env python

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOW

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Escapes forward slash character '/' with '\/'

    Tested against:

    Notes:
        * Useful to bypass Incapsula application firewall

    >>> tamper('cat /etc/passwd')
    'cat \/etc\/passwd'
    """

    return payload.replace("/", "\/")
