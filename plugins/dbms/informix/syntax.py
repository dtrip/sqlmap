#!/usr/bin/env python2

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import re

from lib.core.common import isDBMSVersionAtLeast
from lib.core.common import randomStr
from plugins.generic.syntax import Syntax as GenericSyntax

class Syntax(GenericSyntax):
    def __init__(self):
        GenericSyntax.__init__(self)

    @staticmethod
    def escape(expression, quote=True):
        """
        >>> from lib.core.common import Backend
        >>> Backend.setVersion('12.10')
        ['12.10']
        >>> Syntax.escape("SELECT 'abcdefgh' FROM foobar")
        'SELECT CHR(97)||CHR(98)||CHR(99)||CHR(100)||CHR(101)||CHR(102)||CHR(103)||CHR(104) FROM foobar'
        """

        def escaper(value):
            return "||".join("CHR(%d)" % ord(_) for _ in value)

        retVal = expression

        if isDBMSVersionAtLeast("11.70"):
            excluded = {}
            for _ in re.findall(r"DBINFO\([^)]+\)", expression):
                excluded[_] = randomStr()
                expression = expression.replace(_, excluded[_])

            retVal = Syntax._escape(expression, quote, escaper)

            for _ in excluded.items():
                retVal = retVal.replace(_[1], _[0])

        return retVal
