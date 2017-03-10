#!/usr/bin/env python

"""
Copyright (c) 2006-2017 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

from lib.core.enums import DBMS
from lib.core.settings import MSSQL_SYSTEM_DBS
from lib.core.unescaper import unescaper
from plugins.dbms.filemakerpro.enumeration import Enumeration
from plugins.dbms.filemakerpro.filesystem import Filesystem
from plugins.dbms.filemakerpro.fingerprint import Fingerprint
from plugins.dbms.filemakerpro.syntax import Syntax
from plugins.dbms.filemakerpro.takeover import Takeover
from plugins.generic.misc import Miscellaneous


class FilemakerMap(Syntax, Fingerprint, Enumeration, Filesystem, Miscellaneous, Takeover):
    """
    This class defines Filemaker Pro methods
    """

    def __init__(self):
        # self.excludeDbsList = MSSQL_SYSTEM_DBS

        Syntax.__init__(self)
        Fingerprint.__init__(self)
        Enumeration.__init__(self)
        Filesystem.__init__(self)
        Miscellaneous.__init__(self)
        Takeover.__init__(self)

    unescaper[DBMS.FILEMAKERPRO] = Syntax.escape
