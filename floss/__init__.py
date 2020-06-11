# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

import logging

from . import version


logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

__all__ = ('__version__',
           'logger')
__version__ = version.__version__
