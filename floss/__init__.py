# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.

from .utils import ONE_MB
from .utils import STACK_MEM_NAME
from .utils import makeEmulator
from .utils import removeStackMemory

import pkg_resources


__all__ = ('__version__', 'ONE_MB', 'STACK_MEM_NAME', 'makeEmulator', 'removeStackMemory')
__version__ = pkg_resources.get_distribution("mypackage").version
