#!/usr/bin/env python3
import os
os.environ.setdefault('OSKEN_HUB_TYPE', 'eventlet')

import eventlet
eventlet.monkey_patch()

import sys
import logging
import traceback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
sys.path.insert(0, '.')

from os_ken.base.app_manager import AppManager
from os_ken import cfg

if __name__ == '__main__':
    try:
        cfg.CONF(project='os_ken', args=sys.argv[1:])
        AppManager.run_apps(['controller'])
    except Exception:
        traceback.print_exc()
