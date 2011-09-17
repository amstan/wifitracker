#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
from urllib2 import urlopen

print urlopen(sys.argv[1],open(sys.argv[2]).read()).read()
