#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app')
from mitmproxy_opa.opa_filter import OPAFilter

# Create addon instance
addons = [OPAFilter()]