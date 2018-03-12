##############################################################################
#
# Copyright (C) Zenoss, Inc. 2007-2018, all rights reserved.
#
# This content is made available according to terms specified in
# License.zenoss under the directory where your Zenoss product is installed.
#
##############################################################################

import Globals
import os.path
import logging
from ZenPacks.zenoss.ZenPackLib import zenpacklib

log = logging.getLogger("zen.NtpMonitor")

skinsDir = os.path.join(os.path.dirname(__file__), 'skins')
from Products.CMFCore.DirectoryView import registerDirectory
if os.path.isdir(skinsDir):
    registerDirectory(skinsDir, globals())

def onCollectorInstalled(ob, event):
    zpFriendly = 'NtpMonitor'
    errormsg = '{0} binary cannot be found on {1}. This is part of the nagios-plugins ' + \
               'dependency, and must be installed before {2} can function.'
    
    verifyBin = 'check_ntp'
    code, output = ob.executeCommand('zenbincheck %s' % verifyBin, 'zenoss', needsZenHome=True)
    if code:
       	log.warn(errormsg.format(verifyBin, ob.hostname, zpFriendly))


zenpacklib.load_yaml()
