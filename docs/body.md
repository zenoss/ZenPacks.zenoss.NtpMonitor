Background
----------
This ZenPack monitors the difference between the system time a server is
using and the time a Network Time Protocol (NTP) server is reporting.

### Prerequisites

- Zenoss 5.0+
- ZenPacks.zenoss.PythonCollector
- ZenPacks.zenoss.ZenPackLib

Usage
--------

The NTPMonitor template must be bound to the device class or device you
want to monitor.

* Select Infrastructure from the navigation bar.
* Click the device name in the device list.
* Expand Monitoring Templates, and then select Device from the left panel.
* Select Bind Templates from the Action menu.appears.
* Add the NTPMonitor template to the list of selected templates, and then click Submit.

The NTPMonitor template is added to the list of monitoring templates.
You can now start collecting the clock offset between the device and
sync peer.


Changes
-------

3.0.0 

- No longer relies on Nagios plugins to monitor NTP servers
- Added unit tests 
- Rewritten as a PythonCollector's PythonDataSource
- Now uses yaml definition (ZenPackLib) instead of objects.xml 
- Added IPv6 support
- Tested with Zenoss Resource Manager  5.3.3, 6.1.2 and 6.2.0

2.2.1 

- Switched from check_ntp_peer to check_ntp_offset. (ZEN-15833)

2.2.2 

- Switched back to check_ntp_peer (ZEN-15833) 
- Tested for compatibility on Zenoss 5.0.9

