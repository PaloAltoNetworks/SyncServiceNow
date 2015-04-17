
ServiceNow Palo Alto Networks Sync
==================================

This program is a proof of concept to demonstrate synchronization of assets and their
attributes from ServiceNow into registered IP tags on a Palo Alto Networks
Next-Generation Firewall.  Once the tags are synchronized, they can be used in
Dynamic Address Groups in the firewall security policy.

Example Usage
-------------

Sync assets from ServiceNow to a Palo Alto Networks Next-Generation Firewall at 10.0.0.1:

    python syncServiceNowAssets.py -v -l admin:admin 10.0.0.1 mycompany.service-now.com servicenowuser:password

Dependencies
------------

* Palo Alto Networks Firewall running PAN-OS 6.0 or higher

* pan-python >= 0.6.0  https://github.com/kevinsteves/pan-python

* pandevice >= 0.2.0  https://github.com/PaloAltoNetworks-BD/pandevice

Contributors
------------

* Brian Torres-Gil <btorres-gil@paloaltonetworks.com>
