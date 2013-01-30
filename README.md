zoop
====

Zabbix Object Oriented Python

The purpose of this python module is to provide instance-based access to data from the Zabbix API.
I use the Python Zabbix API at https://github.com/gescheit/scripts, but wanted a better
way to make use of the data, an object.  I mean, the data is in JSON, which is an OBJECT
notation. It only makes sense to use objects on the programming end :)

Basic class structure and usage:

	api = zoop(url='http://www.example.com/zabbix', username='zabbixuser', password='zabbixpassword')
	 
	zabbixitem = api.item()
	zabbixitem.get(hostid='1234', key_='test_key')
	 
	print zabbixitem["hostid"]
	print zabbixitem["interfaceid"]
	…

#item (dict)

* Methods

- get
- create
- etc.

* The item object is itself a dictionary, so you can call or populate it like a dictionary:

- self["hostid"]
- self["itemid"]
- self["key_"] 
- etc.

#host (dict)

* Methods

- get
- create
- etc.

* A host object is itself a dictionary, so you can call or populate it like a dictionary:

- self["hostid"]
- self["host"] 
- self["name"] 
- etc.

#Module dependencies:

* Python Zabbix API:

- https://github.com/gescheit/scripts (in particular, zabbix_api.py)

#LICENSE:

The license is Apache 2.0.  I didn't simply fork the Python Zabbix API because it's under the LGPL, and I don't like the LGPL.
