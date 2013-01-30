import sys
from zabbix_api import ZabbixAPI
from UserDict import UserDict
from UserList import UserList


def exitOnException(msg):
    print "Error %s:" % msg.args[0]
    sys.exit(2)


class zoopError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class zoop:
    """Outermost class for all nested classes"""

    def __init__(self, url=None, username=None, password=None):
        if not (url and username and password):
            raise zoopError("Valid url, username and password must be passed at instance creation.")
            sys.exit(2)
        self.url = url
        self.username = username
        self.password = password
        # Populate these values in these subclasses so they are filled.
        self.connect()


    def connect(self):
        """Do login and fill the inner class API values"""
        self.login()
        self.fillInnerClassesAPI()
    

    def login(self):
        """Do API login"""
        try:
            self.api = ZabbixAPI(server=self.url)
            self.api.login(self.username, self.password)
        except Exception, e:
            exitOnException(e)
    

    def version(self):
        """This very useful to do a generic attempt to connect and get a value back (verify connectivity)"""
        try:
            retval = self.api.APIInfo.version()
        except Exception:
            retval = 0
        return retval


    def fillInnerClassesAPI(self):
        """Fill the inner classes API values"""
        zoop.host.api = self.api
        zoop.hostinterface.api = self.api
        zoop.item.api = self.api
            

    class item(UserDict):
        """Zabbix item object.  Useful for item manipulation.  Pull/Push items via the API"""

        def __init__(self):
            UserDict.__init__(self)
            self.empty()
            self.internal_item = {}

    
        def empty(self):
            keylist = [ 'itemid', 'username', 'inventory_link', 'lastclock', 'lastlogsize', 'trends', 'snmpv3_authpassphrase', 'snmp_oid', 'templateid', 'snmpv3_securitylevel', 'port', 'multiplier', 'lastns', 'authtype', 'password', 'logtimefmt', 'mtime', 'delay', 'publickey', 'params', 'snmpv3_securityname', 'formula', 'type', 'prevvalue', 'status', 'lastvalue', 'snmp_community', 'description', 'data_type', 'trapper_hosts', 'units', 'value_type', 'prevorgvalue', 'delta', 'delay_flex', 'lifetime', 'interfaceid', 'snmpv3_privpassphrase', 'hostid', 'key_', 'name', 'privatekey', 'filter', 'valuemapid', 'flags', 'error', 'ipmi_sensor', 'history' ]
            for k in keylist:
                self[k] = None
     
    
        def fill_item_dict(self, mydict):
            for k in mydict.iterkeys():
                # Check for null responses and mismatching hostids
                if k is "hostid" and self[k] is not mydict[k]:
                    print "Error: hostid mismatch!"
                    sys.exit(2)
                elif not mydict[k]:
                    self[k] = ''
                # Otherwise add them to the dict
                else:
                    self[k] = mydict[k]
    
    
        def exists(self):
            """Simply put, it exists or it doesn't. Can't go wrong with hostid, no ambiguity."""
            try:
                retval = zoop.item.api.item.exists({"key_":self["key_"],"hostids":self["hostid"]})
            except Exception, e:
                exitOnException(e)
            return retval
    
        
        def get(self, key_=None, hostid=None):
            """First determine if it exists, then fill our "self" with the values"""
            self["key_"] = key_ if key_ else None
            self["hostid"] = hostid if hostid else None
            try:
                if self.exists():
                    self.fill_item_dict(zoop.item.api.item.get({"output":"extend","hostids":(hostid),"filter":{"key_":(key_)}})[0])
            except Exception, e:
                exitOnException(e)
    

        def itemkeycheck(self):
            """Strips out items defined as type None, and makes sure the required dict keys are present afterwards (i.e., none were stripped because they were still 'None' type"""
            print "Self currently looks like this: "
            print self

            for k in list(self.keys()):
                if self[k] is None:
                    del(self[k])

            print "Now self looks like this: "
            print self
                
            requiredkeys = [ "hostid", "interfaceid", "history", "delay", "name", "key_", "type", "value_type", "applications" ]
            retval = True
            for key in requiredkeys:
                if not key in self:
                    retval = False
            return retval 

    
        def show(self):
            try:
                for k in self.iterkeys():
                    print k, self[k]
            except Exception, e:
                print "Error: Unable to iterate through dict keys."
                print e
    
    
        def create(self):
            """We certainly don't want to create it if it exists already..."""
            if not self.exists():
                try:
                    if self.itemkeycheck():
                        ItemObject = {}
                        # Something about "self" won't allow JSON to serialize, so I'll pass all of the keys here.  The passed value-object works.
                        for k,v in self.iteritems():
                            ItemObject[k] = v
#                        print "second = ", ItemObject
                        retval = zoop.item.api.item.create(ItemObject)
                except Exception, e:
                    exitOnException(e)
                return retval
            else: 
                print "Error! Item already exists on hostid " + str(self['hostid']) + " with key " + self['key_']
    
    
    
    
    class hostinterface(UserList):
        """ 
        Zabbix host interface object/dict for host interactions with the API
        """
        def __init__(self):
            UserList.__init__(self)
    
        def map_type(self, iftype):
            """Map an integer iftype to a string"""
            try:
                retval = ""
                if type(iftype) is type(int()):
                    if iftype == 1:
                        retval = "agent"
                    elif iftype == 2:
                        retval = "snmp"
                    elif iftype == 3:
                        retval = "ipmi"
                    elif iftype == 4:
                        retval = "jmx"
                else:
                    print "Error: Provided interface value could not be mapped."
            except Exception, e:
                exitOnException(e)
            return retval
        
        
        def verify_type(self, iftype):
            """Verify an iftype"""
            try:
                retval = 0
                if type(iftype) is type(str()):
                    if iftype.lower() is "agent":
                        retval = 1
                    elif iftype.lower() is "snmp":
                        retval = 2
                    elif iftype.lower() is "ipmi":
                        retval = 3
                    elif iftype.lower() is "jmx":
                        retval = 4
                    else:
                        retval = None
                elif type(iftype) is type(int()):
                    if iftype > 0 and iftype < 5:
                        retval = iftype
                    else:
                        retval = None
                else:
                    print "Error: Provided interface value could not be mapped."
            except Exception, e:
                exitOnException(e)
            return retval
        

        def exists(self, hostid=None, dns=None, ip=None):
            """Since hostid already exists, we can add dns and/or ip to search"""
            mydict = {}
            mydict['hostid'] = hostid if hostid else None
            mydict['dns'] = dns if dns else None
            mydict['ip'] = ip if ip else None
            if not hostid and not dns and not ip:
                print "FAIL: Must provide one of hostid, dns or ip"
                sys.exit(2)
            try:
                return zoop.hostinterface.api.hostinterface.exists(mydict)
            except Exception, e:
                exitOnException(e)
    
        
        def get(self, hostid=None):
            """First determine if it exists, then fill our "self" with the values. Should fill "self" with array of host interfaces."""
            try:
                if self.exists(hostid=(hostid)):
                    results = zoop.hostinterface.api.hostinterface.get({"output":"extend","hostids":hostid})
                    for result in results:
                        self.append(result)
            except Exception, e:
                exitOnException(e)
    
    
        def agent(self, hostid=None):
            """This presumes that you will have one and only one agent per host.  Will return the interfaceid for the MAIN host interface which is type agent"""
            if not len(self) > 0:
                try:
                    self.get(hostid)
                except Exception, e:
                    exitOnException(e)
            try:
                for entry in self:
                    retval = entry["interfaceid"] if entry["type"] == "1" and entry["main"] == "1" else None
                    if retval:
                        break
            except Exception, e:
                exitOnException(e)
    
            return retval
    
    
        def show(self):
            try:
                for entry in self:
                    print "InterfaceID: " + str(entry["interfaceid"])
                    for k in entry.iterkeys():
                        if k == "type":
                            print "    ", k, entry[k], "("+self.map_type(int(entry[k]))+")" 
                        else:
                            print "    ", k, entry[k]
                    print
            except Exception, e:
                print "Error: Unable to iterate through dict keys."
                print e
    
    
    
    
    class host(UserDict):
        """ 
        Zabbix host object/dict for host interactions with the API
        """
        def __init__(self, host=None, hostid=None):
            UserDict.__init__(self)
            self.empty()
    
    
        def empty(self):
            keylist = [ 'host', 'hostid', 'maintenance_type', 'maintenances', 'ipmi_username', 'snmp_disable_until', 'ipmi_authtype', 'ipmi_disable_until', 'lastaccess', 'snmp_error', 'ipmi_privilege', 'jmx_error', 'jmx_available', 'ipmi_errors_from', 'maintenanceid', 'snmp_available', 'available', 'disable_until', 'ipmi_password', 'ipmi_available', 'maintenance_status', 'snmp_errors_from', 'ipmi_error', 'proxy_hostid', 'name', 'jmx_errors_from', 'jmx_disable_until', 'status', 'error', 'maintenance_from', 'errors_from' ]
            for k in keylist:
                self[k] = None
     
    
        def fill_host_dict(self, mydict):
            for result in mydict:
                for k in result.iterkeys():
                    # Check for null responses and maintenances (an odd array, for now)
                    if k is "maintenances":
                        self[k] = list()
                    elif not result[k]:
                        self[k] = ''
                    # Otherwise add them to the dict
                    else:
                        self[k] = result[k]
            
    
        def exists(self):
            try:
                if self['hostid']: 
                    mykey = 'hostid'
                elif self['host']: 
                    mykey = 'host'
                elif self['name']: 
                    mykey = 'name'
                else:
                    # This should never happen
                    print "Error: No host, hostid or name provided"
                    sys.exit(2)
                retval = zoop.host.api.host.exists({mykey:self[mykey]})
    
            except Exception, e:
                exitOnException(e)
            return retval
        
    
        def appexists(self, appname):
            try:
                retval = zoop.host.api.application.exists({"name":appname,"hostid":self['hostid']})
            except Exception, e:
                exitOnException(e)
            return retval
    
    
        def getappid(self, appname):
            try:
                if self.appexists(appname):
                    retval = zoop.host.api.application.get({"output":"extend","hostids":self['hostid'],"filter":{"name":appname}})[0]["applicationid"]
                else:
                    retval = False
            except Exception, e:
                exitOnException(e)
            return retval
    
    
        def createapp(self, appname):
            try:
                if not self.appexists(appname):
                    retval = zoop.host.api.application.create({"name":appname,"hostid":self['hostid']})["applicationids"][0]
                else:
                    retval = False
            except Exception, e:
                exitOnException(e)
            return retval
    
    
        def get(self, hostid=None, host=None, name=None):
            """See if a matching host exists, then try to pull the data into the object"""        
            self["hostid"] = hostid if hostid else None
            self["host"] = host if host else None
            self["name"] = name if name else None
            if self.exists():
                try:
                    if self['hostid']: 
                        mykey = 'hostid'
                    elif self['host']: 
                        mykey = 'host'
                    elif self['name']: 
                        mykey = 'name'
                    else:
                        # This should never happen
                        print "Error: You have no host or hostid."
                        sys.exit(2)
        
                    test = zoop.host.api.host.get({"filter":{mykey:self[mykey]},"output":"extend"})
                    if len(test) == 1:
                        self.fill_host_dict(test)
                    else: 
                        print "ERROR: More than one matching entry found for zoop.host.api.host.get!"
                        sys.exit(2)
                except Exception, e:
                    exitOnException(e)
            else:
                print "Can't perform get. Host does not exist!"
    
    
        def show(self):
            try:
                for k in self.iterkeys():
                    print k, self[k]
            except Exception, e:
                print "Error: Unable to iterate through dict keys."
                print e
                 

