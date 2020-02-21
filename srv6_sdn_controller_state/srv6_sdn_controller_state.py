#!/usr/bin/python

# General imports
from bson.objectid import ObjectId
import pymongo
from pymongo import ReturnDocument
import datetime
import logging
import urllib.parse
from ipaddress import IPv4Interface, IPv6Interface
from srv6_sdn_controller_state import utils


# Global variables
DEFAULT_MONGODB_HOST = '172.0.248.121'
DEFAULT_MONGODB_PORT = 27017
DEFAULT_MONGODB_USERNAME = 'root'
DEFAULT_MONGODB_PASSWORD = '12345678'

DEFAULT_VXLAN_PORT = 4789

# Table where we store our seg6local routes
LOCAL_SID_TABLE = 1
# Reserved table IDs
RESERVED_TABLEIDS = [0, 253, 254, 255]
RESERVED_TABLEIDS.append(LOCAL_SID_TABLE)

# Set logging level
logging.basicConfig(level=logging.DEBUG)

# MongoDB client
client = None


# Get a reference to the MongoDB client
def get_mongodb_session(host=DEFAULT_MONGODB_HOST,
                        port=DEFAULT_MONGODB_PORT,
                        username=DEFAULT_MONGODB_USERNAME,
                        password=DEFAULT_MONGODB_PASSWORD):
    global client
    # Percent-escape username
    username = urllib.parse.quote_plus(username)
    # Percent-escape password
    password = urllib.parse.quote_plus(password)
    # Return the MogoDB client
    logging.debug('Trying to establish a connection '
                  'to the db (%s:%s)' % (host, port))
    if client is None:
        client = pymongo.MongoClient(host=host,
                                     port=port,
                                     username=username,
                                     password=password)
    return client


''' Functions operating on the devices collection '''


# Register a device
def register_device(deviceid, features, interfaces, mgmtip,
                    tenantid):
    # Build the document to insert
    device = {
        'deviceid': deviceid,
        'name': None,
        'description': None,
        'features': features,
        'interfaces': interfaces,
        'mgmtip': mgmtip,
        'tenantid': tenantid,
        'tunnel_mode': None,
        'tunnel_info': None,
        'nat_type': None,
        'connected': True,
        'configured': False,
        'enabled': False,
        'stats': {
            'counters': {
                'tunnels': []
            }
        },
        'vtep_ip_addr': None,
        'registration_timestamp': str(datetime.datetime.utcnow())
    }
    # Register the device
    logging.debug('Registering device on DB: %s' % device)
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Add the device to the collection
        success = devices.insert_one(device).acknowledged
        if success:
            logging.debug('Device successfully registered')
        else:
            logging.error('Cannot register the device')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


# Unregister a device
def unregister_device(deviceid):
    # Build the document to insert
    device = {'deviceid': deviceid}
    # Unregister the device
    logging.debug('Unregistering device: %s' % deviceid)
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Delete the device from the collection
        success = devices.delete_one(device).deleted_count == 1
        if success:
            logging.debug('Device unregistered successfully')
        else:
            logging.error('Cannot unregister the device')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


# Unregister all devices of a tenant
def unregister_devices_by_tenantid(tenantid):
    # Build the filter
    device = {'tenantid': tenantid}
    # Delete all the devices in the collection
    logging.debug('Unregistering all the devices of the tenant %s' % tenantid)
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        success = devices.delete_many(device).acknowledged
        if success:
            logging.debug('Devices successfully unregistered')
        else:
            logging.error('Cannot unregister the devices')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


# Unregister all devices
def unregister_all_devices():
    # Delete all the devices in the collection
    logging.debug('Unregistering all the devices')
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        success = devices.delete_many().acknowledged
        if success:
            logging.debug('Devices successfully unregistered')
        else:
            logging.error('Cannot unregister the devices')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


# Update tunnel mode
def update_tunnel_mode(deviceid, mgmtip, interfaces, tunnel_mode, nat_type):
    # Build the query
    query = [{'deviceid': deviceid}]
    for interface in interfaces:
        query.append({'deviceid': deviceid, 'interfaces.name': interface})
    # Build the update
    update = [{
        '$set': {'mgmtip': mgmtip,
                 'tunnel_mode': tunnel_mode,
                 'nat_type': nat_type}
    }]
    for interface in interfaces.values():
        update.append({
            '$set': {
                'interfaces.$.ext_ipv4_addrs': interface['ext_ipv4_addrs'],
                'interfaces.$.ext_ipv6_addrs': interface['ext_ipv6_addrs']
            }
        })
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Update the device
        for q, u in zip(query, update):
            logging.debug('Updating interface %s on DB' % q)
            res = devices.update_one(q, u).matched_count == 1
            if res:
                logging.debug('Interface successfully updated')
                if success is not False:
                    success = True
            else:
                logging.error('Cannot update interface')
                success = False
        if success:
            logging.debug('Device successfully updated')
        else:
            logging.error('Cannot update device')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False in case of failure or
    # None if an error occurred during the connection to the db
    return success


# Get devices
def get_devices(deviceids=None, tenantid=None, return_dict=False):
    # Build the query
    query = dict()
    if tenantid is not None:
        query['tenantid'] = tenantid
    if deviceids is not None:
        query['deviceid'] = {'$in': list(deviceids)}
    # Find the device by device ID
    logging.debug('Retrieving devices [%s] by tenant ID %s' % (
        deviceids, tenantid))
    res = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the devices
        devices = devices.find(query)
        if return_dict:
            # Build a dict representation of the devices
            res = dict()
            for device in devices:
                deviceid = device['deviceid']
                res[deviceid] = device
        else:
            res = list(devices)
        logging.debug('Devices found: %s' % devices)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the devices
    return res


# Get a device
def get_device(deviceid):
    # Build the query
    query = {'deviceid': deviceid}
    # Find the device
    logging.debug('Retrieving device %s' % deviceid)
    device = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the devices
        device = devices.find_one(query)
        logging.debug('Device found: %s' % device)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the device
    return device


# Return True if a device exists,
# False otherwise
def device_exists(deviceid):
    # Build the query
    device = {'deviceid': deviceid}
    device_exists = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Count the devices with the given device ID
        logging.debug('Searching the device %s' % deviceid)
        if devices.count_documents(device, limit=1):
            logging.debug('The device exists')
            device_exists = True
        else:
            logging.debug('The device does not exist')
            device_exists = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the device exists,
    # False if the device does not exist
    # or None if an error occurred during the connection to the db
    return device_exists


# Return True if all the devices exist,
# False otherwise
def devices_exists(deviceids):
    # Build the query
    query = {'deviceid': {'$in': deviceids}}
    devices_exist = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Count the devices with the given device ID
        logging.debug('Searching the devices %s' % deviceids)
        if devices.count_documents(query) == len(deviceids):
            logging.debug('The devices exist')
            devices_exist = True
        else:
            logging.debug('The devices do not exist')
            devices_exist = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the devices exist,
    # False if the devices do not exist
    # or None if an error occurred during the connection to the db
    return devices_exist


# Return True if a device exists and is in enabled state,
# False otherwise
def is_device_enabled(deviceid):
    # Get the device
    logging.debug('Searching the device %s' % deviceid)
    device = get_device(deviceid)
    res = None
    if device is not None:
        # Get the status of the device
        res = device['enabled']
        if res:
            logging.debug('The device is enabled')
        else:
            logging.debug('The device is not enabled')
    # Return True if the device is enabled,
    # False if it is not enabled or
    # None if an error occurred during the connection to the db
    return res


# Return True if a device exists and is in configured state,
# False otherwise
def is_device_configured(deviceid):
    # Get the device
    logging.debug('Searching the device %s' % deviceid)
    device = get_device(deviceid)
    res = None
    if device is not None:
        # Get the status of the device
        res = device['configured']
        if res:
            logging.debug('The device is configured')
        else:
            logging.debug('The device is not configured')
    # Return True if the device is configured,
    # False if it is not configured or
    # None if an error occurred during the connection to the db
    return res


# Return True if a device exists and is in connected state,
# False otherwise
def is_device_connected(deviceid):
    # Get the device
    logging.debug('Searching the device %s' % deviceid)
    device = get_device(deviceid)
    res = None
    if device is not None:
        # Get the status of the device
        res = device['connected']
        if res:
            logging.debug('The device is connected')
        else:
            logging.debug('The device is not connected')
    # Return True if the device is connected,
    # False if it is not connected or
    # None if an error occurred during the connection to the db
    return res


# Return True if an interface exists on a given device,
# False otherwise
def interface_exists_on_device(deviceid, interface_name):
    # Build the query
    query = {'deviceid': deviceid, 'interfaces.name': interface_name}
    # Get the device
    logging.debug('Getting the interface %s on the device %s' %
                  (interface_name, deviceid))
    exists = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Add the device to the collection
        device = devices.find_one(query)
        if device is not None:
            logging.debug('The interface exists on the device')
            exists = True
        else:
            logging.debug('The interface does not exist on the device')
            exists = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the interface exists,
    # False if it not exists or
    # None if an error occurred during the connection to the db
    return exists


# Return an interface of a device
def get_interface(deviceid, interface_name):
    logging.debug('Getting the interface %s of device %s' %
                  (interface_name, deviceid))
    # Build the query
    query = {'deviceid': deviceid}
    # Build the filter
    filter = {'interfaces': {'$elemMatch': {'name': interface_name}}}
    interface = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the interface
        interfaces = devices.find_one(query, filter)['interfaces']
        if len(interfaces) == 0:
            # Interface not found
            logging.debug('Interface not found')
        else:
            interface = interfaces[0]
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the interface if exists,
    # None if it does not exist or if an error occurred
    return interface


# Return all the interfaces of a device
def get_interfaces(deviceid):
    # Get the device
    logging.debug('Getting the interfaces of device %s' % deviceid)
    device = get_device(deviceid)
    interfaces = None
    if device is not None:
        # Return the interfaces
        interfaces = device['interfaces']
    # Return the interfaces if the device exists or
    # None if an error occurred during the connection to the db
    return interfaces


# Get device's IPv4 addresses
def get_ipv4_addresses(deviceid, interface_name):
    # Find the IPv4 addresses by device ID and interface
    logging.debug('Retrieving IPv4 addresses for device %s' % deviceid)
    interface = get_interface(deviceid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        addrs = interface['ipv4_addrs']
        logging.debug('IPv4 addresses: %s' % addrs)
    # Return the IPv4 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's IPv6 addresses
def get_ipv6_addresses(deviceid, interface_name):
    # Find the IPv6 addresses by device ID and interface
    logging.debug('Retrieving IPv6 addresses for device %s' % deviceid)
    interface = get_interface(deviceid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        addrs = interface['ipv6_addrs']
        logging.debug('IPv6 addresses: %s' % addrs)
    # Return the IPv6 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's IP addresses
def get_ip_addresses(deviceid, interface_name):
    # Find the IP addresses by device ID and interface name
    logging.debug('Retrieving IP addresses for device %s '
                  'and interface %s' % (deviceid, interface_name))
    interface = get_interface(deviceid, interface_name)
    addrs = None
    if interface is not None:
        addrs = interface['ipv4_addrs'] + \
            interface['ipv6_addrs']
        logging.debug('IP addresses: %s' % addrs)
        return addrs
    # Return the IP addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's external IPv4 addresses
def get_ext_ipv4_addresses(deviceid, interface_name):
    # Find the external IPv4 addresses by device ID and interface
    logging.debug(
        'Retrieving external IPv4 addresses for device %s' % deviceid)
    interface = get_interface(deviceid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        addrs = interface['ext_ipv4_addrs']
        logging.debug('External IPv4 addresses: %s' % addrs)
    # Return the IPv4 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's external IPv6 addresses
def get_ext_ipv6_addresses(deviceid, interface_name):
    # Find the external IPv6 addresses by device ID and interface
    logging.debug(
        'Retrieving external IPv6 addresses for device %s' % deviceid)
    interface = get_interface(deviceid, interface_name)
    addrs = None
    if interface is not None:
        # Extract the addresses
        addrs = interface['ext_ipv6_addrs']
        logging.debug('External IPv6 addresses: %s' % addrs)
    # Return the IPv6 addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's external IP addresses
def get_ext_ip_addresses(deviceid, interface_name):
    # Find the external IP addresses by device ID and interface name
    logging.debug('Retrieving external IP addresses for device %s '
                  'and interface %s' % (deviceid, interface_name))
    interface = get_interface(deviceid, interface_name)
    addrs = None
    if interface is not None:
        addrs = interface['ext_ipv4_addrs'] + \
            interface['ext_ipv6_addrs']
        logging.debug('External IP addresses: %s' % addrs)
        return addrs
    # Return the IP addresses associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return addrs


# Get device's IPv4 subnets
def get_ipv4_subnets(deviceid, interface_name):
    # Find the IPv4 subnets by device ID and interface
    logging.debug('Retrieving IPv4 subnets for device %s' % deviceid)
    interface = get_interface(deviceid, interface_name)
    subnets = None
    if interface is not None:
        # Extract the subnets
        subnets = interface['ipv4_subnets']
        logging.debug('IPv4 subnets: %s' % subnets)
    # Return the IPv4 subnets associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return subnets


# Get device's IPv6 subnets
def get_ipv6_subnets(deviceid, interface_name):
    # Find the IPv6 subnets by device ID and interface
    logging.debug('Retrieving IPv6 subnets for device %s' % deviceid)
    interface = get_interface(deviceid, interface_name)
    subnets = None
    if interface is not None:
        # Extract the subnets
        subnets = interface['ipv6_subnets']
        logging.debug('IPv6 subnets: %s' % subnets)
    # Return the IPv6 subnets associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return subnets


# Get device's IP subnets
def get_ip_subnets(deviceid, interface_name):
    # Find the IP subnets by device ID and interface name
    logging.debug('Retrieving IP subnets for device %s '
                  'and interface %s' % (deviceid, interface_name))
    interface = get_interface(deviceid, interface_name)
    subnets = None
    if interface is not None:
        subnets = interface['ipv4_subnets'] + \
            interface['ipv6_subnets']
        logging.debug('IP subnets: %s' % subnets)
        return subnets
    # Return the IP subnets associated to the
    # interface if the interface exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
    return subnets


# Get router's IPv4 loopback IP
def get_loopbackip_ipv4(deviceid):
    addrs = get_ipv4_addresses(deviceid, 'lo')
    if addrs is not None:
        return addrs[0]
    else:
        return None


# Get router's IPv4 loopback net
def get_loopbacknet_ipv4(deviceid):
    loopbackip = get_loopbackip_ipv4(deviceid)
    if loopbackip is not None:
        return IPv4Interface(loopbackip).network.__str__()
    else:
        return None


# Get router's IPv6 loopback IP
def get_loopbackip_ipv6(deviceid):
    addrs = get_ipv6_addresses(deviceid, 'lo')
    if addrs is not None:
        return addrs[0]
    else:
        return None


# Get router's IPv6 loopback net
def get_loopbacknet_ipv6(deviceid):
    loopbackip = get_loopbackip_ipv6(deviceid)
    if loopbackip is not None:
        return IPv6Interface(loopbackip).network.__str__()
    else:
        return None


# Get router's management IP address
def get_router_mgmtip(deviceid):
    logging.debug('Retrieving management IP for device %s' % deviceid)
    # Get the device
    device = get_device(deviceid)
    mgmtip = None
    if device is not None:
        # Get the management IP address
        mgmtip = device['mgmtip']
        logging.debug('Management IP: %s' % mgmtip)
    # Return the management IP address if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return mgmtip


# Get WAN interfaces of a device
def get_wan_interfaces(deviceid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid)
    wan_interfaces = None
    if interfaces is not None:
        # Filter WAN interfaces
        wan_interfaces = list()
        for interface in interfaces:
            if interface['type'] == utils.InterfaceType.WAN:
                wan_interfaces.append(interface['name'])
    # Return the WAN interfaces if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return wan_interfaces


# Get LAN interfaces of a device
def get_lan_interfaces(deviceid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid)
    lan_interfaces = None
    if interfaces is not None:
        # Filter LAN interfaces
        lan_interfaces = list()
        for interface in interfaces:
            if interface['type'] == utils.InterfaceType.LAN:
                lan_interfaces.append(interface['name'])
    # Return the LAN interfaces if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return lan_interfaces


# Get non-loopback interfaces of a device
def get_non_loopback_interfaces(deviceid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid)
    non_lo_interfaces = None
    if interfaces is not None:
        # Filter non-loopback interfaces
        non_lo_interfaces = list()
        for interface in interfaces:
            if interface['name'] != 'lo':
                non_lo_interfaces.append(interface['name'])
    # Return the non-loopback interfaces if the device exists,
    # None if the device does not exist or
    # None if an error occurred during the connection to the db
    return non_lo_interfaces


# Configure the devices
def configure_devices(devices):
    # Build the update statements
    queries = []
    updates = []
    for device in devices:
        # Get device ID
        deviceid = device['deviceid']
        # Get device name
        name = device['name']
        # Get device description
        description = device['description']
        # Add query
        queries.append({'deviceid': deviceid})
        # Add update
        updates.append({'$set': {
            'name': name,
            'description': description,
            'configured': True
        }})
        # Get interfaces
        interfaces = device['interfaces']
        for interface in interfaces.values():
            # Get interface name
            interface_name = interface['name']
            # Get IPv4 addresses
            ipv4_addrs = interface['ipv4_addrs']
            # Get IPv6 addresses
            ipv6_addrs = interface['ipv6_addrs']
            # Get IPv4 subnets
            ipv4_subnets = interface['ipv4_subnets']
            # Get IPv6 subnets
            ipv6_subnets = interface['ipv6_subnets']
            # Get the type of the interface
            type = interface['type']
            # Add query
            queries.append(
                {'deviceid': deviceid, 'interfaces.name': interface_name})
            # Add update
            updates.append({
                '$set': {
                    'interfaces.$.ipv4_addrs': ipv4_addrs,
                    'interfaces.$.ipv6_addrs': ipv6_addrs,
                    'interfaces.$.ipv4_subnets': ipv4_subnets,
                    'interfaces.$.ipv6_subnets': ipv6_subnets,
                    'interfaces.$.type': type
                }
            })
    res = True
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Update the devices
        logging.debug('Configuring devices')
        for query, update in zip(queries, updates):
            success = devices.update_one(query, update).matched_count == 1
            if not success:
                logging.error('Cannot configure device %s' % query)
                res = False
        logging.debug('Devices configured')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
        res = None
    # Return True if all the devices have been configured,
    # False otherwise
    return res


# Enable or disable a device
def set_device_enabled_flag(deviceid, enabled):
    # Build the query
    query = {'deviceid': deviceid}
    # Build the update
    update = {'$set': {'enabled': enabled}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Change 'enabled' flag
        logging.debug('Change enabled flag for device %s' % deviceid)
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot change enabled flag: device not found')
        else:
            logging.debug('Enabled flag updated successfully')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False otherwise
    return success


# Mark the device as configured / unconfigured
def set_device_configured_flag(deviceid, configured):
    # Build the query
    query = {'deviceid': deviceid}
    # Build the update
    update = {'$set': {'configured': configured}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Change 'configured' flag
        logging.debug('Change configured flag for device %s' % deviceid)
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot change configured flag: device not found')
        else:
            logging.debug('Configured flag updated successfully')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False otherwise
    return success


# Set / unset 'connected' flag for a device
def set_device_connected_flag(deviceid, connected):
    # Build the query
    query = {'deviceid': deviceid}
    # Build the update
    update = {'$set': {'connected': connected}}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Change 'connected' flag
        logging.debug('Change connected flag for device %s' % deviceid)
        success = devices.update_one(query, update).matched_count == 1
        if not success:
            logging.error('Cannot change connected flag: device not found')
        else:
            logging.debug('Connected flag updated successfully')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False otherwise
    return success


# Get the counter of a tunnel mode on a device and
# increase the counter
def get_and_inc_tunnel_mode_counter(tunnel_name, deviceid):
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug('Getting the device %s' % deviceid)
        # Build query
        query = {'deviceid': deviceid,
                 'stats.counters.tunnels.tunnel_mode': {'$ne': tunnel_name}}
        # Build the update
        update = {'$push': {
            'stats.counters.tunnels': {'tunnel_mode': tunnel_name, 'counter': 0}}}
        # If the counter does not exist, create it
        devices.update_one(query, update)
        # Build the query
        query = {'deviceid': deviceid,
                 'stats.counters.tunnels.tunnel_mode': tunnel_name}
        # Build the update
        update = {'$inc': {'stats.counters.tunnels.$.counter': 1}}
        # Increase the counter for the tunnel mode
        device = devices.find_one_and_update(
            query, update)
        # Return the counter if exists, 0 otherwise
        counter = 0
        for tunnel_mode in device['stats']['counters']['tunnels']:
            if tunnel_name == tunnel_mode['tunnel_mode']:
                counter = tunnel_mode['counter']
        logging.debug('Counter before the increment: %s' % counter)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Decrease the counter of a tunnel mode on a device and
# return the counter after the decrement
def dec_and_get_tunnel_mode_counter(tunnel_name, deviceid):
    # Build the query
    query = {'deviceid': deviceid,
             'stats.counters.tunnels.tunnel_mode': tunnel_name}
    counter = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug('Getting the device %s' % deviceid)
        # Decrease the counter for the tunnel mode
        device = devices.find_one_and_update(
            query, {'$inc': {'stats.counters.tunnels.$.counter': -1}},
            return_document=ReturnDocument.AFTER)
        # Return the counter
        counter = -1
        for tunnel_mode in device['stats']['counters']['tunnels']:
            if tunnel_name == tunnel_mode['tunnel_mode']:
                counter = tunnel_mode['counter']
        if counter == -1:
            logging.error('Cannot update counter')
        logging.debug('Counter after the decrement: %s' % counter)
        # If counter is 0, remove the tunnel mode from the device stats
        if counter == 0:
            logging.debug('Counter set to 0, removing tunnel mode')
            devices.update_one(
                query, {'$pull': {'stats.counters.tunnels': {'tunnel_mode': tunnel_name}}})
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Return the number of tunnels configured on a device
def get_num_tunnels(deviceid):
    # Build the query
    query = {'deviceid': deviceid}
    num = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Find the device
        logging.debug('Counting tunnels for device %s' % deviceid)
        # Get the device
        device = devices.find_one(query)
        if device is None:
            logging.error('Device %s not found' % deviceid)
        else:
            # Extract tunnel mode counter
            counters = device['stats']['counters']['tunnels']
            # Count the tunnels
            num = 0
            for tunnel_mode in counters:
                num += tunnel_mode['counter']
            logging.debug('%s tunnels found' % num)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the number of tunnels if success,
    # None if an error occurred during the connection to the db
    return num


''' Functions operating on the overlays collection '''


# Create overlay
def create_overlay(name, type, slices, tenantid, tunnel_mode):
    # Build the document
    overlay = {
        'name': name,
        'tenantid': tenantid,
        'type': type,
        'slices': slices,
        'tunnel_mode': tunnel_mode,
        'vni': None
    }
    overlayid = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Add the overlay to the collection
        logging.debug('Creating the overlay: %s' % overlay)
        overlayid = overlays.insert_one(overlay).inserted_id
        if overlayid is not None:
            logging.debug('Overlay created successfully')
        else:
            logging.error('Cannot create the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return overlayid


# Remove overlay by ID
def remove_overlay(overlayid):
    # Build the filter
    overlay = {'_id': ObjectId(overlayid)}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Remove the overlay from the collection
        logging.debug('Removing the overlay: %s' % overlayid)
        success = overlays.delete_one(overlay).deleted_count == 1
        if success:
            logging.debug('Overlay removed successfully')
        else:
            logging.error('Cannot remove the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success, False otherwise
    return success


# Remove all the overlays
def remove_all_overlays():
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Delete all the overlays in the collection
        logging.debug('Removing all overlays')
        success = overlays.delete_many({}).acknowledged
        if success:
            logging.debug('Overlays removed successfully')
        else:
            logging.error('Cannot remove the overlays')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success, False otherwise
    return success


# Remove all the overlays of a tenant
def remove_overlays_by_tenantid(tenantid):
    # Build the filter
    filter = {'tenantid': tenantid}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Delete all the overlays in the collection
        logging.debug('Removing all overlays of tenant: %s' % tenantid)
        success = overlays.delete_many(filter).acknowledged
        if success:
            logging.debug('Overlays removed successfully')
        else:
            logging.error('Cannot remove the overlays')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success, False otherwise
    return success


# Get overlay
def get_overlay(overlayid):
    # Build the query
    query = {'_id': overlayid}
    overlay = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the device by device ID
        logging.debug('Retrieving overlay %s' % overlayid)
        overlay = overlays.find_one(query)
        if overlay is not None:
            logging.debug('Overlay found: %s' % overlay)
        else:
            logging.error('Overlay not found')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay if it exists,
    # None if it does not exist
    # None if an error occurred during the connection to the db
    return overlay


# Get overlays
def get_overlays(overlayids=None, tenantid=None):
    # Build the query
    query = dict()
    if tenantid is not None:
        query['tenantid'] = tenantid
    if overlayids is not None:
        query['_id'] = {'$in': [ObjectId(overlayid)
                                for overlayid in overlayids]}
    overlays = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the device by device ID
        logging.debug('Retrieving overlays by tenant ID %s' % tenantid)
        overlays = list(overlays.find(query))
        logging.debug('Overlays found: %s' % overlays)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the list of the overlays if no errors or
    # None if an error occurred during the connection to the db
    return overlays


# Get a overlay by its name
def get_overlay_by_name(name, tenantid):
    # Build the query
    query = {'name': name, 'tenantid': tenantid}
    overlay = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlay
        logging.debug('Searching the overlay %s, tenant ID %s' %
                      (name, tenantid))
        overlay = overlays.find_one(query)
        if overlay is not None:
            logging.debug('Overlay found: %s' % overlay)
        else:
            logging.debug('Cannot find the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay if it exists,
    # None if it does not exist or an error
    # occurred during the connection to the db
    return overlay


# Return True if an overlay exists
# with the provided name exists, False otherwise
def overlay_exists(name, tenantid):
    # Build the query
    query = {'name': name, 'tenantid': tenantid}
    overlay_exists = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Count the overlays with the given name and tenant ID
        logging.debug('Searching the overlay %s, tenant ID %s' %
                      (name, tenantid))
        if overlays.count_documents(query, limit=1):
            logging.debug('The overlay exists')
            overlay_exists = True
        else:
            logging.debug('The overlay does not exist')
            overlay_exists = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the overlay exists,
    # False if the overlay does not exist
    # or None if an error occurred during the connection to the db
    return overlay_exists


# Add a slice to an overlay
def add_slice_to_overlay(overlayid, _slice):
    # Build the query
    query = {'_id': ObjectId(overlayid)}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Add the slice to the overlay
        logging.debug('Adding the slice to the overlay %s' % overlayid)
        success = overlays.update_one(
            query,
            {'$push': {'slices': _slice}}
        ).matched_count == 1
        if success:
            logging.debug('Slice added to the overlay')
        else:
            logging.error('Cannot add the slice to the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Add many slices to an overlay
def add_many_slices_to_overlay(overlayid, slices):
    # Build the query
    query = {'_id': ObjectId(overlayid)}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Add the slices to the overlay
        logging.debug('Adding the slice to the overlay %s' % overlayid)
        success = overlays.update_one(
            query,
            {'$pushAll': {'slices': slices}}
        ).matched_count == 1
        if success:
            logging.debug('Slices added to the overlay')
        else:
            logging.error('Cannot add the slices to the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if all the slices added to the overlay
    # False if some slice has not been added to the overlay
    # None if an error occurred during the connection to the db
    return success


# Remove a slice from an overlay
def remove_slice_from_overlay(overlayid, _slice):
    # Build the query
    query = {'_id': ObjectId(overlayid)}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Remove the slice from the overlay
        logging.debug('Removing the slice from the overlay %s' % overlayid)
        success = overlays.update_one(
            query,
            {'$pull': {'slices': _slice}}
        ).matched_count == 1
        if success:
            logging.debug('Slice removed from the overlay')
        else:
            logging.error('Cannot remove the slice from the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure or
    # None if an error occurred during the connection to the db
    return success


# Remove many slices from an overlay
def remove_many_slices_from_overlay(overlayid, slices):
    # Build the query
    query = {'_id': ObjectId(overlayid)}
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Remove the slices to the overlay
        logging.debug('Removing the slices from the overlay %s' % overlayid)
        success = overlays.update_one(
            query,
            {'$pullAll': {'slices': slices}}
        ).matched_count == 1
        if success:
            logging.debug('Slices removed from the overlay')
        else:
            logging.error('Cannot remove the sices from the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure or
    # None if an error occurred during the connection to the db
    return success


# Retrieve the slices contained in a given overlay
def get_slices_in_overlay(overlayid):
    # Get the overlays
    logging.debug('Getting the slices in the overlay %s' % overlayid)
    overlay = get_overlay(overlayid)
    # Extract the slices from the overlay
    slices = None
    if overlay is not None:
        slices = overlay['slices']
        logging.debug('Slices found: %s' % slices)
    # Return the list of the slices if the overlay exists
    # None if the overlay does not exist
    # None if an error occurred during the connection to the db
    return


# Return the overlay which contains the slice,
# None the slice is not assigned to any overlay
def get_overlay_containing_slice(_slice, tenantid):
    # Build the query
    query = {
        'tenantid': tenantid,
        'slices.deviceid': _slice['deviceid'],
        'slices.interface_name': _slice['interface_name']
    }
    # Find the device
    logging.debug('Checking if the slice %s (tenant %s) '
                  'is assigned to an overlay' % (_slice, tenantid))
    overlay = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlays
        overlay = overlays.find_one(query)
        if overlay is not None:
            logging.debug('Slice assigned to the overlay %s' % overlay)
        else:
            logging.debug('The slice is not assigned to any overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay
    return overlay


# Return an overlay to which the device is partecipating,
# None the device is not part of any overlay
def get_overlay_containing_device(deviceid, tenantid):
    # Build the query
    query = {
        'tenantid': tenantid,
        'slices.deviceid': deviceid
    }
    # Find the device
    logging.debug('Checking if the device %s (tenant %s) '
                  'is partecipating to some overlay' % (deviceid, tenantid))
    overlay = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Find the overlays
        overlay = overlays.find_one(query)
        if overlay is not None:
            logging.debug(
                'Device is partecipating to the overlay %s' % overlay)
        else:
            logging.debug('The device is not partpartecipating to any overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the overlay
    return overlay


''' Functions operating on the tenants collection '''


# Return the tenant configuration
def get_tenant_config(tenantid):
    # Build the query
    query = {'tenantid': tenantid}
    config = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Find the tenant configuration
        logging.debug('Getting the configuration of the tenant %s' % tenantid)
        tenant = tenants.find_one(query)
        if tenant is not None:
            config = tenant['config']
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the tenant configuration if the tenant exists,
    # None if an error occurred during the connection to the db
    return config


# Return information about tenants
def get_tenant_configs(tenantids):
    # Build the query
    query = {'$in': list(tenantids)}
    configs = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Get the tenant configs
        logging.debug('Getting the tenants %s' % tenantids)
        tenants = tenants.find(query, {'conf': 1})
        # Return the configs
        configs = dict()
        for tenantid in tenants:
            configs[tenantid] = {
                'name': tenants[tenantid]['name'],
                'tenantid': tenants[tenantid]['tenantid'],
                'config': tenants[tenantid]['config'],
                'info': tenants[tenantid]['info']
            }
        logging.debug('Configs: %s' % configs)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the configurations if no errors,
    # return None if an error occurred during the connection to the db
    return configs


# Return the VXLAN port used by the tenant
# or None if an error occurredduring the connection to the db
def get_tenant_vxlan_port(tenantid):
    # Extract the tenant configuration from the database
    config = get_tenant_config(tenantid)
    if config is not None:
        # Extract the VXLAN port from the tenant configuration
        return config.get('vxlan_port', DEFAULT_VXLAN_PORT)
    else:
        return None


# Get tenant ID by token
def get_tenantid(token):
    # Build the query
    query = {'token': token}
    tenantid = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Get the tenant ID
        logging.debug('Getting the tenant ID')
        tenant = tenants.find_one(query, {'tenantid': 1})
        if tenant is not None:
            # Return the tenant ID
            tenantid = tenants.get('tenantid', None)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the tenant ID if success,
    # return None if an error occurred during the connection to the db
    return tenantid


# Configure a tenant
def configure_tenant(tenantid, tenant_info=None, vxlan_port=None):
    logging.debug('Configuring tenant %s (info %s, vxlan_port %s)'
                  % (tenantid, tenant_info, vxlan_port))
    # Build the query
    query = {'tenantid': tenantid}
    # Build the update statement
    update = {'$set': {
        'configured': True,
        'vtep_ip_index': -1,
        'reu_vtep_ip_addr': [],
        'assigned_vtep_ip_addr': 0,
        'vni_index': -1,
        'reu_vni': [],
        'assigned_vni': 0,
        'counters': {
            'tableid': {
                'reusable_tableids': [],
                'last_allocated_tableid': 0
            }
        }
    }
    }
    if vxlan_port is not None:
        update['$set']['config.vxlan_port'] = vxlan_port
    if tenant_info is not None:
        update['$set']['info'] = tenant_info
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Configure the tenant
        success = tenants.update_one(query, update).matched_count == 1
        if success:
            logging.debug('Tenant configured successfully')
        else:
            logging.error('Error configuring the tenant')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # return False if failure or
    # return None if an error occurred during the connection to the db
    return success


# Return True if the tenant is configured,
# False otherwise,
# None if an error occurred to the connection to the db
def is_tenant_configured(tenantid):
    logging.debug('Checking if tenant %s already '
                  'received the configuration' % tenantid)
    # Build the query
    query = {'tenantid': tenantid}
    is_config = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Configure the tenant
        tenant = tenants.find_one(query)
        if tenant is not None:
            logging.debug('The tenant is configured')
            is_config = tenant.get('configured', False)
        else:
            logging.error('Tenant not found')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the tenant is configured,
    # False otherwise,
    # None if an error occurred to the connection to the db
    return is_config


# Return True if a tenant exists,
# False otherwise
def tenant_exists(tenantid):
    # Build the query
    query = {'tenantid': tenantid}
    tenant_exists = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the tenants collection
        tenants = db.tenants
        # Count the tenants with the given tenant ID
        logging.debug('Searching the tenant %s' % tenantid)
        if tenants.count_documents(query, limit=1):
            logging.debug('The tenant exists')
            tenant_exists = True
        else:
            logging.debug('The tenant does not exist')
            tenant_exists = False
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if the tenant exists,
    # False if the tenant does not exist
    # or None if an error occurred during the connection to the db
    return tenant_exists


# Allocate and return a new table ID for a overlay
def get_new_tableid(tenantid):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the tenants collection
    tenants = db.tenants
    # Get a new table ID
    tableid = None
    logging.debug('Getting new table ID for the tenant %s' % tenantid)
    try:
        # Build the query
        query = {'tenantid': tenantid}
        # Check if a reusable table ID is available
        tenant = tenants.find_one(query)
        if tenant is None:
            logging.debug('The tenant does not exist')
        else:
            reusable_tableids = tenant['counters']['tableid']['reusable_tableids']
            if len(reusable_tableids) > 0:
                # Get a table ID
                tableid = reusable_tableids.pop()
                # Remove the table ID from the reusable_tableids list
                update = {
                    '$set': {'counters.tableid.reusable_tableids': reusable_tableids}}
                if tenants.update_one(query, update).modified_count != 1:
                    logging.error(
                        'Error while updating reusable table IDs list')
                    tableid = None
            else:
                while True:
                    # No reusable ID, allocate a new table ID
                    tenant = tenants.find_one_and_update(
                        query, {'$inc': {'counters.tableid.last_allocated_tableid': 1}},
                        return_document=ReturnDocument.AFTER)
                    if tenant is not None:
                        tableid = tenant['counters']['tableid']['last_allocated_tableid']
                        if tableid not in RESERVED_TABLEIDS:
                            logging.debug('Found table ID: %s' % tableid)
                            break
                        logging.debug('Table ID %s is reserved. Getting new table ID' % tableid)
                    else:
                        logging.error('Error in get_new_tableid')
                        break
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the table ID
    return tableid


# Release a table ID and mark it as reusable
def release_tableid(tableid, tenantid):
    # Build the query
    query = {'tenantid': tenantid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the tenants collection
    tenants = db.tenants
    # Release the table ID
    logging.debug('Release table ID %s for tenant %s'
                  % (tableid, tenantid))
    success = None
    try:
        # Get the overlay
        tenant = tenants.find_one(query)
        if tenant is None:
            logging.debug('The tenant does not exist')
        else:
            reusable_tableids = tenant['counters']['tableid']['reusable_tableids']
            # Add the table ID to the reusable table IDs list
            reusable_tableids.append(tableid)
            update = {'$set': {'counters.tableid.reusable_tableids': reusable_tableids}}
            if tenants.update_one(query, update).modified_count != 1:
                logging.error('Error while updating reusable table IDs list')
                success = False
            else:
                logging.debug('Table ID added to reusable_tableids list')
                success = True
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Return the table ID assigned to the VPN
# If the VPN has no assigned table IDs, return None
def get_tableid(overlayid, tenantid):
    # Build the query
    query = {'tenantid': tenantid, '_id': ObjectId(overlayid)}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Release the table ID
    logging.debug('Get table ID for the overlay %s (%s)'
                  % (overlayid, tenantid))
    tableid = None
    try:
        # Get the overlay
        overlay = overlays.find_one(query)
        # Get the table ID assigned to the overlay
        tableid = overlay.get('tableid')
        if tableid is None:
            logging.error('No table ID assigned to the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the table ID or None if error
    return tableid


# Assign a table ID to an overlay
def assign_tableid_to_overlay(overlayid, tenantid, tableid):
    # Build the query
    query = {'tenantid': tenantid, '_id': overlayid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Assign the table ID to the overlay
    success = True
    try:
        logging.debug('Trying to assign the table ID %s to the overlay %s'
                      % (tableid, overlayid))
        # Build the update
        update = {'$set': {'tableid': tableid}}
        # Assign the table ID
        success = overlays.update_one(query, update).modified_count == 1
        if success is False:
            logging.error('Cannot assign table ID')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Remove a table ID from an overlay
def remove_tableid_from_overlay(overlayid, tenantid, tableid):
    # Build the query
    query = {'tenantid': tenantid, '_id': overlayid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Set the table ID to null for the overlay
    success = True
    try:
        logging.debug('Trying to remove the table ID from the overlay %s'
                      % overlayid)
        # Build the update
        update = {'$unset': {'tableid': 1}}
        # Remove the table ID
        success = overlays.update_one(query, update).modified_count == 1
        if success is False:
            logging.error('Cannot remove table ID')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return True if success,
    # False if failure,
    # None if an error occurred during the connection to the db
    return success


# Device authentication
def authenticate_device(token):
    tenantid = get_tenantid(token)
    # return tenantid is not None, tenantid      # TODO for the future...
    return True, '1'


""" Topology """


# Return the topology
def get_topology():
    raise NotImplementedError
