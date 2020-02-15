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
        'features': features,
        'interfaces': interfaces,
        'mgmtip': mgmtip,
        'tenantid': tenantid,
        'tunnel_mode': None,
        'tunnel_info': None,
        'nat_type': None,
        'status': utils.DeviceStatus.CONNECTED,
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
        success = devices.delete_one(device).acknowledged
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
    query = {'deviceid': deviceid}
    # Build the update
    update = {
        '$set': {'mgmtip': mgmtip,
                 'tunnel_mode': tunnel_mode,
                 'nat_type': nat_type}
    }
    for interface in interfaces.values():
        interface_name = interface['name']
        ext_ipv4_addrs = interface['ext_ipv4_addrs']
        ext_ipv6_addrs = interface['ext_ipv6_addrs']
        update['$set']['interfaces.' + interface_name +
                       '.ext_ipv4_addrs'] = ext_ipv4_addrs
        update['$set']['interfaces.' + interface_name +
                       '.ext_ipv6_addrs'] = ext_ipv6_addrs
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the devices collection
        devices = db.devices
        # Add the device to the collection
        logging.debug('Updating device on DB: %s' % update)
        success = devices.update_one(query, update).acknowledged
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


# Return True if a device exists and is in running state,
# False otherwise
def is_device_running(deviceid):
    # Get the device
    logging.debug('Searching the device %s' % deviceid)
    device = get_device(deviceid)
    res = None
    if device is not None:
        # Get the status of the device
        status = device['status']
        if status == utils.DeviceStatus.RUNNING:
            logging.debug('The device is running')
            res = True
        else:
            logging.debug('The device is not running')
            res = False
    # Return True if the device is running,
    # False if it is not running or
    # None if an error occurred during the connection to the db
    return res


# Return True if a device exists and is connected,
# False otherwise
def is_device_connected(deviceid):
    # Get the device
    logging.debug('Searching the device %s' % deviceid)
    device = get_device(deviceid)
    res = None
    if device is not None:
        # Get the status of the device
        status = device['status']
        if status in [utils.DeviceStatus.CONNECTED, utils.DeviceStatus.RUNNING]:
            logging.debug('The device is running')
            res = True
        else:
            logging.debug('The device is not running')
            res = False
    # Return True if the device is connected,
    # False if it is not connected or
    # None if an error occurred during the connection to the db
    return res


# Return True if an interface exists on a given device,
# False otherwise
def interface_exists_on_device(deviceid, interface_name):
    # Get the device
    logging.debug('Getting the interface %s on the device %s' %
                  (interface_name, deviceid))
    device = get_device(deviceid)
    res = None
    if device is not None:
        # Check if the interface exists
        if interface_name in device['interfaces']:
            res = True
        else:
            res = False
    # Return True if the interface exists,
    # False if it not exists or
    # None if an error occurred during the connection to the db
    return res


# Return an interface of a device
def get_interface(deviceid, interface_name):
    # Get the device
    logging.debug('Getting the interface %s of device %s' %
                  (interface_name, deviceid))
    device = get_device(deviceid)
    interface = None
    if device is not None:
        # Return the interface
        interface = device['interfaces'].get(interface_name)
    # Return the interface if it exists,
    # None if the interface does not exist or
    # None if an error occurred during the connection to the db
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
        for interface in interfaces.values():
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
        for interface in interfaces.values():
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
        for interface in interfaces.values():
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
        update = {'$set': {
            'name': name,
            'description': description,
            'status': utils.DeviceStatus.RUNNING
        }}
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
            # Add update
            update['$set']['interfaces.' +
                            interface_name + '.ipv4_addrs'] = ipv4_addrs
            update['$set']['interfaces.' +
                            interface_name + '.ipv6_addrs'] = ipv6_addrs
            update['$set']['interfaces.' + interface_name +
                            '.ipv4_subnets'] = ipv4_subnets
            update['$set']['interfaces.' + interface_name +
                            '.ipv6_subnets'] = ipv6_subnets
            update['$set']['interfaces.' + interface_name + '.type'] = type
        updates.append(update)
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
            success = devices.update_one(query, update).acknowledged
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


''' Functions operating on the overlays collection '''


# Create overlay
def create_overlay(name, type, slices, tenantid, tunnel_mode):
    # Build the document
    overlay = {
        'name': name,
        'type': type,
        'slices': slices,
        'tenantid': tenantid,
        'tunnel_mode': tunnel_mode
    }
    success = None
    try:
        # Get a reference to the MongoDB client
        client = get_mongodb_session()
        # Get the database
        db = client.EveryWan
        # Get the overlays collection
        overlays = db.overlays
        # Add the overlay to the collection
        logging.debug('Creating the overlay: %s' % overlay)
        success = overlays.insert_one(overlay).acknowledged
        if success:
            logging.debug('Overlay created successfully')
        else:
            logging.error('Cannot create the overlay')
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return
    return success


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
        success = overlays.delete_one(overlay).acknowledged
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
    overlay = {'tenantid': tenantid}
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
        success = overlays.delete_many(overlay).acknowledged
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
        ).acknowledged
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
        ).acknowledged
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
        ).acknowledged
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
        ).acknowledged
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
    return slices


# Get the counter of a tunnel mode on a device and
# increase the counter
def get_and_inc_tunnel_mode_counter(tunnel_mode, deviceid):
    # Build the query
    query = {'deviceid': deviceid}
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
        # Increase the counter for the tunnel mode
        device = devices.find_one_and_update(
            query, {'$inc': {'stats.counters.tunnel_mode' + tunnel_mode: 1}}, upsert=True)
        # Return the counter if exists, 0 otherwise
        counter = device['stats']['counters']['tunnel_mode'].get(
            tunnel_mode, 0)
        logging.debug('Counter before the increment: %s' % counter)
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


# Decrease the counter of a tunnel mode on a device and
# return the counter after the decrement
def dec_and_get_tunnel_mode_counter(tunnel_mode, deviceid):
    # Build the query
    query = {'deviceid': deviceid}
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
            query, {'$inc': {'stats.counters.tunnel_mode' + tunnel_mode: -1}},
            return_document=ReturnDocument.AFTER)
        # Return the counter
        counter = device['stats']['counters']['tunnel_mode'][tunnel_mode]
        logging.debug('Counter after the decrement: %s' % counter)
        # If counter is 0, remove the tunnel mode from the device stats
        if counter == 0:
            devices.update_one(
                query, {'$unset': {'stats.counters.tunnel_mode' + tunnel_mode: 1}})
    except pymongo.errors.ServerSelectionTimeoutError:
        logging.error('Cannot establish a connection to the db')
    # Return the counter if success,
    # None if an error occurred during the connection to the db
    return counter


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
            config = tenant['conf']
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
                'config': tenants[tenantid]['conf'],
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


'''
# Allocate and return a new table ID for a overlay
def get_new_tableid(tenantid):
    # Build the query
    query = {'tenantid': tenantid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the tenants collection
    tenants = db.tenants
    # Get a new table ID
    logging.debug('Getting new table ID for the tenant %s' % tenantid)
    tableid = tenants.find_one_and_update(
        query, {'$inc': {'counters.last_tableid': 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER)['counters']['last_tableid']
    # Return the table ID
    return tableid


# Return the table ID assigned to the VPN
# If the VPN has no assigned table IDs, return -1
def get_tableid(overlay_name, tenantid):
    if tenantid not in self.vpn_to_tableid:
        return -1
    return self.vpn_to_tableid[tenantid].get(vpn_name, -1)


# Release a table ID and mark it as reusable
def release_tableid(vpn_name, tenantid):
    # Check if the VPN has an associated table ID
    if self.vpn_to_tableid[tenantid].get(vpn_name):
        # The VPN has an associated table ID
        tableid = self.vpn_to_tableid[tenantid][vpn_name]
        # Unassign the table ID
        del self.vpn_to_tableid[tenantid][vpn_name]
        # Mark the table ID as reusable
        self.reusable_tableids[tenantid].add(tableid)
        # If the tenant has no VPNs,
        # destory data structures
        if len(self.vpn_to_tableid[tenantid]) == 0:
            del self.vpn_to_tableid[tenantid]
            del self.reusable_tableids[tenantid]
            del self.last_allocated_tableid[tenantid]
        # Return the table ID
        return tableid
    else:
        # The VPN has not an associated table ID
        return -1
'''


# Device authentication
def authenticate_device(token):
    return get_tenantid(token) is not None


""" Topology """


# Return the topology
def get_topology():
    raise NotImplementedError
