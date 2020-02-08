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


# Get a reference to the MongoDB client
def get_mongodb_session(host=DEFAULT_MONGODB_HOST,
                        port=DEFAULT_MONGODB_PORT,
                        username=DEFAULT_MONGODB_USERNAME,
                        password=DEFAULT_MONGODB_PASSWORD):
    # Percent-escape username
    username = urllib.parse.quote_plus(username)
    # Percent-escape password
    password = urllib.parse.quote_plus(password)
    # Return the MogoDB client
    return pymongo.MongoClient(host=host,
                               port=port,
                               username=username,
                               password=password)


''' Device management '''


# Register a device
def register_device(deviceid, features, interfaces, mgmtip,
                    tenantid):
    # Build the query
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
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Add the device to the collection
    logging.debug('Registering device on DB: %s' % device)
    devices.insert_one(device)
    logging.debug('Device successfully registered')


# Unregister a device
def unregister_device(deviceid):
    # Build the query
    device = {'deviceid': deviceid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Delete the device from the collection
    logging.debug('Unregistering device: %s' % deviceid)
    devices.delete_one(device)
    logging.debug('Device successfully unregistered')


# Unregister all devices
def unregister_devices_by_tenantid(tenantid):
    # Build the query
    device = {'tenantid': tenantid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Delete all the devices in the collection
    logging.debug('Unregistering all the devices of the tenant %s' % tenantid)
    devices.delete_many(device)
    logging.debug('Devices successfully unregistered')


# Unregister all devices
def unregister_all_devices(deviceid):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Delete all the devices in the collection
    logging.debug('Unregistering all devices')
    devices.delete_many({})
    logging.debug('Devices successfully unregistered')


# Get devices
def get_devices(deviceids=None, tenantid=None, return_dict=False):
    # Build the query
    query = dict()
    if tenantid is not None:
        query['tenantid'] = tenantid
    if deviceids is not None:
        query['deviceid'] = {'$in': list(deviceids)}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Find the device by device ID
    logging.debug('Retrieving devices by tenant ID %s' % tenantid)
    devices = devices.find(query)
    if return_dict:
        _devices = dict()
        for device in devices:
            _devices[device['deviceid']] = device
        devices = _devices
    else:
        devices = list(devices)
    logging.debug('Devices found: %s' % devices)
    return devices


# Return True if a device exists,
# False otherwise
def device_exists(deviceid):
    # Build the query
    device = {'deviceid': deviceid}
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
        return True
    else:
        logging.debug('The device does not exist')
        return False


# Return True if a device exists and is in running state,
# False otherwise
def is_device_running(deviceid):
    # Build the query
    device = {'deviceid': deviceid, 'status': utils.DeviceStatus.RUNNING}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Count the devices with the given device ID
    logging.debug('Searching the device %s' % deviceid)
    if devices.count_documents(device, limit=1):
        logging.debug('The device is running')
        return True
    else:
        logging.debug('The device is not running')
        return False


# Return True if a device exists and is connected,
# False otherwise
def is_device_connected(deviceid):
    # Build the query
    device = {
        'deviceid': deviceid,
        "$or": [
            {'status': utils.DeviceStatus.CONNECTED},
            {'status': utils.DeviceStatus.RUNNING}
        ]
    }
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Count the devices with the given device ID
    logging.debug('Searching the device %s' % deviceid)
    if devices.count_documents(device, limit=1):
        logging.debug('The device is connected')
        return True
    else:
        logging.debug('The device is not connected')
        return False


# Return True if an interface exists on a given device,
# False otherwise
def interface_exists_on_device(deviceid, interface_name):
    # Build the query
    device = {
        'deviceid': deviceid,
        'interfaces': {"$in": [interface_name]}
    }
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Count the interfaces with the given name
    logging.debug('Searching the interface %s on device %s' %
                  (interface_name, deviceid))
    if devices.count_documents(device, limit=1):
        logging.debug('The interface exists')
        return True
    else:
        logging.debug('The interface does not exist')
        return False


# Return all the interfaces of a device
def get_interfaces(deviceid):
    # Build the query
    device = {'deviceid': deviceid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Count the interfaces with the given name
    logging.debug('Getting the interfaces of device %s' % deviceid)
    interfaces = devices.find_one(device, {'interfaces': 1})['interfaces']
    logging.debug('Interfaces found: %s' % interfaces)
    return interfaces


# Get device's IPv4 addresses
def get_ipv4_addresses(deviceid, interface_name):
    # Find the IPv4 addresses by device ID and interface
    logging.debug('Retrieving IPv4 addresses for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    addrs = interfaces[interface_name]['ipv4_addrs']
    logging.debug('IPv4 addresses: %s' % addrs)
    return addrs


# Get device's IPv6 addresses
def get_ipv6_addresses(deviceid, interface_name):
    # Find the IPv6 addresses by device ID and interface
    logging.debug('Retrieving IPv6 addresses for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    addrs = interfaces[interface_name]['ipv6_addrs']
    logging.debug('IPv6 addresses: %s' % addrs)
    return addrs


# Get device's IP addresses
def get_ip_addresses(deviceid, interface_name):
    # Find the IPv4 addresses by device ID and interface
    logging.debug('Retrieving IPv4 addresses for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    addrs = interfaces[interface_name]['ipv4_addrs'] + \
        interfaces[interface_name]['ipv6_addrs']
    logging.debug('IPv4 addresses: %s' % addrs)
    return addrs


# Get device's external IPv4 addresses
def get_ext_ipv4_addrs(deviceid, interface_name):
    # Find the IPv4 addresses by device ID and interface
    logging.debug('Retrieving IPv4 addresses for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    addrs = interfaces[interface_name]['ext_ipv4_addrs']
    logging.debug('IPv4 addresses: %s' % addrs)
    return addrs


# Get device's external IPv6 addresses
def get_ext_ipv6_addrs(deviceid, interface_name):
    # Find the IPv6 addresses by device ID and interface
    logging.debug('Retrieving IPv6 addresses for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    addrs = interfaces[interface_name]['ext_ipv6_addrs']
    logging.debug('IPv6 addresses: %s' % addrs)
    return addrs


# Get device's external IP addresses
def get_ext_ip_addrs(deviceid, interface_name):
    # Find the IPv4 addresses by device ID and interface
    logging.debug('Retrieving IPv4 addresses for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    addrs = interfaces[interface_name]['ext_ipv4_addrs'] + \
        interfaces[interface_name]['ext_ipv6_addrs']
    logging.debug('IP addresses: %s' % addrs)
    return addrs


# Get device's IPv4 subnets
def get_ipv4_subnets(deviceid, interface_name):
    # Find the IPv4 subnets by device ID and interface
    logging.debug('Retrieving IPv4 subnets for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    subnets = interfaces[interface_name]['ipv4_subnets']
    logging.debug('IPv4 subnets: %s' % subnets)
    return subnets


# Get device's IPv6 subnets
def get_ipv6_subnets(deviceid, interface_name):
    # Find the IPv6 subnets by device ID and interface
    logging.debug('Retrieving IPv6 subnets for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    subnets = interfaces[interface_name]['ipv6_subnets']
    logging.debug('IPv6 subnets: %s' % subnets)
    return subnets


# Get device's IP subnets
def get_ip_subnets(deviceid, interface_name):
    # Find the subnets by device ID and interface
    logging.debug('Retrieving subnets for device %s' % deviceid)
    interfaces = get_interfaces(deviceid)
    subnets = interfaces[interface_name]['ipv4_subnets'] + \
        interfaces[interface_name]['ipv6_subnets']
    logging.debug('Subnets: %s' % subnets)
    return subnets


# Get router's IPv4 loopback IP
def get_loopbackip_ipv4(deviceid):
    return get_ipv4_addresses(deviceid, 'lo')[0]


# Get router's IPv4 loopback net
def get_loopbacknet_ipv4(deviceid):
    loopbackip = get_loopbackip_ipv4(deviceid)
    return IPv4Interface(loopbackip).network.__str__()


# Get router's IPv6 loopback IP
def get_loopbackip_ipv6(deviceid):
    return get_ipv6_addresses(deviceid, 'lo')[0]


# Get router's IPv6 loopback net
def get_loopbacknet_ipv6(deviceid):
    loopbackip = get_loopbackip_ipv6(deviceid)
    return IPv6Interface(loopbackip).network.__str__()


# Get router's management IP address
def get_router_mgmtip(deviceid):
    # Build the query
    device = {
        'deviceid': deviceid
    }
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Find the IPv6 addresses by device ID and interface
    logging.debug('Retrieving management IP for device %s' % deviceid)
    mgmtip = devices.find_one(device, {'mgmtip': 1})['mgmtip']
    logging.debug('Management IP: %s' % mgmtip)
    return mgmtip


# Get WAN interfaces of a device
def get_wan_interfaces(deviceid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid)
    # Filter WAN interfaces
    wan_interfaces = list()
    for interface in interfaces.values():
        if interface['type'] == utils.InterfaceType.WAN:
            wan_interfaces.append(interface['name'])
    # Return the WAN interfaces
    return wan_interfaces


# Get LAN interfaces of a device
def get_lan_interfaces(deviceid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid)
    # Filter LAN interfaces
    lan_interfaces = list()
    for interface in interfaces.values():
        if interface['type'] == utils.InterfaceType.LAN:
            lan_interfaces.append(interface['name'])
    # Return the LAN interfaces
    return lan_interfaces


# Get non-loopback interfaces of a device
def get_non_loopback_interfaces(deviceid):
    # Retrieve all the interfaces
    interfaces = get_interfaces(deviceid)
    # Filter non-loopback interfaces
    non_lo_interfaces = list()
    for interface in interfaces.values():
        if interface['name'] != 'lo':
            non_lo_interfaces.append(interface['name'])
    # Return the non-loopback interfaces
    return non_lo_interfaces


# Configure the devices
def configure_devices(devices):
    # Build the update statements
    queries = []
    updates = []
    for device in devices:
        deviceid = device['deviceid']
        interfaces = device['interfaces']
        for interface in interfaces.values():
            interface_name = interface['name']
            ipv4_addrs = interface['ipv4_addrs']
            ipv6_addrs = interface['ipv6_addrs']
            ipv4_subnets = interface['ipv4_subnets']
            ipv6_subnets = interface['ipv6_subnets']
            type = interface['type']
            updates.append({
                '$set': {
                    'interfaces.' + interface_name + '.ipv4_addrs': ipv4_addrs,
                    'interfaces.' + interface_name + '.ipv6_addrs': ipv6_addrs,
                    'interfaces.' + interface_name + '.ipv4_subnets': ipv4_subnets,
                    'interfaces.' + interface_name + '.ipv6_subnets': ipv6_subnets,
                    'interfaces.' + interface_name + '.type': type,
                    'status': utils.DeviceStatus.RUNNING
                }
            })
            queries.append({'deviceid': deviceid})
    #query = {'$or': query}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Count the interfaces with the given name
    logging.debug('Updating interfaces')
    for query, update in zip(queries, updates):
        devices.update_one(query, update)
    logging.debug('Interfaces updated')


''' Overlay management '''


# Create overlay
def create_overlay(name, type, _slices, tenantid, tunnel_mode):
    # Build the query
    overlay = {
        'name': name,
        'type': type,
        'slices': _slices,
        'tenantid': tenantid,
        'tunnel_mode': tunnel_mode
    }
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Add the overlay to the collection
    logging.debug('Creating the overlay: %s' % overlay)
    overlays.insert_one(overlay)
    logging.debug('Overlay created successfully')


# Remove overlay by ID
def remove_overlay(overlayid):
    # Build the query
    overlay = {'_id': ObjectId(overlayid)}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Remove the overlay from the collection
    logging.debug('Removing the overlay: %s' % overlayid)
    overlays.delete_one(overlay)
    logging.debug('Overlay removed successfully')


# Remove all the overlays
def remove_all_overlays():
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Delete all the overlays in the collection
    logging.debug('Removing all overlays')
    overlays.delete_many({})
    logging.debug('Overlays removed successfully')


# Remove all the overlays of a tenant
def remove_overlays_by_tenantid(tenantid):
    # Build the query
    overlay = {'tenantid': tenantid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Delete all the overlays in the collection
    logging.debug('Removing all overlays of tenant: %s' % tenantid)
    overlays.delete_many(overlay)
    logging.debug('Overlays removed successfully')


# Get overlays
def get_overlays(overlayids=None, tenantid=None):
    # Build the query
    query = dict()
    if tenantid is not None:
        query['tenantid'] = tenantid
    if overlayids is not None:
        query['_id'] = {'$in': overlayids}
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
    return overlays


# Get a overlay by its name
def get_overlay_by_name(name, tenantid):
    # Build the query
    overlay = {'name': name, 'tenantid': tenantid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Find the overlay
    logging.debug('Searching the overlay %s, tenant ID %s' % (name, tenantid))
    overlay = overlays.find_one(overlay)
    logging.debug('Overlay found: %s' % overlay)
    return overlay


# Return True if an overlay exists
# with the provided name exists, False otherwise
def overlay_exists(name, tenantid):
    # Build the query
    overlay = {'name': name, 'tenantid': tenantid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Count the overlays with the given name and tenant ID
    logging.debug('Searching the overlay %s, tenant ID %s' % (name, tenantid))
    if overlays.count_documents(overlay, limit=1):
        logging.debug('The overlay exists')
        return True
    else:
        logging.debug('The overlay does not exist')
        return False


# Add a slice to an overlay
def add_slice_to_overlay(overlayid, _slice):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Add the slice to the overlay
    logging.debug('Adding the slice to the overlay %s' % overlayid)
    overlays.update_one(
        {'_id': ObjectId(overlayid)},
        {'$push': {'slices': _slice}}
    )
    logging.debug('Slice added to the overlay')


# Add many slices to an overlay
def add_many_slices_to_overlay(overlayid, slices):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Add the slices to the overlay
    logging.debug('Adding the slice to the overlay %s' % overlayid)
    overlays.update_one(
        {'_id': ObjectId(overlayid)},
        {'$pushAll': {'slices': slices}}
    )
    logging.debug('Slices added to the overlay')


# Remove a slice from an overlay
def remove_slice_from_overlay(overlayid, _slice):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Remove the slice from the overlay
    logging.debug('Removing the slice from the overlay %s' % overlayid)
    overlays.update_one(
        {'_id': ObjectId(overlayid)},
        {'$pull': {'slices': _slice}}
    )
    logging.debug('Slice removed from the overlay')


# Remove many slices from an overlay
def remove_many_slice_from_overlay(overlayid, slices):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Remove the slices to the overlay
    logging.debug('Removing the slices from the overlay %s' % overlayid)
    overlays.update_one(
        {'_id': ObjectId(overlayid)},
        {'$pullAll': {'slices': slices}}
    )
    logging.debug('Slices removed from the overlay')


# Retrieve the slices contained in a given overlay
def get_slices_in_overlay(overlayid):
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the overlays collection
    overlays = db.overlays
    # Find the slice in the overlay
    logging.debug('Getting the slices in the overlay %s' % overlayid)
    slices = overlays.find_one(
        {'_id': ObjectId(overlayid)},
        {'slices': 1}
    )['slices']
    logging.debug('Slices found: %s' % slices)
    return slices


# Increase the ref count for a tunnel mode and device
# and return the old ref count
def inc_tunnel_mode_refcount(tunnel_mode, deviceid):
    # Build the query
    query = {'tunnel_mode': tunnel_mode}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the tunnel_modes collection
    tunnel_modes = db.tunnel_modes
    # Find the tunnel mode
    logging.debug('Getting the tunnel mode %s' % tunnel_mode)
    # Increase the ref count for the device
    old_refcount = tunnel_modes.find_one_and_update(
        query, {'$inc': {'refcount.' + deviceid: 1}})
    # Return the old ref count
    logging.debug('Old ref count: %s' % old_refcount)
    return old_refcount


# Decrease the ref count for a tunnel mode and device
# and return the new ref count
def dec_tunnel_mode_refcount(tunnel_mode, deviceid):
    # Build the query
    query = {'tunnel_mode': tunnel_mode}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the tunnel_modes collection
    tunnel_modes = db.tunnel_modes
    # Find the tunnel mode
    logging.debug('Getting the tunnel mode %s' % tunnel_mode)
    # Increase the ref count for the device
    new_refcount = tunnel_modes.find_one_and_update(
        query, {'$dec': {'refcount.' + deviceid: 1}},
        return_document=ReturnDocument.AFTER)
    # Return the old ref count
    logging.debug('New ref count: %s' % new_refcount)
    return new_refcount


# Return the tenant configuration
def get_tenant_config(tenantid):
    # Build the query
    query = {'tenantid': tenantid}
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the tenants collection
    tenants = db.tenants
    # Find the tenant configuration
    logging.debug('Getting the configuration of the tenant %s' % tenantid)
    return tenants.find_one(query)['configuration']


# Return the VXLAN port used by the tenant
def get_tenant_vxlan_port(tenantid):
    # Extract the tenant configuration from the database
    config = get_tenant_config(tenantid)
    # Extract the VXLAN port from the tenant configuration
    return config.get('vxlan_port', DEFAULT_VXLAN_PORT)


# Update tunnel mode
def update_tunnel_mode(deviceid, mgmtip, interfaces, tunnel_mode, nat_type):
    print('\n\n\n\nTUNNEL MODE', tunnel_mode)
    # Build the query
    query = {'deviceid': deviceid}
    # Build the update
    updates = [{
        '$set': {'mgmtip': mgmtip,
                 'tunnel_mode': tunnel_mode,
                 'tunnel_info': None,
                 'nat_type': nat_type}
    }]
    for interface in interfaces.values():
        interface_name = interface['name']
        ext_ipv4_addrs = interface['ext_ipv4_addrs']
        ext_ipv6_addrs = interface['ext_ipv6_addrs']
        updates.append({
            '$set': {
                'interfaces.' + interface_name + '.ext_ipv4_addrs': ext_ipv4_addrs,
                'interfaces.' + interface_name + '.ext_ipv6_addrs': ext_ipv6_addrs,
                'status': utils.DeviceStatus.RUNNING
            }
        })
    # Get a reference to the MongoDB client
    client = get_mongodb_session()
    # Get the database
    db = client.EveryWan
    # Get the devices collection
    devices = db.devices
    # Add the device to the collection
    logging.debug('Updating device on DB: %s' % updates)
    for update in updates:
        devices.update_one(query, update)
    logging.debug('Device successfully updated')


""" Topology management """

# Return the topology


def get_topology():
    raise NotImplementedError
