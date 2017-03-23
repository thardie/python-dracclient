#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import collections
import logging

from dracclient import constants
from dracclient import exceptions
from dracclient.resources import uris
from dracclient import utils
from dracclient import wsman


LOG = logging.getLogger(__name__)

RAID_LEVELS = {
    'non-raid': '1',
    '0': '2',
    '1': '4',
    '5': '64',
    '6': '128',
    '1+0': '2048',
    '5+0': '8192',
    '6+0': '16384',
}

REVERSE_RAID_LEVELS = dict((v, k) for (k, v) in RAID_LEVELS.items())

DISK_RAID_STATUS = {
    '0': 'unknown',
    '1': 'ready',
    '2': 'online',
    '3': 'foreign',
    '4': 'offline',
    '5': 'blocked',
    '6': 'failed',
    '7': 'degraded',
    '8': 'non-RAID',
    '9': 'missing'
}

VIRTUAL_DISK_PENDING_OPERATIONS = {
    '0': None,
    '1': 'fast_init',
    '2': 'pending_delete',
    '3': 'pending_create'
}

PHYSICAL_DISK_MEDIA_TYPE = {
    '0': 'hdd',
    '1': 'ssd'
}

PHYSICAL_DISK_BUS_PROTOCOL = {
    '0': 'unknown',
    '1': 'scsi',
    '2': 'pata',
    '3': 'fibre',
    '4': 'usb',
    '5': 'sata',
    '6': 'sas'
}

PhysicalDiskTuple = collections.namedtuple(
    'PhysicalDisk',
    ['id', 'description', 'controller', 'manufacturer', 'model', 'media_type',
     'interface_type', 'size_mb', 'free_size_mb', 'serial_number',
     'firmware_version', 'status', 'raid_status'])


class PhysicalDisk(PhysicalDiskTuple):

    def __new__(cls, **kwargs):
        if 'state' in kwargs:
            LOG.warning('PhysicalDisk.state is deprecated. '
                        'Use PhysicalDisk.status instead.')
            kwargs['status'] = kwargs['state']
            del kwargs['state']

        if 'raid_state' in kwargs:
            LOG.warning('PhysicalDisk.raid_state is deprecated. '
                        'Use PhysicalDisk.raid_status instead.')
            kwargs['raid_status'] = kwargs['raid_state']
            del kwargs['raid_state']

        return super(PhysicalDisk, cls).__new__(cls, **kwargs)

    @property
    def state(self):
        LOG.warning('PhysicalDisk.state is deprecated. '
                    'Use PhysicalDisk.status instead.')
        return self.status

    @property
    def raid_state(self):
        LOG.warning('PhysicalDisk.raid_state is deprecated. '
                    'Use PhysicalDisk.raid_status instead.')
        return self.raid_status

RAIDController = collections.namedtuple(
    'RAIDController', ['id', 'description', 'manufacturer', 'model',
                       'primary_status', 'firmware_version'])

VirtualDiskTuple = collections.namedtuple(
    'VirtualDisk',
    ['id', 'name', 'description', 'controller', 'raid_level', 'size_mb',
     'status', 'raid_status', 'span_depth', 'span_length',
     'pending_operations', 'physical_disks'])


class VirtualDisk(VirtualDiskTuple):

    def __new__(cls, **kwargs):
        if 'state' in kwargs:
            LOG.warning('VirtualDisk.state is deprecated. '
                        'Use VirtualDisk.status instead.')
            kwargs['status'] = kwargs['state']
            del kwargs['state']

        if 'raid_state' in kwargs:
            LOG.warning('VirtualDisk.raid_state is deprecated. '
                        'Use VirtualDisk.raid_status instead.')
            kwargs['raid_status'] = kwargs['raid_state']
            del kwargs['raid_state']

        return super(VirtualDisk, cls).__new__(cls, **kwargs)

    @property
    def state(self):
        LOG.warning('VirtualDisk.state is deprecated. '
                    'Use VirtualDisk.status instead.')
        return self.status

    @property
    def raid_state(self):
        LOG.warning('VirtualDisk.raid_state is deprecated. '
                    'Use VirtualDisk.raid_status instead.')
        return self.raid_status


class RAIDManagement(object):

    def __init__(self, client):
        """Creates RAIDManagement object

        :param client: an instance of WSManClient
        """
        self.client = client

    def list_raid_settings(self, by_name=True):
        """Returns the list of RAID controllers

        :returns: a list of RAIDController objects
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        """

        result = {}
        namespaces = [(uris.DCIM_RAIDEnumeration, RAIDEnumerableAttribute),
                      (uris.DCIM_RAIDString, RAIDStringAttribute),
                      (uris.DCIM_RAIDInteger, RAIDIntegerAttribute)]
        for (namespace, attr_cls) in namespaces:
            attribs = self._get_config(namespace, attr_cls, by_name)
            if not set(result).isdisjoint(set(attribs)):
                raise exceptions.DRACOperationFailed(
                    drac_messages=('Colliding attributes %r' % (
                        set(result) & set(attribs))))
            result.update(attribs)
        return result

    def _get_config(self, resource, attr_cls, by_name):
        result = {}

        doc = self.client.enumerate(resource)
        items = doc.find('.//{%s}Items' % wsman.NS_WSMAN)

        for item in items:
            attribute = attr_cls.parse(item)
            if by_name:
                result[attribute.name] = attribute
            else:
                result[attribute.instance_id] = attribute

        return result

    def set_raid_settings(self, target, new_settings):
        """Sets the raid configuration

        To be more precise, it sets the pending_value parameter for each of the
        attributes passed in. For the values to be applied, a config job must
        be created and the node must be rebooted.

        :param new_settings: a dictionary containing the proposed values, with
                             each key being the name of attribute and the
                             value being the proposed value.
        :returns: a dictionary containing the commit_needed key with a boolean
                  value indicating whether a config job must be created for the
                  values to be applied.
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        :raises: DRACUnexpectedReturnValue on return value mismatch
        :raises: InvalidParameterValue on invalid raid attribute
        """

        current_settings = self.list_raid_settings(by_name=True)
        # raid settings are returned as dict indexed by InstanceID.
        # However DCIM_RAIDService requires attribute name, not instance id
        # so recreate this as a dict indexed by attribute name
        # TODO(anish) : Enable this code if/when by_name gets deprecated
        # raid_settings = self.list_raid_settings(by_name=False)
        # current_settings = dict((value.name, value)
        #                         for key, value in raid_settings.items())
        unknown_keys = set(new_settings) - set(current_settings)
        if unknown_keys:
            msg = ('Unknown raid attributes found: %(unknown_keys)r' %
                   {'unknown_keys': unknown_keys})
            raise exceptions.InvalidParameterValue(reason=msg)

        read_only_keys = []
        unchanged_attribs = []
        invalid_attribs_msgs = []
        attrib_names = []
        candidates = set(new_settings)

        for attr in candidates:
            if str(new_settings[attr]) == str(
                    current_settings[attr].current_value):
                unchanged_attribs.append(attr)
            elif current_settings[attr].read_only:
                read_only_keys.append(attr)
            else:
                validation_msg = current_settings[attr].validate(
                    new_settings[attr])
                if validation_msg is None:
                    attrib_names.append(attr)
                else:
                    invalid_attribs_msgs.append(validation_msg)

        if unchanged_attribs:
            LOG.warning('Ignoring unchanged raid attributes: %r',
                        unchanged_attribs)

        if invalid_attribs_msgs or read_only_keys:
            if read_only_keys:
                read_only_msg = ['Cannot set read-only raid attributes: %r.'
                                 % read_only_keys]
            else:
                read_only_msg = []

            drac_messages = '\n'.join(invalid_attribs_msgs + read_only_msg)
            raise exceptions.DRACOperationFailed(
                drac_messages=drac_messages)

        if not attrib_names:
            return {'commit_required': False}

        selectors = {'CreationClassName': 'DCIM_RAIDService',
                     'Name': 'DCIM:RAIDService',
                     'SystemCreationClassName': 'DCIM_ComputerSystem',
                     'SystemName': 'DCIM:ComputerSystem'}
        properties = {'Target': target,
                      'AttributeName': attrib_names,
                      'AttributeValue': [new_settings[attr] for attr
                                         in attrib_names]}
        doc = self.client.invoke(uris.DCIM_RAIDService, 'SetAttributes',
                                 selectors, properties)

        return {'commit_required': utils.is_reboot_required(
            doc, uris.DCIM_RAIDService)}


    def list_raid_controllers(self):
        """Returns the list of RAID controllers

        :returns: a list of RAIDController objects
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        """

        doc = self.client.enumerate(uris.DCIM_ControllerView)

        drac_raid_controllers = utils.find_xml(doc, 'DCIM_ControllerView',
                                               uris.DCIM_ControllerView,
                                               find_all=True)

        return [self._parse_drac_raid_controller(controller)
                for controller in drac_raid_controllers]


    def _parse_drac_raid_controller(self, drac_controller):
        return RAIDController(
            id=self._get_raid_controller_attr(drac_controller, 'FQDD'),
            description=self._get_raid_controller_attr(
                drac_controller, 'DeviceDescription'),
            manufacturer=self._get_raid_controller_attr(
                drac_controller, 'DeviceCardManufacturer'),
            model=self._get_raid_controller_attr(
                drac_controller, 'ProductName'),
            primary_status=constants.PRIMARY_STATUS[
                self._get_raid_controller_attr(drac_controller,
                                               'PrimaryStatus')],
            firmware_version=self._get_raid_controller_attr(
                drac_controller, 'ControllerFirmwareVersion'))

    def _get_raid_controller_attr(self, drac_controller, attr_name):
        return utils.get_wsman_resource_attr(
            drac_controller, uris.DCIM_ControllerView, attr_name,
            nullable=True)

    def list_virtual_disks(self):
        """Returns the list of virtual disks

        :returns: a list of VirtualDisk objects
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        """

        doc = self.client.enumerate(uris.DCIM_VirtualDiskView)

        drac_virtual_disks = utils.find_xml(doc, 'DCIM_VirtualDiskView',
                                            uris.DCIM_VirtualDiskView,
                                            find_all=True)

        return [self._parse_drac_virtual_disk(disk)
                for disk in drac_virtual_disks]

    def _parse_drac_virtual_disk(self, drac_disk):
        fqdd = self._get_virtual_disk_attr(drac_disk, 'FQDD')
        drac_raid_level = self._get_virtual_disk_attr(drac_disk, 'RAIDTypes')
        size_b = self._get_virtual_disk_attr(drac_disk, 'SizeInBytes')
        drac_status = self._get_virtual_disk_attr(drac_disk, 'PrimaryStatus')
        drac_raid_status = self._get_virtual_disk_attr(drac_disk, 'RAIDStatus')
        drac_pending_operations = self._get_virtual_disk_attr(
            drac_disk, 'PendingOperations')

        return VirtualDisk(
            id=fqdd,
            name=self._get_virtual_disk_attr(drac_disk, 'Name',
                                             nullable=True),
            description=self._get_virtual_disk_attr(drac_disk,
                                                    'DeviceDescription',
                                                    nullable=True),
            controller=fqdd.split(':')[-1],
            raid_level=REVERSE_RAID_LEVELS[drac_raid_level],
            size_mb=int(size_b) / 2 ** 20,
            status=constants.PRIMARY_STATUS[drac_status],
            raid_status=DISK_RAID_STATUS[drac_raid_status],
            span_depth=int(self._get_virtual_disk_attr(drac_disk,
                                                       'SpanDepth')),
            span_length=int(self._get_virtual_disk_attr(drac_disk,
                                                        'SpanLength')),
            pending_operations=(
                VIRTUAL_DISK_PENDING_OPERATIONS[drac_pending_operations]),
            physical_disks=self._get_virtual_disk_attrs(drac_disk,
                                                        'PhysicalDiskIDs'))

    def _get_virtual_disk_attr(self, drac_disk, attr_name, nullable=False):
        return utils.get_wsman_resource_attr(
            drac_disk, uris.DCIM_VirtualDiskView, attr_name,
            nullable=nullable)

    def _get_virtual_disk_attrs(self, drac_disk, attr_name):
        return utils.get_all_wsman_resource_attrs(
            drac_disk, uris.DCIM_VirtualDiskView, attr_name, nullable=False)

    def list_physical_disks(self):
        """Returns the list of physical disks

        :returns: a list of PhysicalDisk objects
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        """

        doc = self.client.enumerate(uris.DCIM_PhysicalDiskView)

        drac_physical_disks = utils.find_xml(doc, 'DCIM_PhysicalDiskView',
                                             uris.DCIM_PhysicalDiskView,
                                             find_all=True)

        return [self._parse_drac_physical_disk(disk)
                for disk in drac_physical_disks]

    def _parse_drac_physical_disk(self, drac_disk):
        fqdd = self._get_physical_disk_attr(drac_disk, 'FQDD')
        size_b = self._get_physical_disk_attr(drac_disk, 'SizeInBytes')
        free_size_b = self._get_physical_disk_attr(drac_disk,
                                                   'FreeSizeInBytes')
        drac_status = self._get_physical_disk_attr(drac_disk, 'PrimaryStatus')
        drac_raid_status = self._get_physical_disk_attr(drac_disk,
                                                        'RaidStatus')
        drac_media_type = self._get_physical_disk_attr(drac_disk, 'MediaType')
        drac_bus_protocol = self._get_physical_disk_attr(drac_disk,
                                                         'BusProtocol')

        return PhysicalDisk(
            id=fqdd,
            description=self._get_physical_disk_attr(drac_disk,
                                                     'DeviceDescription'),
            controller=fqdd.split(':')[-1],
            manufacturer=self._get_physical_disk_attr(drac_disk,
                                                      'Manufacturer'),
            model=self._get_physical_disk_attr(drac_disk, 'Model'),
            media_type=PHYSICAL_DISK_MEDIA_TYPE[drac_media_type],
            interface_type=PHYSICAL_DISK_BUS_PROTOCOL[drac_bus_protocol],
            size_mb=int(size_b) / 2 ** 20,
            free_size_mb=int(free_size_b) / 2 ** 20,
            serial_number=self._get_physical_disk_attr(drac_disk,
                                                       'SerialNumber'),
            firmware_version=self._get_physical_disk_attr(drac_disk,
                                                          'Revision'),
            status=constants.PRIMARY_STATUS[drac_status],
            raid_status=DISK_RAID_STATUS[drac_raid_status])

    def _get_physical_disk_attr(self, drac_disk, attr_name):
        return utils.get_wsman_resource_attr(
            drac_disk, uris.DCIM_PhysicalDiskView, attr_name, nullable=True)

    def convert_physical_disks(self, physical_disks, raid_enable):
        """Converts a list of physical disks into or out of RAID mode.

        Disks can be enabled or disabled for RAID mode.

        :param physical_disks: list of FQDD ID strings of the physical disks
               to update
        :param raid_enable: boolean flag, set to True if the disk is to
               become part of the RAID.  The same flag is applied to all
               listed disks
        :returns: a dictionary containing the commit_needed key with a boolean
                  value indicating whether a config job must be created for the
                  values to be applied.
        """
        invocation = 'ConvertToRAID' if raid_enable else 'ConvertToNonRAID'

        selectors = {'SystemCreationClassName': 'DCIM_ComputerSystem',
                     'CreationClassName': 'DCIM_RAIDService',
                     'SystemName': 'DCIM:ComputerSystem',
                     'Name': 'DCIM:RAIDService'}

        properties = {'PDArray': physical_disks}

        doc = self.client.invoke(uris.DCIM_RAIDService, invocation,
                                 selectors, properties,
                                 expected_return_value=utils.RET_SUCCESS)

        return {'commit_required':
                utils.is_reboot_required(doc, uris.DCIM_RAIDService)}

    def create_virtual_disk(self, raid_controller, physical_disks, raid_level,
                            size_mb, disk_name=None, span_length=None,
                            span_depth=None):
        """Creates a virtual disk

        The created virtual disk will be in pending state. For the changes to
        be applied, a config job must be created and the node must be rebooted.

        :param raid_controller: id of the RAID controller
        :param physical_disks: ids of the physical disks
        :param raid_level: RAID level of the virtual disk
        :param size_mb: size of the virtual disk in megabytes
        :param disk_name: name of the virtual disk (optional)
        :param span_length: number of disks per span (optional)
        :param span_depth: number of spans in virtual disk (optional)
        :returns: a dictionary containing the commit_needed key with a boolean
                  value indicating whether a config job must be created for the
                  values to be applied.
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        :raises: DRACUnexpectedReturnValue on return value mismatch
        :raises: InvalidParameterValue on invalid input parameter
        """

        virtual_disk_prop_names = []
        virtual_disk_prop_values = []
        error_msgs = []

        # RAID controller validation
        if not raid_controller:
            error_msgs.append("'raid_controller' is not supplied")

        # physical disks validation
        if not physical_disks:
            error_msgs.append("'physical_disks' is not supplied")

        # size validation
        if not size_mb:
            error_msgs.append("'size_mb' is not supplied")
        else:
            utils.validate_integer_value(size_mb, 'size_mb', error_msgs)

        virtual_disk_prop_names.append('Size')
        virtual_disk_prop_values.append(str(size_mb))

        # RAID level validation
        virtual_disk_prop_names.append('RAIDLevel')
        try:
            virtual_disk_prop_values.append(RAID_LEVELS[str(raid_level)])
        except KeyError:
            error_msgs.append("'raid_level' is invalid")

        if disk_name is not None:
            virtual_disk_prop_names.append('VirtualDiskName')
            virtual_disk_prop_values.append(disk_name)

        if span_depth is not None:
            utils.validate_integer_value(span_depth, 'span_depth', error_msgs)

            virtual_disk_prop_names.append('SpanDepth')
            virtual_disk_prop_values.append(str(span_depth))

        if span_length is not None:
            utils.validate_integer_value(span_length, 'span_length',
                                         error_msgs)

            virtual_disk_prop_names.append('SpanLength')
            virtual_disk_prop_values.append(str(span_length))

        if error_msgs:
            msg = ('The following errors were encountered while parsing '
                   'the provided parameters: %r') % ','.join(error_msgs)
            raise exceptions.InvalidParameterValue(reason=msg)

        selectors = {'SystemCreationClassName': 'DCIM_ComputerSystem',
                     'CreationClassName': 'DCIM_RAIDService',
                     'SystemName': 'DCIM:ComputerSystem',
                     'Name': 'DCIM:RAIDService'}
        properties = {'Target': raid_controller,
                      'PDArray': physical_disks,
                      'VDPropNameArray': virtual_disk_prop_names,
                      'VDPropValueArray': virtual_disk_prop_values}
        doc = self.client.invoke(uris.DCIM_RAIDService, 'CreateVirtualDisk',
                                 selectors, properties,
                                 expected_return_value=utils.RET_SUCCESS)

        return {'commit_required': utils.is_reboot_required(
            doc, uris.DCIM_RAIDService)}

    def delete_virtual_disk(self, virtual_disk):
        """Deletes a virtual disk

        The deleted virtual disk will be in pending state. For the changes to
        be applied, a config job must be created and the node must be rebooted.

        :param virtual_disk: id of the virtual disk
        :returns: a dictionary containing the commit_needed key with a boolean
                  value indicating whether a config job must be created for the
                  values to be applied.
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        :raises: DRACUnexpectedReturnValue on return value mismatch
        """

        selectors = {'SystemCreationClassName': 'DCIM_ComputerSystem',
                     'CreationClassName': 'DCIM_RAIDService',
                     'SystemName': 'DCIM:ComputerSystem',
                     'Name': 'DCIM:RAIDService'}
        properties = {'Target': virtual_disk}

        doc = self.client.invoke(uris.DCIM_RAIDService, 'DeleteVirtualDisk',
                                 selectors, properties,
                                 expected_return_value=utils.RET_SUCCESS)

        return {'commit_required': utils.is_reboot_required(
            doc, uris.DCIM_RAIDService)}


class RAIDAttribute(object):
    """Generic RAID attribute class"""

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only):
        """Creates RAIDAttribute object

        :param name: name of the RAID attribute
        :param instance_id: opaque and unique identifier of the RAID attribute
        :param current_value: current value of the RAID attribute
        :param pending_value: pending value of the RAID attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this RAID attribute can be changed
        """
        self.name = name
        self.instance_id = instance_id
        self.current_value = current_value
        self.pending_value = pending_value
        self.read_only = read_only

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self.__eq__(other)

    @classmethod
    def parse(cls, namespace, RAID_attr_xml):
        """Parses XML and creates RAIDAttribute object"""

        name = utils.get_wsman_resource_attr(
            RAID_attr_xml, namespace, 'AttributeName')
        instance_id = utils.get_wsman_resource_attr(
            RAID_attr_xml, namespace, 'InstanceID')
        current_value = utils.get_wsman_resource_attr(
            RAID_attr_xml, namespace, 'CurrentValue', nullable=True)
        pending_value = utils.get_wsman_resource_attr(
            RAID_attr_xml, namespace, 'PendingValue', nullable=True)
        read_only = utils.get_wsman_resource_attr(
            RAID_attr_xml, namespace, 'IsReadOnly')

        return cls(name, instance_id, current_value, pending_value,
                   (read_only == 'true'))




class RAIDEnumerableAttribute(RAIDAttribute):
    """Enumerable RAID attribute class"""

    namespace = uris.DCIM_RAIDEnumeration

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, possible_values):
        """Creates RAIDEnumerableAttribute object

        :param name: name of the RAID attribute
        :param current_value: current value of the RAID attribute
        :param pending_value: pending value of the RAID attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this RAID attribute can be changed
        :param possible_values: list containing the allowed values for the RAID
                                attribute
        """
        super(RAIDEnumerableAttribute, self).__init__(name, instance_id,
                                                      current_value,
                                                      pending_value, read_only)
        self.possible_values = possible_values

    @classmethod
    def parse(cls, raid_attr_xml):
        """Parses XML and creates RAIDEnumerableAttribute object"""

        raid_attr = RAIDAttribute.parse(cls.namespace, raid_attr_xml)
        possible_values = [attr.text for attr
                           in utils.find_xml(raid_attr_xml, 'PossibleValues',
                                             cls.namespace, find_all=True)]

        return cls(raid_attr.name, raid_attr.instance_id,
                   raid_attr.current_value, raid_attr.pending_value,
                   raid_attr.read_only, possible_values)

    def validate(self, new_value):
        """Validates new value"""

        if str(new_value) not in self.possible_values:
            msg = ("Attribute '%(attr)s' cannot be set to value '%(val)s'."
                   " It must be in %(possible_values)r.") % {
                       'attr': self.name,
                       'val': new_value,
                       'possible_values': self.possible_values}
            return msg


class RAIDStringAttribute(RAIDAttribute):
    """String RAID attribute class"""

    namespace = uris.DCIM_RAIDString

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, min_length, max_length, pcre_regex):
        """Creates RAIDStringAttribute object

        :param name: name of the RAID attribute
        :param current_value: current value of the RAID attribute
        :param pending_value: pending value of the RAID attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this RAID attribute can be changed
        :param min_length: minimum length of the string
        :param max_length: maximum length of the string
        :param pcre_regex: is a PCRE compatible regular expression that the
                           string must match
        """
        super(RAIDStringAttribute, self).__init__(name, instance_id,
                                                  current_value, pending_value,
                                                  read_only)
        self.min_length = min_length
        self.max_length = max_length
        self.pcre_regex = pcre_regex

    @classmethod
    def parse(cls, raid_attr_xml):
        """Parses XML and creates RAIDStringAttribute object"""

        raid_attr = RAIDAttribute.parse(cls.namespace, raid_attr_xml)
        min_length = int(utils.get_wsman_resource_attr(
            raid_attr_xml, cls.namespace, 'MinLength'))
        max_length = int(utils.get_wsman_resource_attr(
            raid_attr_xml, cls.namespace, 'MaxLength'))
        pcre_regex = utils.get_wsman_resource_attr(
            raid_attr_xml, cls.namespace, 'ValueExpression', nullable=True)

        return cls(raid_attr.name, raid_attr.instance_id,
                   raid_attr.current_value, raid_attr.pending_value,
                   raid_attr.read_only, min_length, max_length, pcre_regex)

    def validate(self, new_value):
        """Validates new value"""

        if self.pcre_regex is not None:
            regex = re.compile(self.pcre_regex)
            if regex.search(str(new_value)) is None:
                msg = ("Attribute '%(attr)s' cannot be set to value '%(val)s.'"
                       " It must match regex '%(re)s'.") % {
                           'attr': self.name,
                           'val': new_value,
                           're': self.pcre_regex}
                return msg


class RAIDIntegerAttribute(RAIDAttribute):
    """Integer RAID attribute class"""

    namespace = uris.DCIM_RAIDInteger

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, lower_bound, upper_bound):
        """Creates RAIDIntegerAttribute object

        :param name: name of the RAID attribute
        :param current_value: current value of the RAID attribute
        :param pending_value: pending value of the RAID attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this RAID attribute can be changed
        :param lower_bound: minimum value for the RAID attribute
        :param upper_bound: maximum value for the RAID attribute
        """
        super(RAIDIntegerAttribute, self).__init__(name, instance_id,
                                                   current_value,
                                                   pending_value, read_only)
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound

    @classmethod
    def parse(cls, raid_attr_xml):
        """Parses XML and creates RAIDIntegerAttribute object"""

        raid_attr = RAIDAttribute.parse(cls.namespace, raid_attr_xml)
        lower_bound = utils.get_wsman_resource_attr(
            raid_attr_xml, cls.namespace, 'LowerBound')
        upper_bound = utils.get_wsman_resource_attr(
            raid_attr_xml, cls.namespace, 'UpperBound')

        if raid_attr.current_value:
            raid_attr.current_value = int(raid_attr.current_value)
        if raid_attr.pending_value:
            raid_attr.pending_value = int(raid_attr.pending_value)

        return cls(raid_attr.name, raid_attr.instance_id,
                   raid_attr.current_value, raid_attr.pending_value,
                   raid_attr.read_only, int(lower_bound), int(upper_bound))

    def validate(self, new_value):
        """Validates new value"""

        val = int(new_value)
        if val < self.lower_bound or val > self.upper_bound:
            msg = ('Attribute %(attr)s cannot be set to value %(val)d.'
                   ' It must be between %(lower)d and %(upper)d.') % {
                       'attr': self.name,
                       'val': new_value,
                       'lower': self.lower_bound,
                       'upper': self.upper_bound}
            return msg
