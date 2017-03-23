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

from dracclient.resources import uris
from dracclient import utils
from dracclient import wsman
import collections

SoftwareComponent = collections.namedtuple(
    'SoftwareComponent', ['instance_id', 'component_type', 'component_id', 'element_name',
                       'version_string', 'major_version', 'minor_version', 'build_number',
                          'revision_number', 'revision_string', 'impacts_tp_measurements',
                          'device_id', 'sub_device_id', 'vendor_id', 'sub_vendor_id',
                          'status', 'installation_date', 'identity_info_type',
                          'identity_info_value', 'classifications'])


class LifecycleControllerManagement(object):

    def __init__(self, client):
        """Creates LifecycleControllerManagement object

        :param client: an instance of WSManClient
        """
        self.client = client

    def get_version(self):
        """Returns the Lifecycle controller version

        :returns: Lifecycle controller version as a tuple of integers
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        """

        filter_query = ('select LifecycleControllerVersion '
                        'from DCIM_SystemView')
        doc = self.client.enumerate(uris.DCIM_SystemView,
                                    filter_query=filter_query)
        lc_version_str = utils.find_xml(doc, 'LifecycleControllerVersion',
                                        uris.DCIM_SystemView).text

        return tuple(map(int, (lc_version_str.split('.'))))


class LCConfiguration(object):

    def __init__(self, client):
        """Creates LifecycleControllerManagement object

        :param client: an instance of WSManClient
        """
        self.client = client

    def list_firmware_components(self):
        """Returns the list of RAID controllers

        :returns: a list of RAIDController objects
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        """

        doc = self.client.enumerate(uris.DCIM_SoftwareIdentity)

        software_components = utils.find_xml(doc, 'DCIM_SoftwareIdentity',
                                               uris.DCIM_SoftwareIdentity,
                                               find_all=True)

        return [self._parse_software_components(component)
                for component in software_components]

    def _parse_software_components(self, component):
        return SoftwareComponent(
            instance_id = self._get_software_component_attr(component, 'InstanceID'),
            component_type=self._get_software_component_attr(component,
                                                          'ComponentType'),
            component_id=self._get_software_component_attr(component,
                                                          'ComponentID'),
            element_name=self._get_software_component_attr(component,
                                                          'ElementName'),
            version_string=self._get_software_component_attr(component,
                                                          'VersionString'),
            major_version=self._get_software_component_attr(component,
                                                          'MajorVersion'),
            minor_version=self._get_software_component_attr(component,
                                                          'MinorVersion'),
            build_number=self._get_software_component_attr(component,
                                                          'BuildNumber'),
            revision_number=self._get_software_component_attr(component,
                                                          'RevisionNumber'),
            revision_string=self._get_software_component_attr(component,
                                                          'RevisionString'),
            impacts_tp_measurements=self._get_software_component_attr(component,
                                                          'impactsTPMmeasurements'),
            device_id=self._get_software_component_attr(component,
                                                          'DeviceID'),
            sub_device_id=self._get_software_component_attr(component,
                                                          'SubDeviceID'),
            vendor_id=self._get_software_component_attr(component,
                                                          'VendorID'),
            sub_vendor_id=self._get_software_component_attr(component,
                                                          'SubVendorID'),
            status=self._get_software_component_attr(component,
                                                          'Status'),
            installation_date=self._get_software_component_attr(component,
                                                          'InstallationDate'),
            identity_info_type=self._get_software_component_attr(component,
                                                          'IdentityInfoType'),
            identity_info_value=self._get_software_component_attr(component,
                                                          'IdentityInfoValue'),
            classifications=self._get_software_component_attr(component,
                                                          'Classifications'))

    def _get_software_component_attr(self, component, attr_name):
        return utils.get_wsman_resource_attr(
            component, uris.DCIM_SoftwareIdentity, attr_name,
            nullable=True)

    def install_software(self, uri, instance):
        selectors = {'CreationClassName': "DCIM_SoftwareInstallationService",
                     'SystemCreationClassName': 'DCIM_ComputerSystem',
                     'SystemName': 'IDRAC:ID',
                     'Name': 'DCIM:SoftwareUpdate',
                     }
        target = self.client.create_software_identity('Target', uris.DCIM_SoftwareInstallationService, instance, uris.DCIM_SoftwareIdentity)
        properties = {
            'URI': uri,
            'Target': target,
        }

        doc = self.client.invoke(uris.DCIM_SoftwareInstallationService, 'InstallFromURI',
                                 selectors, properties)

        query = ('.//{%(namespace)s}%(item)s[@%(attribute_name)s='
                 '"%(attribute_value)s"]' %
                 {'namespace': wsman.NS_WSMAN, 'item': 'Selector',
                  'attribute_name': 'Name',
                  'attribute_value': 'InstanceID'})
        job_id = doc.find(query).text
        return job_id

    def create_reboot_job(self):
        selectors = {'CreationClassName': "DCIM_SoftwareInstallationService",
                     'SystemCreationClassName': 'DCIM_ComputerSystem',
                     'SystemName': 'IDRAC:ID',
                     'Name': 'DCIM:SoftwareUpdate',
                     }
        properties = {
            'RebootJobType': "1",
        }

        doc = self.client.invoke(uris.DCIM_SoftwareInstallationService, 'CreateRebootJob',
                                 selectors, properties)

        query = ('.//{%(namespace)s}%(item)s[@%(attribute_name)s='
                 '"%(attribute_value)s"]' %
                 {'namespace': wsman.NS_WSMAN, 'item': 'Selector',
                  'attribute_name': 'Name',
                  'attribute_value': 'InstanceID'})
        job_id = doc.find(query).text
        return job_id



    def list_lifecycle_settings(self):
        """List the LC configuration settings

        :returns: a dictionary with the LC settings using InstanceID as the
                  key. The attributes are either LCEnumerableAttribute,
                  LCStringAttribute or LCIntegerAttribute objects.
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        """
        result = {}
        namespaces = [(uris.DCIM_LCEnumeration, LCEnumerableAttribute),
                      (uris.DCIM_LCString, LCStringAttribute)]
        for (namespace, attr_cls) in namespaces:
            attribs = self._get_config(namespace, attr_cls)
            result.update(attribs)
        return result

    def _get_config(self, resource, attr_cls):
        result = {}

        doc = self.client.enumerate(resource)

        items = doc.find('.//{%s}Items' % wsman.NS_WSMAN)
        for item in items:
            attribute = attr_cls.parse(item)
            result[attribute.instance_id] = attribute

        return result

class LCRegAttribute(object):
    """Generic LC LCRegAttribute class"""

    def __init__(self, registered_name, registered_version, registered_orginization, other_registered_orginization):
        """Creates LCAttribute object

        :param name: name of the LC attribute
        :param instance_id: InstanceID of the LC attribute
        :param current_value: current value of the LC attribute
        :param pending_value: pending value of the LC attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this LC attribute can be changed
        """
        self.registered_name = registered_name
        self.registered_version = registered_version
        self.registered_orginization = registered_orginization
        self.other_registered_orginization = other_registered_orginization

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    @classmethod
    def parse(cls, namespace, lifecycle_attr_xml):
        """Parses XML and creates LCAttribute object"""

        registered_name = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'RegisteredName')
        registered_version = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'RegisteredVersion')
        registered_orginization = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'RegisteredOrganization')
        other_registered_orginization = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'OtherRegisteredOrganization')

        return cls(registered_name, registered_version, registered_orginization, other_registered_orginization)



class LCRegisteredProfile(LCRegAttribute):
    """Enumerable LC attribute class"""

    namespace = uris.DCIM_LCRegisteredProfile

    def __init__(self, registered_name, registered_version, registered_orginization, other_registered_orginization,
                 possible_values):
        """Creates LCRegisteredProfile object

        :param name: name of the LC attribute
        :param current_value: current value of the LC attribute
        :param pending_value: pending value of the LC attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this LC attribute can be changed
        :param possible_values: list containing the allowed values for the LC
                                attribute
        """
        super(LCRegisteredProfile, self).__init__(registered_name, registered_version,
                                                  registered_orginization,
                                                  other_registered_orginization)
        self.possible_values = possible_values

    @classmethod
    def parse(cls, lifecycle_attr_xml):
        """Parses XML and creates LCEnumerableAttribute object"""

        lifecycle_attr = LCAttribute.parse(cls.namespace, lifecycle_attr_xml)
        possible_values = [attr.text for attr
                           in utils.find_xml(lifecycle_attr_xml,
                                             'PossibleValues',
                                             cls.namespace, find_all=True)]

        return cls(lifecycle_attr.name, lifecycle_attr.instance_id,
                   lifecycle_attr.current_value, lifecycle_attr.pending_value,
                   lifecycle_attr.read_only, possible_values)



class LCAttribute(object):
    """Generic LC attribute class"""

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only):
        """Creates LCAttribute object

        :param name: name of the LC attribute
        :param instance_id: InstanceID of the LC attribute
        :param current_value: current value of the LC attribute
        :param pending_value: pending value of the LC attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this LC attribute can be changed
        """
        self.name = name
        self.instance_id = instance_id
        self.current_value = current_value
        self.pending_value = pending_value
        self.read_only = read_only

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    @classmethod
    def parse(cls, namespace, lifecycle_attr_xml):
        """Parses XML and creates LCAttribute object"""

        name = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'AttributeName')
        instance_id = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'InstanceID')
        current_value = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'CurrentValue', nullable=True)
        pending_value = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'PendingValue', nullable=True)
        read_only = utils.get_wsman_resource_attr(
            lifecycle_attr_xml, namespace, 'IsReadOnly')

        return cls(name, instance_id, current_value, pending_value,
                   (read_only == 'true'))


class LCEnumerableAttribute(LCAttribute):
    """Enumerable LC attribute class"""

    namespace = uris.DCIM_LCEnumeration

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, possible_values):
        """Creates LCEnumerableAttribute object

        :param name: name of the LC attribute
        :param current_value: current value of the LC attribute
        :param pending_value: pending value of the LC attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this LC attribute can be changed
        :param possible_values: list containing the allowed values for the LC
                                attribute
        """
        super(LCEnumerableAttribute, self).__init__(name, instance_id,
                                                    current_value,
                                                    pending_value, read_only)
        self.possible_values = possible_values

    @classmethod
    def parse(cls, lifecycle_attr_xml):
        """Parses XML and creates LCEnumerableAttribute object"""

        lifecycle_attr = LCAttribute.parse(cls.namespace, lifecycle_attr_xml)
        possible_values = [attr.text for attr
                           in utils.find_xml(lifecycle_attr_xml,
                                             'PossibleValues',
                                             cls.namespace, find_all=True)]

        return cls(lifecycle_attr.name, lifecycle_attr.instance_id,
                   lifecycle_attr.current_value, lifecycle_attr.pending_value,
                   lifecycle_attr.read_only, possible_values)


class LCStringAttribute(LCAttribute):
    """String LC attribute class"""

    namespace = uris.DCIM_LCString

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, min_length, max_length):
        """Creates LCStringAttribute object

        :param name: name of the LC attribute
        :param instance_id: InstanceID of the LC attribute
        :param current_value: current value of the LC attribute
        :param pending_value: pending value of the LC attribute, reflecting
                an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this LC attribute can be changed
        :param min_length: minimum length of the string
        :param max_length: maximum length of the string
        """
        super(LCStringAttribute, self).__init__(name, instance_id,
                                                current_value, pending_value,
                                                read_only)
        self.min_length = min_length
        self.max_length = max_length

    @classmethod
    def parse(cls, lifecycle_attr_xml):
        """Parses XML and creates LCStringAttribute object"""

        lifecycle_attr = LCAttribute.parse(cls.namespace, lifecycle_attr_xml)
        min_length = int(utils.get_wsman_resource_attr(
            lifecycle_attr_xml, cls.namespace, 'MinLength'))
        max_length = int(utils.get_wsman_resource_attr(
            lifecycle_attr_xml, cls.namespace, 'MaxLength'))

        return cls(lifecycle_attr.name, lifecycle_attr.instance_id,
                   lifecycle_attr.current_value, lifecycle_attr.pending_value,
                   lifecycle_attr.read_only, min_length, max_length)
