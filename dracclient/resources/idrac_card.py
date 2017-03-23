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


class iDRACCardConfiguration(object):

    def __init__(self, client):
        """Creates iDRACCardManagement object

        :param client: an instance of WSManClient
        """
        self.client = client
        self.current_settings = None

    def list_idrac_settings(self, force_reget=False):
        """List the iDRACCard configuration settings

        :returns: a dictionary with the iDRACCard settings using its name as
                  the key. The attributes are either
                  iDRACCardEnumerableAttribute, iDRACCardStringAttribute
                  or iDRACCardIntegerAttribute objects.
        :raises: WSManRequestFailure on request failures
        :raises: WSManInvalidResponse when receiving invalid response
        :raises: DRACOperationFailed on error reported back by the DRAC
                 interface
        """

        if not force_reget and self.current_settings:
            return self.current_settings
        result = {}
        namespaces = [(uris.DCIM_iDRACCardEnumeration,
                       iDRACCardEnumerableAttribute),
                      (uris.DCIM_iDRACCardString, iDRACCardStringAttribute),
                      (uris.DCIM_iDRACCardInteger, iDRACCardIntegerAttribute)]
        for (namespace, attr_cls) in namespaces:
            attribs = self._get_config(namespace, attr_cls)
            result.update(attribs)

        self.current_settings = result
        return result

    def _get_config(self, resource, attr_cls):
        result = {}
        doc = self.client.enumerate(resource)

        items = doc.find('.//{%s}Items' % wsman.NS_WSMAN)

        if items:
            for item in items:
                attribute = attr_cls.parse(item)
                result[attribute.instance_id] = attribute
        return result

    def set_idrac_settings(self, new_settings):
        """Sets the iDRAC settings

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
        :raises: InvalidParameterValue on invalid iDRAC attribute
        """

        if not self.current_settings:
            current_settings = self.list_idrac_settings()
        else:
            current_settings = self.current_settings
        # iDRAC settings are returned as dict indexed by InstanceID.
        # However DCIM_iDRACCardService requires attribute name, not instance id
        # so recreate this as a dict indexed by attribute name
        # TODO(anish) : Enable this code if/when by_name gets deprecated
        # iDRAC_settings = self.list_iDRAC_settings(by_name=False)
        # current_settings = dict((value.name, value)
        #                         for key, value in iDRAC_settings.items())
        unknown_keys = set(new_settings) - set(current_settings)
        if unknown_keys:
            msg = ('Unknown iDRAC attributes found: %(unknown_keys)r' %
                   {'unknown_keys': unknown_keys})
            raise exceptions.InvalidParameterValue(reason=msg)

        read_only_keys = []
        unchanged_attribs = []
        invalid_attribs_msgs = []
        attrib_names = []
        target = None
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
                    split_name = attr.split("#")
                    if not target:
                        target = split_name[0]
                    else:
                        if split_name[0] != target:
                            raise exceptions.InvalidParameterValue(reason="Cannot pass multiple targets")
                    attrib_names.append('#'.join(split_name[1:]))
                else:
                    invalid_attribs_msgs.append(validation_msg)

        if unchanged_attribs:
            LOG.warning('Ignoring unchanged iDRAC attributes: %r',
                        unchanged_attribs)

        if invalid_attribs_msgs or read_only_keys:
            if read_only_keys:
                read_only_msg = ['Cannot set read-only iDRAC attributes: %r.'
                                 % read_only_keys]
            else:
                read_only_msg = []

            drac_messages = '\n'.join(invalid_attribs_msgs + read_only_msg)
            raise exceptions.DRACOperationFailed(
                drac_messages=drac_messages)

        if not attrib_names:
            return None

        selectors = {'CreationClassName': 'DCIM_iDRACCardService',
                     'Name': 'DCIM:iDRACCardService',
                     'SystemCreationClassName': 'DCIM_ComputerSystem',
                     'SystemName': 'DCIM:ComputerSystem'}
        properties = {'Target': target,
                      'AttributeName': attrib_names,
                      'AttributeValue': [new_settings[target + "#" + attr] for attr
                                         in attrib_names]}
        doc = self.client.invoke(uris.DCIM_iDRACCardService, 'ApplyAttributes',
                                 selectors, properties)
        query = ('.//{%(namespace)s}%(item)s[@%(attribute_name)s='
                 '"%(attribute_value)s"]' %
                 {'namespace': wsman.NS_WSMAN, 'item': 'Selector',
                  'attribute_name': 'Name',
                  'attribute_value': 'InstanceID'})
        job_id = doc.find(query).text
        return job_id

class iDRACCardAttribute(object):
    """Generic iDRACCard attribute class"""

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, fqdd, group_id):
        """Creates iDRACCardAttribute object

        :param name: name of the iDRACCard attribute
        :param instance_id: InstanceID of the iDRACCard attribute
        :param current_value: current value of the iDRACCard attribute
        :param pending_value: pending value of the iDRACCard attribute,
                reflecting an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this iDRACCard attribute can be
                changed
        :param fqdd: Fully Qualified Device Description of the iDRACCard
                Attribute
        :param group_id: GroupID of the iDRACCard Attribute
        """
        self.name = name
        self.instance_id = instance_id
        self.current_value = current_value
        self.pending_value = pending_value
        self.read_only = read_only
        self.fqdd = fqdd
        self.group_id = group_id

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    @classmethod
    def parse(cls, namespace, idrac_attr_xml):
        """Parses XML and creates iDRACCardAttribute object"""

        name = utils.get_wsman_resource_attr(
            idrac_attr_xml, namespace, 'AttributeName')
        instance_id = utils.get_wsman_resource_attr(
            idrac_attr_xml, namespace, 'InstanceID')
        current_value = utils.get_wsman_resource_attr(
            idrac_attr_xml, namespace, 'CurrentValue', nullable=True)
        pending_value = utils.get_wsman_resource_attr(
            idrac_attr_xml, namespace, 'PendingValue', nullable=True)
        read_only = utils.get_wsman_resource_attr(
            idrac_attr_xml, namespace, 'IsReadOnly').lower()
        fqdd = utils.get_wsman_resource_attr(
            idrac_attr_xml, namespace, 'FQDD')
        group_id = utils.get_wsman_resource_attr(
            idrac_attr_xml, namespace, 'GroupID')

        return cls(name, instance_id, current_value, pending_value,
                   (read_only == 'true'), fqdd, group_id)


class iDRACCardEnumerableAttribute(iDRACCardAttribute):
    """Enumerable iDRACCard attribute class"""

    namespace = uris.DCIM_iDRACCardEnumeration

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, fqdd, group_id, possible_values):
        """Creates iDRACCardEnumerableAttribute object

        :param name: name of the iDRACCard attribute
        :param instance_id: InstanceID of the iDRACCard attribute
        :param current_value: current value of the iDRACCard attribute
        :param pending_value: pending value of the iDRACCard attribute,
                reflecting an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this iDRACCard attribute can be
                changed
        :param fqdd: Fully Qualified Device Description of the iDRACCard
                Attribute
        :param group_id: GroupID of the iDRACCard Attribute
        :param possible_values: list containing the allowed values for the
                                iDRACCard attribute
        """
        super(iDRACCardEnumerableAttribute, self).__init__(name, instance_id,
                                                           current_value,
                                                           pending_value,
                                                           read_only, fqdd,
                                                           group_id)
        self.possible_values = possible_values

    @classmethod
    def parse(cls, idrac_attr_xml):
        """Parses XML and creates iDRACCardEnumerableAttribute object"""

        idrac_attr = iDRACCardAttribute.parse(cls.namespace, idrac_attr_xml)
        possible_values = [attr.text for attr
                           in utils.find_xml(idrac_attr_xml, 'PossibleValues',
                                             cls.namespace, find_all=True)]

        return cls(idrac_attr.name, idrac_attr.instance_id,
                   idrac_attr.current_value, idrac_attr.pending_value,
                   idrac_attr.read_only, idrac_attr.fqdd, idrac_attr.group_id,
                   possible_values)

    def validate(self, new_value):
        """Validates new value"""

        if str(new_value) not in self.possible_values:
            msg = ("Attribute '%(attr)s' cannot be set to value '%(val)s'."
                   " It must be in %(possible_values)r.") % {
                       'attr': self.name,
                       'val': new_value,
                       'possible_values': self.possible_values}
            return msg


class iDRACCardStringAttribute(iDRACCardAttribute):
    """String iDRACCard attribute class"""

    namespace = uris.DCIM_iDRACCardString

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, fqdd, group_id, min_length, max_length):
        """Creates iDRACCardStringAttribute object

        :param name: name of the iDRACCard attribute
        :param instance_id: InstanceID of the iDRACCard attribute
        :param current_value: current value of the iDRACCard attribute
        :param pending_value: pending value of the iDRACCard attribute,
                reflecting an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this iDRACCard attribute can be
                changed
        :param fqdd: Fully Qualified Device Description of the iDRACCard
                Attribute
        :param group_id: GroupID of the iDRACCard Attribute
        :param min_length: minimum length of the string
        :param max_length: maximum length of the string
        """
        super(iDRACCardStringAttribute, self).__init__(name, instance_id,
                                                       current_value,
                                                       pending_value,
                                                       read_only, fqdd,
                                                       group_id)
        self.min_length = min_length
        self.max_length = max_length

    @classmethod
    def parse(cls, idrac_attr_xml):
        """Parses XML and creates iDRACCardStringAttribute object"""

        idrac_attr = iDRACCardAttribute.parse(cls.namespace, idrac_attr_xml)
        min_length = int(utils.get_wsman_resource_attr(
            idrac_attr_xml, cls.namespace, 'MinLength'))
        max_length = int(utils.get_wsman_resource_attr(
            idrac_attr_xml, cls.namespace, 'MaxLength'))

        return cls(idrac_attr.name, idrac_attr.instance_id,
                   idrac_attr.current_value, idrac_attr.pending_value,
                   idrac_attr.read_only, idrac_attr.fqdd, idrac_attr.group_id,
                   min_length, max_length)

    def validate(self, new_value):
        """Validates new value"""

        if len(new_value) < self.min_length:
            msg = ("Attribute '%(attr)s' cannot be set to value '%(val)s.'"
                   " It must be at least %(len)s long'.") % {
                      'attr': self.name,
                      'val': new_value,
                      'len': self.min_length}
            return msg

        if len(new_value) > self.max_length:
            msg = ("Attribute '%(attr)s' cannot be set to value '%(val)s.'"
                   " It must not be longer than %(len)s'.") % {
                      'attr': self.name,
                      'val': new_value,
                      'len': self.max_length}
            return msg



class iDRACCardIntegerAttribute(iDRACCardAttribute):
    """Integer iDRACCard attribute class"""

    namespace = uris.DCIM_iDRACCardInteger

    def __init__(self, name, instance_id, current_value, pending_value,
                 read_only, fqdd, group_id, lower_bound, upper_bound):
        """Creates iDRACCardIntegerAttribute object

        :param name: name of the iDRACCard attribute
        :param instance_id: InstanceID of the iDRACCard attribute
        :param current_value: current value of the iDRACCard attribute
        :param pending_value: pending value of the iDRACCard attribute,
                reflecting an unprocessed change (eg. config job not completed)
        :param read_only: indicates whether this iDRACCard attribute can be
                changed
        :param fqdd: Fully Qualified Device Description of the iDRACCard
                Attribute
        :param group_id: GroupID of the iDRACCard Attribute
        :param lower_bound: minimum value for the iDRACCard attribute
        :param upper_bound: maximum value for the iDRACCard attribute
        """
        super(iDRACCardIntegerAttribute, self).__init__(name, instance_id,
                                                        current_value,
                                                        pending_value,
                                                        read_only, fqdd,
                                                        group_id)
        self.lower_bound = lower_bound
        self.upper_bound = upper_bound

    @classmethod
    def parse(cls, idrac_attr_xml):
        """Parses XML and creates iDRACCardIntegerAttribute object"""

        idrac_attr = iDRACCardAttribute.parse(cls.namespace, idrac_attr_xml)
        lower_bound = utils.get_wsman_resource_attr(
            idrac_attr_xml, cls.namespace, 'LowerBound')
        upper_bound = utils.get_wsman_resource_attr(
            idrac_attr_xml, cls.namespace, 'UpperBound')

        if idrac_attr.current_value:
            idrac_attr.current_value = int(idrac_attr.current_value)
        if idrac_attr.pending_value:
            idrac_attr.pending_value = int(idrac_attr.pending_value)

        return cls(idrac_attr.name, idrac_attr.instance_id,
                   idrac_attr.current_value, idrac_attr.pending_value,
                   idrac_attr.read_only, idrac_attr.fqdd, idrac_attr.group_id,
                   int(lower_bound), int(upper_bound))

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
