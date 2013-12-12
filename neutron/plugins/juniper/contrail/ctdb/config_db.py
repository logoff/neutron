# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Juniper Networks.  All rights reserved.
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
#
# @author: Hampapur Ajay, Rudra Rugge, Atul Moghe Juniper Networks.

import json
import netaddr
import re
import requests
import socket
import time
import uuid

from cfgm_common import exceptions as vnc_exc
from vnc_api import vnc_api

from neutron.api.v2 import attributes as attr
from neutron.common import constants
from neutron.common import exceptions
from neutron.extensions import portbindings
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)

_DEFAULT_HEADERS = {
    'Content-type': 'application/json; charset="UTF-8"', }

CREATE = 1
READ = 2
UPDATE = 3
DELETE = 4


class DBInterface(object):
    """An instance of this class forwards requests to vnc cfg api server"""
    Q_URL_PREFIX = '/extensions/ct'

    def __init__(self, admin_name, admin_password, admin_tenant_name,
                 api_server_ip, api_server_port, max_retries, retry_interval,
                 user_info=None):
        self._api_server_ip = api_server_ip
        self._api_server_port = api_server_port
        self._max_retries = max_retries
        self._retry_interval = retry_interval

        self._db_cache = {
            'q_networks': {},
            'q_subnets': {},
            'q_subnet_maps': {},
            'q_policies': {},
            'q_ipams': {},
            'q_floatingips': {},
            'q_ports': {},
            'q_fixed_ip_to_subnet': {},
            # obj-uuid to tenant-uuid mapping
            'q_obj_to_tenant': {},
            # port count per tenant-id
            'q_tenant_port_count': {},
            'vnc_networks': {},
            'vnc_ports': {},
            'vnc_projects': {},
            'vnc_instance_ips': {},
        }

        # Retry till a api-server is up or up to max_retries
        connected = False
        remaining = self._max_retries
        if remaining == -1:
            remaining = 'infinite'
        msg = _('api-server connection failed. %s attempts left.')

        while not connected:
            try:
                self._vnc_lib = vnc_api.VncApi(
                    admin_name, admin_password,
                    admin_tenant_name, api_server_ip,
                    api_server_port, '/', user_info=user_info)
                connected = True
            except requests.exceptions.RequestException:
                LOG.warn(msg % remaining)
                if (remaining != 'infinite' and remaining == 0):
                    raise
                if (remaining != 'infinite'):
                    remaining -= 1

                time.sleep(self._retry_interval)

        # changes 'net_fq_name_str pfx/len' key to 'net_id pfx/len' key
        # eg. domain1:project1:net1 1.1.1.0/24 becomes <uuid> 1.1.1.0/24
        subnet_map = self._vnc_lib.kv_retrieve(key=None)
        for kv_dict in subnet_map:
            key = kv_dict['key']
            if len(key.split()) == 1:
                subnet_id = key
                # uuid key, fixup value portion to 'net_id pfx/len' format
                # if not already so
                if len(kv_dict['value'].split(':')) == 1:
                    # new format already, skip
                    continue

                net_fq_name = kv_dict['value'].split()[0].split(':')
                try:
                    net_obj = self._virtual_network_read(fq_name=net_fq_name)
                except vnc_exc.NoIdError:
                    LOG.warning(_("No network: %r"), net_fq_name)
                    self._vnc_lib.kv_delete(subnet_id)
                    continue

                new_subnet_key = '%s %s' % (net_obj.uuid,
                                            kv_dict['value'].split()[1])
                self._vnc_lib.kv_store(subnet_id, new_subnet_key)
            else:  # subnet key
                if len(key.split()[0].split(':')) == 1:
                    # new format already, skip
                    continue

                # delete old key, convert to new key format and save
                old_subnet_key = key
                self._vnc_lib.kv_delete(old_subnet_key)

                subnet_id = kv_dict['value']
                net_fq_name = key.split()[0].split(':')
                try:
                    net_obj = self._virtual_network_read(fq_name=net_fq_name)
                except vnc_exc.NoIdError:
                    LOG.warning(_("No network: %r"), net_fq_name)
                    continue

                new_subnet_key = '%s %s' % (net_obj.uuid, key.split()[1])
                self._vnc_lib.kv_store(new_subnet_key, subnet_id)

    def _request_api_server(self, url, method, data=None, headers=None):
        return requests.request(method, url=url, data=data, headers=headers)

    def _relay_request(self, request):
        """Send received request to api server"""
        # chop neutron parts of url and add api server address
        url_path = re.sub(self.Q_URL_PREFIX, '', request.environ['PATH_INFO'])
        url = "http://%s:%s%s" % (self._api_server_ip, self._api_server_port,
                                  url_path)

        return self._request_api_server(
            url, request.environ['REQUEST_METHOD'],
            request.body, {'Content-type': request.environ['CONTENT_TYPE']})

    def _obj_to_dict(self, obj):
        return self._vnc_lib.obj_to_dict(obj)
    #end _obj_to_dict

    def _ensure_instance_exists(self, instance_id):
        instance_name = instance_id
        instance_obj = vnc_api.VirtualMachine(instance_name)
        try:
            id = self._vnc_lib.obj_to_id(instance_obj)
            instance_obj = self._vnc_lib.virtual_machine_read(id=id)
        except vnc_exc.NoIdError:  # instance doesn't exist, create it
            instance_obj.uuid = instance_id
            self._vnc_lib.virtual_machine_create(instance_obj)

        return instance_obj

    def _ensure_default_security_group_exists(self, proj_id):
        proj_obj = self._vnc_lib.project_read(id=proj_id)
        sg_groups = proj_obj.get_security_groups()
        for sg_group in sg_groups or []:
            sg_obj = self._vnc_lib.security_group_read(id=sg_group['uuid'])
            if sg_obj.name == 'default':
                return

        sg_obj = vnc_api.SecurityGroup(name='default', parent_obj=proj_obj)
        self._vnc_lib.security_group_create(sg_obj)

        #allow all egress traffic
        def_rule = {
            'port_range_min': 0,
            'port_range_max': 65535,
            'direction': 'egress',
            'remote_ip_prefix': None,
            'remote_group_id': None,
            'protocol': 'any',
        }
        rule = self._security_group_rule_neutron_to_vnc(def_rule, CREATE)
        self._security_group_rule_create(sg_obj.uuid, rule)

        #allow ingress traffic from within default security group
        def_rule = {
            'port_range_min': 0,
            'port_range_max': 65535,
            'direction': 'ingress',
            'remote_ip_prefix': None,
            'remote_group_id': None,
            'protocol': 'any',
        }
        rule = self._security_group_rule_neutron_to_vnc(def_rule, CREATE)
        self._security_group_rule_create(sg_obj.uuid, rule)

    def _get_obj_tenant_id(self, q_type, obj_uuid):
        # Get the mapping from cache, else seed cache and return
        try:
            return self._db_cache['q_obj_to_tenant'][obj_uuid]
        except KeyError:
            # Seed the cache and return
            if q_type == 'port':
                port_obj = self._virtual_machine_interface_read(obj_uuid)
                net_id = port_obj.get_virtual_network_refs()[0]['uuid']
                # recurse up type-hierarchy
                tenant_id = self._get_obj_tenant_id('network', net_id)
                self._set_obj_tenant_id(obj_uuid, tenant_id)
                return tenant_id

            if q_type == 'network':
                net_obj = self._virtual_network_read(net_id=obj_uuid)
                tenant_id = net_obj.parent_uuid.replace('-', '')
                self._set_obj_tenant_id(obj_uuid, tenant_id)
                return tenant_id

    def _set_obj_tenant_id(self, obj_uuid, tenant_uuid):
        self._db_cache['q_obj_to_tenant'][obj_uuid] = tenant_uuid

    def _del_obj_tenant_id(self, obj_uuid):
        try:
            del self._db_cache['q_obj_to_tenant'][obj_uuid]
        except Exception:
            pass

    def _project_read(self, proj_id=None, fq_name=None):
        if proj_id:
            proj_obj = self._vnc_lib.project_read(id=proj_id)
            fq_name_str = json.dumps(proj_obj.get_fq_name())
            self._db_cache['vnc_projects'][proj_id] = proj_obj
            self._db_cache['vnc_projects'][fq_name_str] = proj_obj
            return proj_obj

        if fq_name:
            fq_name_str = json.dumps(fq_name)
            proj_obj = self._vnc_lib.project_read(fq_name=fq_name)
            self._db_cache['vnc_projects'][fq_name_str] = proj_obj
            self._db_cache['vnc_projects'][proj_obj.uuid] = proj_obj
            return proj_obj

    def _security_group_rule_create(self, sg_id, sg_rule):
        sg_vnc = self._vnc_lib.security_group_read(id=sg_id)
        rules = sg_vnc.get_security_group_entries()
        if rules is None:
            rules = vnc_api.PolicyEntriesType([sg_rule])
        else:
            rules.add_policy_rule(sg_rule)

        sg_vnc.set_security_group_entries(rules)
        self._vnc_lib.security_group_update(sg_vnc)

    def _security_group_rule_find(self, sgr_id):
        dom_projects = self._project_list_domain(None)
        for project in dom_projects:
            proj_id = project['uuid']
            project_sgs = self._security_group_list_project(proj_id)

            for sg in project_sgs:
                sg_obj = self._vnc_lib.security_group_read(id=sg['uuid'])
                sgr_entries = sg_obj.get_security_group_entries()
                if sgr_entries is None:
                    continue

                for sg_rule in sgr_entries.get_policy_rule():
                    if sg_rule.get_rule_uuid() == sgr_id:
                        return sg_obj, sg_rule

        return None, None

    def _security_group_rule_delete(self, sg_obj, sg_rule):
        rules = sg_obj.get_security_group_entries()
        rules.get_policy_rule().remove(sg_rule)
        sg_obj.set_security_group_entries(rules)
        self._vnc_lib.security_group_update(sg_obj)

    def _security_group_create(self, sg_obj):
        sg_uuid = self._vnc_lib.security_group_create(sg_obj)
        return sg_uuid

    def _security_group_delete(self, sg_id):
        self._vnc_lib.security_group_delete(id=sg_id)

    def _virtual_network_create(self, net_obj):
        net_uuid = self._vnc_lib.virtual_network_create(net_obj)

        return net_uuid

    def _virtual_network_read(self, net_id=None, fq_name=None):
        if net_id:
            net_obj = self._vnc_lib.virtual_network_read(id=net_id)
            fq_name_str = json.dumps(net_obj.get_fq_name())
            self._db_cache['vnc_networks'][net_id] = net_obj
            self._db_cache['vnc_networks'][fq_name_str] = net_obj
            return net_obj

        if fq_name:
            fq_name_str = json.dumps(fq_name)
            net_obj = self._vnc_lib.virtual_network_read(fq_name=fq_name)
            self._db_cache['vnc_networks'][fq_name_str] = net_obj
            self._db_cache['vnc_networks'][net_obj.uuid] = net_obj
            return net_obj

    def _virtual_network_update(self, net_obj):
        self._vnc_lib.virtual_network_update(net_obj)
        # read back to get subnet gw allocated by api-server
        net_obj = self._vnc_lib.virtual_network_read(id=net_obj.uuid)
        fq_name_str = json.dumps(net_obj.get_fq_name())

        self._db_cache['vnc_networks'][net_obj.uuid] = net_obj
        self._db_cache['vnc_networks'][fq_name_str] = net_obj

    def _virtual_network_delete(self, net_id):
        fq_name_str = None
        try:
            net_obj = self._db_cache['vnc_networks'][net_id]
            fq_name_str = json.dumps(net_obj.get_fq_name())
        except KeyError:
            pass

        self._vnc_lib.virtual_network_delete(id=net_id)

        try:
            del self._db_cache['vnc_networks'][net_id]
            if fq_name_str:
                del self._db_cache['vnc_networks'][fq_name_str]
        except KeyError:
            pass

    def _virtual_machine_interface_create(self, port_obj):
        port_uuid = self._vnc_lib.virtual_machine_interface_create(port_obj)

        return port_uuid

    def _virtual_machine_interface_read(self, port_id=None, fq_name=None):
        if port_id:
            port_obj = self._vnc_lib.virtual_machine_interface_read(id=port_id)
            fq_name_str = json.dumps(port_obj.get_fq_name())
            self._db_cache['vnc_ports'][port_id] = port_obj
            self._db_cache['vnc_ports'][fq_name_str] = port_obj
            return port_obj

        if fq_name:
            fq_name_str = json.dumps(fq_name)
            port_obj = self._vnc_lib.virtual_machine_interface_read(
                fq_name=fq_name)
            self._db_cache['vnc_ports'][fq_name_str] = port_obj
            self._db_cache['vnc_ports'][port_obj.uuid] = port_obj
            return port_obj

    def _virtual_machine_interface_update(self, port_obj):
        self._vnc_lib.virtual_machine_interface_update(port_obj)
        fq_name_str = json.dumps(port_obj.get_fq_name())

        self._db_cache['vnc_ports'][port_obj.uuid] = port_obj
        self._db_cache['vnc_ports'][fq_name_str] = port_obj

    def _virtual_machine_interface_delete(self, port_id):
        fq_name_str = None
        try:
            port_obj = self._db_cache['vnc_ports'][port_id]
            fq_name_str = json.dumps(port_obj.get_fq_name())
        except KeyError:
            pass

        self._vnc_lib.virtual_machine_interface_delete(id=port_id)

        try:
            del self._db_cache['vnc_ports'][port_id]
            if fq_name_str:
                del self._db_cache['vnc_ports'][fq_name_str]
        except KeyError:
            pass

    def _instance_ip_create(self, iip_obj):
        iip_uuid = self._vnc_lib.instance_ip_create(iip_obj)

        return iip_uuid

    def _instance_ip_read(self, instance_ip_id=None, fq_name=None):
        if instance_ip_id:
            iip_obj = self._vnc_lib.instance_ip_read(id=instance_ip_id)
            fq_name_str = json.dumps(iip_obj.get_fq_name())
            self._db_cache['vnc_instance_ips'][instance_ip_id] = iip_obj
            self._db_cache['vnc_instance_ips'][fq_name_str] = iip_obj
            return iip_obj

        if fq_name:
            fq_name_str = json.dumps(fq_name)
            iip_obj = self._vnc_lib.instance_ip_read(fq_name=fq_name)
            self._db_cache['vnc_instance_ips'][fq_name_str] = iip_obj
            self._db_cache['vnc_instance_ips'][iip_obj.uuid] = iip_obj
            return iip_obj

    def _instance_ip_update(self, iip_obj):
        self._vnc_lib.instance_ip_update(iip_obj)
        fq_name_str = json.dumps(iip_obj.get_fq_name())

        self._db_cache['vnc_instance_ips'][iip_obj.uuid] = iip_obj
        self._db_cache['vnc_instance_ips'][fq_name_str] = iip_obj

    def _instance_ip_delete(self, instance_ip_id):
        fq_name_str = None
        try:
            iip_obj = self._db_cache['vnc_instance_ips'][instance_ip_id]
            fq_name_str = json.dumps(iip_obj.get_fq_name())
        except KeyError:
            pass

        self._vnc_lib.instance_ip_delete(id=instance_ip_id)

        try:
            del self._db_cache['vnc_instance_ips'][instance_ip_id]
            if fq_name_str:
                del self._db_cache['vnc_instance_ips'][fq_name_str]
        except KeyError:
            pass

    # find projects on a given domain
    def _project_list_domain(self, domain_id):
        fq_name = ['default-domain']
        resp_dict = self._vnc_lib.projects_list(parent_fq_name=fq_name)

        return resp_dict['projects']

    # find network ids on a given project
    def _network_list_project(self, project_id):
        try:
            project_uuid = str(uuid.UUID(project_id))
        except Exception:
            LOG.warning(_("Error in converting uuid: %r"), project_id)

        resp_dict = self._vnc_lib.virtual_networks_list(parent_id=project_uuid)

        return resp_dict['virtual-networks']

    def _security_group_list_project(self, project_id):
        try:
            project_uuid = str(uuid.UUID(project_id))
        except Exception:
            LOG.warning(_("Error in converting uuid: %r"), project_id)

        self._ensure_default_security_group_exists(project_uuid)

        resp_dict = self._vnc_lib.security_groups_list(parent_id=project_uuid)

        return resp_dict['security-groups']

    def _security_group_entries_list_sg(self, sg_id):
        try:
            sg_uuid = str(uuid.UUID(sg_id))
        except Exception:
            LOG.warning(_("Error in converting SG uuid: %r"), sg_id)

        resp_dict = self._vnc_lib.security_groups_list(parent_id=sg_uuid)

        return resp_dict['security-groups']

    # find floating ip pools a project has access to
    def _fip_pool_refs_project(self, project_id):
        project_uuid = str(uuid.UUID(project_id))
        project_obj = self._project_read(proj_id=project_uuid)

        return project_obj.get_floating_ip_pool_refs()

    # find networks of floating ip pools project has access to
    def _fip_pool_ref_networks(self, project_id):
        ret_nets = []

        proj_fip_pool_refs = self._fip_pool_refs_project(project_id)
        if not proj_fip_pool_refs:
            return ret_nets

        for fip_pool_ref in proj_fip_pool_refs:
            fip_uuid = fip_pool_ref['uuid']
            fip_pool_obj = self._vnc_lib.floating_ip_pool_read(id=fip_uuid)
            net_uuid = fip_pool_obj.parent_uuid
            net_obj = self._virtual_network_read(net_id=net_uuid)
            ret_nets.append({'uuid': net_obj.uuid,
                            'fq_name': net_obj.get_fq_name()})

        return ret_nets

    # find floating ip pools defined by network
    def _fip_pool_list_network(self, net_id):
        resp_dict = self._vnc_lib.floating_ip_pools_list(parent_id=net_id)

        return resp_dict['floating-ip-pools']

    # find port ids on a given network
    def _port_list_network(self, network_id):
        ret_list = []

        try:
            net_obj = self._virtual_network_read(net_id=network_id)
        except vnc_exc.NoIdError:
            return ret_list

        port_back_refs = net_obj.get_virtual_machine_interface_back_refs()
        if port_back_refs:
            ret_list = [{'id': port_back_ref['uuid']}
                        for port_back_ref in port_back_refs]

        return ret_list

    # find port ids on a given project
    def _port_list_project(self, project_id):
        ret_list = []
        project_nets = self._network_list_project(project_id)
        for net in project_nets:
            net_ports = self._port_list_network(net['uuid'])
            ret_list.extend(net_ports)

        return ret_list

    def _filters_is_present(self, filters, key_name, match_value):
        """Check if filters present or not.

        Returns True if no filter is specified
        OR search-param is not present in filters
        OR (search-param is present in filters AND
        resource matches param-list AND
        shared parameter in filters is False)
        """
        if filters:
            if key_name in filters:
                try:
                    filters[key_name].index(match_value)
                    if ('shared' in filters and filters['shared'][0]):
                        # yuck, q-api has shared as list always of 1 elem
                        return False  # no shared-resource support
                except ValueError:  # not in requested list
                    return False
            elif len(filters.keys()) == 1:
                shared_val = filters.get('shared')
                if shared_val and shared_val[0]:
                    return False

        return True

    def _network_read(self, net_uuid):
        net_obj = self._virtual_network_read(net_id=net_uuid)
        return net_obj

    def _subnet_vnc_create_mapping(self, subnet_id, subnet_key):
        self._vnc_lib.kv_store(subnet_id, subnet_key)
        self._vnc_lib.kv_store(subnet_key, subnet_id)
        self._db_cache['q_subnet_maps'][subnet_id] = subnet_key
        self._db_cache['q_subnet_maps'][subnet_key] = subnet_id

    def _subnet_vnc_read_mapping(self, id=None, key=None):
        if id:
            try:
                return self._db_cache['q_subnet_maps'][id]
            except KeyError:
                subnet_key = self._vnc_lib.kv_retrieve(id)
                self._db_cache['q_subnet_maps'][id] = subnet_key
                return subnet_key
        if key:
            try:
                return self._db_cache['q_subnet_maps'][key]
            except KeyError:
                subnet_id = self._vnc_lib.kv_retrieve(key)
                self._db_cache['q_subnet_maps'][key] = subnet_id
                return subnet_id

    def _subnet_vnc_read_or_create_mapping(self, id=None, key=None):
        if id:
            return self._subnet_vnc_read_mapping(id=id)

        # if subnet was created outside of neutron handle it and create
        # neutron representation now (lazily)
        try:
            return self._subnet_vnc_read_mapping(key=key)
        except vnc_exc.NoIdError:
            subnet_id = str(uuid.uuid4())
            self._subnet_vnc_create_mapping(subnet_id, key)
            return self._subnet_vnc_read_mapping(key=key)

    def _subnet_vnc_delete_mapping(self, subnet_id, subnet_key):
        self._vnc_lib.kv_delete(subnet_id)
        self._vnc_lib.kv_delete(subnet_key)
        try:
            del self._db_cache['q_subnet_maps'][subnet_id]
        except KeyError:
            pass
        try:
            del self._db_cache['q_subnet_maps'][subnet_key]
        except KeyError:
            pass

    def _subnet_vnc_get_key(self, subnet_vnc, net_id):
        pfx = subnet_vnc.subnet.get_ip_prefix()
        pfx_len = subnet_vnc.subnet.get_ip_prefix_len()

        return '%s %s/%s' % (net_id, pfx, pfx_len)

    def _subnet_read(self, net_uuid, subnet_key):
        try:
            net_obj = self._virtual_network_read(net_id=net_uuid)
        except vnc_exc.NoIdError:
            return

        ipam_refs = net_obj.get_network_ipam_refs()
        if not ipam_refs:
            return

        for ipam_ref in ipam_refs:
            subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
            for subnet_vnc in subnet_vncs:
                if self._subnet_vnc_get_key(subnet_vnc,
                                            net_uuid) == subnet_key:
                    return subnet_vnc

        return

    def _ip_address_to_subnet_id(self, ip_addr, net_obj):
        # find subnet-id for ip-addr, called when instance-ip created
        ipam_refs = net_obj.get_network_ipam_refs()
        if ipam_refs:
            for ipam_ref in ipam_refs:
                subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
                for subnet_vnc in subnet_vncs:
                    cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                                      subnet_vnc.subnet.get_ip_prefix_len())
                    if netaddr.IPAddress(ip_addr) in netaddr.IPSet([cidr]):
                        subnet_key = self._subnet_vnc_get_key(subnet_vnc,
                                                              net_obj.uuid)
                        subnet_id = self._subnet_vnc_read_mapping(
                            key=subnet_key)
                        return subnet_id

    def _security_group_vnc_to_neutron(self, sg_obj):
        sg_q_dict = self._obj_to_dict(sg_obj)

        # replace field names
        sg_q_dict['id'] = sg_obj.uuid
        sg_q_dict['tenant_id'] = sg_obj.parent_uuid.replace('-', '')
        sg_q_dict['name'] = sg_obj.name
        sg_q_dict['description'] = sg_obj.get_id_perms().get_description()

        # get security group rules
        sg_q_dict['rules'] = []
        rule_list = self.security_group_rules_read(sg_obj.uuid)
        if rule_list:
            sg_q_dict['rules'] = [rule['q_api_data']
                                  for rule in rule_list]

        return {'q_api_data': sg_q_dict}

    def _security_group_neutron_to_vnc(self, sg_q, operator):
        if operator == CREATE:
            project_id = str(uuid.UUID(sg_q['tenant_id']))
            project_obj = self._project_read(proj_id=project_id)
            id_perms = vnc_api.IdPermsType(
                enable=True, description=sg_q['description'])
            sg_vnc = vnc_api.SecurityGroup(
                name=sg_q['name'], parent_obj=project_obj,
                id_perms=id_perms)

        return sg_vnc

    def _security_group_rule_vnc_to_neutron(self, sg_id, sg_rule):
        sgr_q_dict = {}
        if sg_id is None:
            return {'q_api_data': sgr_q_dict}

        try:
            sg_obj = self._vnc_lib.security_group_read(id=sg_id)
        except vnc_exc.NoIdError:
            raise exceptions.NetworkNotFound(net_id=sg_id)

        direction = 'egress'
        if sg_rule.get_direction() == '<':
            direction = 'ingress'

        remote_cidr = ''
        remote_sg_uuid = ''
        if direction == 'ingress':
            addr = sg_rule.get_src_addresses()[0]
        else:
            addr = sg_rule.get_dst_addresses()[0]

        if addr.get_subnet():
            remote_cidr = '%s/%s' % (addr.get_subnet().get_ip_prefix(),
                                     addr.get_subnet().get_ip_prefix_len())
        elif addr.get_security_group():
            if (addr.get_security_group() != 'any') and \
                    (addr.get_security_group() != 'local'):
                remote_sg = addr.get_security_group()
                try:
                    remote_sg_obj = self._vnc_lib.security_group_read(
                        fq_name_str=remote_sg)
                    remote_sg_uuid = remote_sg_obj.uuid
                except vnc_exc.NoIdError:
                    pass

        sgr_q_dict['id'] = sg_rule.get_rule_uuid()
        sgr_q_dict['tenant_id'] = sg_obj.parent_uuid.replace('-', '')
        sgr_q_dict['security_group_id'] = sg_obj.uuid
        sgr_q_dict['ethertype'] = 'IPv4'
        sgr_q_dict['direction'] = direction
        sgr_q_dict['protocol'] = sg_rule.get_protocol()
        sgr_q_dict['port_range_min'] = sg_rule.get_dst_ports()[0].\
            get_start_port()
        sgr_q_dict['port_range_max'] = sg_rule.get_dst_ports()[0].\
            get_end_port()
        sgr_q_dict['remote_ip_prefix'] = remote_cidr
        sgr_q_dict['remote_group_id'] = remote_sg_uuid

        return {'q_api_data': sgr_q_dict}

    def _security_group_rule_neutron_to_vnc(self, sgr_q, operator):
        if operator == CREATE:
            port_min = 0
            port_max = 65535
            if sgr_q['port_range_min']:
                port_min = sgr_q['port_range_min']
            if sgr_q['port_range_max']:
                port_max = sgr_q['port_range_max']

            endpt = [vnc_api.AddressType(security_group='any')]
            if sgr_q['remote_ip_prefix']:
                cidr = sgr_q['remote_ip_prefix'].split('/')
                pfx = cidr[0]
                pfx_len = int(cidr[1])
                endpt = [vnc_api.AddressType(
                    subnet=vnc_api.SubnetType(pfx, pfx_len))]
            elif sgr_q['remote_group_id']:
                sg_obj = self._vnc_lib.security_group_read(
                    id=sgr_q['remote_group_id'])
                endpt = [vnc_api.AddressType(
                    security_group=sg_obj.get_fq_name_str())]

            if sgr_q['direction'] == 'ingress':
                dir = '<'
                local = endpt
                remote = [vnc_api.AddressType(security_group='local')]
            else:
                dir = '>'
                remote = endpt
                local = [vnc_api.AddressType(security_group='local')]

            if not sgr_q['protocol']:
                sgr_q['protocol'] = 'any'

            sgr_uuid = str(uuid.uuid4())

            rule = vnc_api.PolicyRuleType(
                rule_uuid=sgr_uuid,
                direction=dir,
                protocol=sgr_q['protocol'],
                src_addresses=local,
                src_ports=[vnc_api.PortType(0, 65535)],
                dst_addresses=remote,
                dst_ports=[vnc_api.PortType(port_min, port_max)])
            return rule

    def _network_neutron_to_vnc(self, network_q, operator):
        net_name = network_q.get('name', None)
        if operator == CREATE:
            project_id = str(uuid.UUID(network_q['tenant_id']))
            project_obj = self._project_read(proj_id=project_id)
            id_perms = vnc_api.IdPermsType(enable=True)
            net_obj = vnc_api.VirtualNetwork(
                net_name, project_obj, id_perms=id_perms)
        else:  # READ/UPDATE/DELETE
            net_obj = self._virtual_network_read(net_id=network_q['id'])

        id_perms = net_obj.get_id_perms()
        if 'admin_state_up' in network_q:
            id_perms.enable = network_q['admin_state_up']
            net_obj.set_id_perms(id_perms)

        if 'contrail:policys' in network_q:
            policy_fq_names = network_q['contrail:policys']
            # reset and add with newly specified list
            net_obj.set_network_policy_list([], [])
            seq = 0
            for p_fq_name in policy_fq_names:
                domain_name, project_name, policy_name = p_fq_name

                domain_obj = vnc_api.Domain(domain_name)
                project_obj = vnc_api.Project(project_name, domain_obj)
                policy_obj = vnc_api.NetworkPolicy(policy_name, project_obj)

                net_obj.add_network_policy(
                    policy_obj,
                    vnc_api.VirtualNetworkPolicyType(
                        sequence=vnc_api.SequenceType(seq, 0)))
                seq = seq + 1

        if 'vpc:route_table' in network_q:
            rt_fq_name = network_q['vpc:route_table']
            if rt_fq_name:
                try:
                    rt_obj = self._vnc_lib.route_table_read(fq_name=rt_fq_name)
                    net_obj.set_route_table(rt_obj)
                except vnc_exc.NoIdError:
                    raise exceptions.NetworkNotFound(net_id=net_obj.uuid)

        return net_obj

    def _network_vnc_to_neutron(self, net_obj, net_repr='SHOW'):
        net_q_dict = {}

        net_q_dict['id'] = net_obj.uuid
        net_q_dict['name'] = net_obj.name
        net_q_dict['tenant_id'] = net_obj.parent_uuid.replace('-', '')
        net_q_dict['admin_state_up'] = net_obj.get_id_perms().enable
        net_q_dict['shared'] = False
        net_q_dict['status'] = constants.NET_STATUS_ACTIVE

        ipam_refs = net_obj.get_network_ipam_refs()
        net_q_dict['subnets'] = []
        if ipam_refs:
            for ipam_ref in ipam_refs:
                subnets = ipam_ref['attr'].get_ipam_subnets()
                for subnet in subnets:
                    sn_info = self._subnet_vnc_to_neutron(subnet, net_obj,
                                                          ipam_ref['to'])
                    sn_dict = sn_info['q_api_data']
                    net_q_dict['subnets'].append(sn_dict)
                    sn_ipam = {}
                    sn_ipam['subnet_cidr'] = sn_dict['cidr']
                    sn_ipam['ipam_fq_name'] = ipam_ref['to']

        return {'q_api_data': net_q_dict}

    def _subnet_neutron_to_vnc(self, subnet_q):
        cidr = subnet_q['cidr'].split('/')
        pfx = cidr[0]
        pfx_len = int(cidr[1])
        if subnet_q['gateway_ip'] != attr.ATTR_NOT_SPECIFIED:
            default_gw = subnet_q['gateway_ip']
        else:
            # Assigned by address manager
            default_gw = None
        sub_net = vnc_api.SubnetType(ip_prefix=pfx,
                                     ip_prefix_len=pfx_len)
        subnet_vnc = vnc_api.IpamSubnetType(subnet=sub_net,
                                            default_gateway=default_gw)
        return subnet_vnc

    def _subnet_vnc_to_neutron(self, subnet_vnc, net_obj, ipam_fq_name):
        sn_q_dict = {
            'name': '',
            'tenant_id': net_obj.parent_uuid.replace('-', ''),
            'network_id': net_obj.uuid,
            'ip_version': 4,
        }

        cidr = '%s/%s' % (subnet_vnc.subnet.get_ip_prefix(),
                          subnet_vnc.subnet.get_ip_prefix_len())
        sn_q_dict['cidr'] = cidr

        subnet_key = self._subnet_vnc_get_key(subnet_vnc, net_obj.uuid)
        sn_id = self._subnet_vnc_read_or_create_mapping(key=subnet_key)

        sn_q_dict['id'] = sn_id

        sn_q_dict['gateway_ip'] = subnet_vnc.default_gateway

        first_ip = str(netaddr.IPNetwork(cidr).network + 1)
        last_ip = str(netaddr.IPNetwork(cidr).broadcast - 2)
        sn_q_dict['allocation_pools'] = [{'id': 'TODO-allocation_pools-id',
                                          'subnet_id': sn_id,
                                          'first_ip': first_ip,
                                          'last_ip': last_ip,
                                          'available_ranges': {}}]

        sn_q_dict['enable_dhcp'] = False
        sn_q_dict['dns_nameservers'] = [{'address': '169.254.169.254',
                                        'subnet_id': sn_id}]

        sn_q_dict['routes'] = [{'destination': 'TODO-destination',
                               'nexthop': 'TODO-nexthop',
                               'subnet_id': sn_id}]

        sn_q_dict['shared'] = False

        return {'q_api_data': sn_q_dict}

    def _floatingip_neutron_to_vnc(self, fip_q, operator):
        if operator == CREATE:
            # use first available pool on net
            net_id = fip_q['floating_network_id']
            fq_name = self._fip_pool_list_network(net_id)[0]['fq_name']
            fip_pool_obj = self._vnc_lib.floating_ip_pool_read(fq_name=fq_name)
            fip_name = str(uuid.uuid4())
            fip_obj = vnc_api.FloatingIp(fip_name, fip_pool_obj)
            fip_obj.uuid = fip_name

            proj_id = str(uuid.UUID(fip_q['tenant_id']))
            proj_obj = self._project_read(proj_id=proj_id)
            fip_obj.set_project(proj_obj)
        else:  # READ/UPDATE/DELETE
            fip_obj = self._vnc_lib.floating_ip_read(id=fip_q['id'])

        if fip_q['port_id']:
            port_obj = self._virtual_machine_interface_read(
                port_id=fip_q['port_id'])
            fip_obj.set_virtual_machine_interface(port_obj)
        else:
            fip_obj.set_virtual_machine_interface_list([])

        return fip_obj

    def _floatingip_vnc_to_neutron(self, fip_obj):
        fip_pool_obj = self._vnc_lib.floating_ip_pool_read(
            id=fip_obj.parent_uuid)
        net_obj = self._virtual_network_read(net_id=fip_pool_obj.parent_uuid)

        tenant_id = fip_obj.get_project_refs()[0]['uuid'].replace('-', '')

        port_id = None
        port_refs = fip_obj.get_virtual_machine_interface_refs()
        if port_refs:
            port_id = fip_obj.get_virtual_machine_interface_refs()[0]['uuid']

        fip_q_dict = {
            'id': fip_obj.uuid,
            'tenant_id': tenant_id,
            'floating_ip_address': fip_obj.get_floating_ip_address(),
            'floating_network_id': net_obj.uuid,
            'router_id': None,
            'fixed_port_id': port_id,
            'fixed_ip_address': None,
        }

        return {'q_api_data': fip_q_dict}

    def _port_neutron_to_vnc(self, port_q, net_obj, operator):
        # if name not passed in use name = uuid = <generated-uuid-val>
        if 'name' in port_q and port_q['name'] != '':
            port_name = port_q['name']
            port_uuid = None
        else:
            port_name = str(uuid.uuid4())
            port_uuid = port_name

        if operator == CREATE:
            instance_name = port_q['device_id']
            instance_obj = vnc_api.VirtualMachine(instance_name)

            id_perms = vnc_api.IdPermsType(enable=True)
            port_obj = vnc_api.VirtualMachineInterface(port_name, instance_obj,
                                                       id_perms=id_perms)
            port_obj.uuid = port_uuid
            port_obj.set_virtual_network(net_obj)

        else:  # READ/UPDATE/DELETE
            port_obj = self._virtual_machine_interface_read(
                port_id=port_q['id'])

        port_obj.set_security_group_list([])
        if ('security_groups' in port_q and
                port_q['security_groups'].__class__ is not object):
            for sg_id in port_q['security_groups']:
                sg_obj = self._vnc_lib.security_group_read(id=sg_id)
                port_obj.add_security_group(sg_obj)

        id_perms = port_obj.get_id_perms()
        if 'admin_state_up' in port_q:
            id_perms.enable = port_q['admin_state_up']
            port_obj.set_id_perms(id_perms)

        return port_obj

    def _port_vnc_to_neutron(self, port_obj, net_obj=None):
        port_q_dict = {}
        port_q_dict['name'] = port_obj.name
        port_q_dict['id'] = port_obj.uuid
        port_q_dict[portbindings.VIF_TYPE] = portbindings.VIF_TYPE_VROUTER

        if not net_obj:
            net_refs = port_obj.get_virtual_network_refs()
            if net_refs:
                net_id = net_refs[0]['uuid']
            else:
                net_id = self._vnc_lib.obj_to_id(vnc_api.VirtualNetwork())

            proj_id = None
            # not in cache, get by reading VN obj, and populate cache
            net_obj = self._virtual_network_read(net_id=net_id)
            proj_id = net_obj.parent_uuid.replace('-', '')
            self._set_obj_tenant_id(port_obj.uuid, proj_id)
        else:
            net_id = net_obj.uuid
            proj_id = net_obj.parent_uuid.replace('-', '')

        port_q_dict['tenant_id'] = proj_id
        port_q_dict['network_id'] = net_id

        port_q_dict['mac_address'] = ''
        mac_refs = port_obj.get_virtual_machine_interface_mac_addresses()
        if mac_refs:
            port_q_dict['mac_address'] = mac_refs.mac_address[0]

        port_q_dict['fixed_ips'] = []
        ip_back_refs = port_obj.get_instance_ip_back_refs()
        if ip_back_refs:
            for ip_back_ref in ip_back_refs:
                try:
                    ip_obj = self._instance_ip_read(
                        instance_ip_id=ip_back_ref['uuid'])
                except vnc_exc.NoIdError:
                    continue

                ip_addr = ip_obj.get_instance_ip_address()

                ip_q_dict = {}
                ip_q_dict['port_id'] = port_obj.uuid
                ip_q_dict['ip_address'] = ip_addr
                ip_q_dict['subnet_id'] = self._ip_address_to_subnet_id(ip_addr,
                                                                       net_obj)
                ip_q_dict['net_id'] = net_id

                port_q_dict['fixed_ips'].append(ip_q_dict)

        sg_dict = {'port_security_enabled': True}
        sg_dict['security_groups'] = []
        sg_refs = port_obj.get_security_group_refs()
        for sg_ref in sg_refs or []:
            sg_dict['security_groups'].append(sg_ref['uuid'])

        port_q_dict['admin_state_up'] = port_obj.get_id_perms().enable
        port_q_dict['status'] = constants.PORT_STATUS_ACTIVE
        port_q_dict['device_id'] = port_obj.parent_name
        port_q_dict['device_owner'] = 'TODO-device-owner'

        return {'q_api_data': port_q_dict}

    def network_create(self, network_q):
        net_obj = self._network_neutron_to_vnc(network_q, CREATE)
        net_uuid = self._virtual_network_create(net_obj)

        ret_network_q = self._network_vnc_to_neutron(net_obj, net_repr='SHOW')
        self._db_cache['q_networks'][net_uuid] = ret_network_q

        return ret_network_q

    def network_read(self, net_uuid, fields=None):
        # see if we can return fast...
        if fields and (len(fields) == 1) and fields[0] == 'tenant_id':
            tenant_id = self._get_obj_tenant_id('network', net_uuid)
            return {'q_api_data': {'id': net_uuid, 'tenant_id': tenant_id}}

        try:
            net_obj = self._network_read(net_uuid)
        except vnc_exc.NoIdError:
            raise exceptions.NetworkNotFound(net_id=net_uuid)

        return self._network_vnc_to_neutron(net_obj, net_repr='SHOW')

    def network_update(self, net_id, network_q):
        network_q['id'] = net_id
        net_obj = self._network_neutron_to_vnc(network_q, UPDATE)
        self._virtual_network_update(net_obj)

        ret_network_q = self._network_vnc_to_neutron(net_obj, net_repr='SHOW')
        self._db_cache['q_networks'][net_id] = ret_network_q

        return ret_network_q

    def network_delete(self, net_id):
        self._virtual_network_delete(net_id=net_id)
        try:
            del self._db_cache['q_networks'][net_id]
        except KeyError:
            pass

    def network_list(self, filters=None):
        ret_list = []

        if filters and 'shared' in filters:
            if filters['shared'][0]:
                # no support for shared networks
                return ret_list

        # collect phase
        all_nets = []  # all networks in all projects
        if filters and 'tenant_id' in filters:
            # project-id is present
            if 'id' in filters:
                # required networks are also specified,
                # just read and populate ret_list
                # prune is skipped because all_nets is empty
                for net_id in filters['id']:
                    net_obj = self._network_read(net_id)
                    net_info = self._network_vnc_to_neutron(net_obj,
                                                            net_repr='LIST')
                    ret_list.append(net_info)
            else:
                # read all networks in project, and prune below
                project_ids = filters['tenant_id']
                for p_id in project_ids:
                    if 'router:external' in filters:
                        all_nets.append(self._fip_pool_ref_networks(p_id))
                    else:
                        project_nets = self._network_list_project(p_id)
                        all_nets.append(project_nets)
        elif filters and 'id' in filters:
            # required networks are specified, just read and populate ret_list
            # prune is skipped because all_nets is empty
            for net_id in filters['id']:
                net_obj = self._network_read(net_id)
                net_info = self._network_vnc_to_neutron(net_obj,
                                                        net_repr='LIST')
                ret_list.append(net_info)
        else:
            # read all networks in all projects
            dom_projects = self._project_list_domain(None)
            for project in dom_projects:
                proj_id = project['uuid']
                if filters and 'router:external' in filters:
                    all_nets.append(self._fip_pool_ref_networks(proj_id))
                else:
                    project_nets = self._network_list_project(proj_id)
                    all_nets.append(project_nets)

        # prune phase
        for project_nets in all_nets:
            for proj_net in project_nets:
                proj_net_id = proj_net['uuid']
                if not self._filters_is_present(filters, 'id', proj_net_id):
                    continue

                proj_net_fq_name = unicode(proj_net['fq_name'])
                if not self._filters_is_present(filters, 'contrail:fq_name',
                                                proj_net_fq_name):
                    continue

                try:
                    net_obj = self._network_read(proj_net['uuid'])
                    net_info = self._network_vnc_to_neutron(net_obj,
                                                            net_repr='LIST')
                except vnc_exc.NoIdError:
                    continue
                ret_list.append(net_info)

        return ret_list

    def network_count(self, filters=None):
        nets_info = self.network_list(filters)
        return len(nets_info)

    def subnet_create(self, subnet_q):
        net_id = subnet_q['network_id']
        net_obj = self._virtual_network_read(net_id=net_id)

        ipam_fq_name = subnet_q['contrail:ipam_fq_name']
        if ipam_fq_name != '':
            domain_name, project_name, ipam_name = ipam_fq_name

            project_obj = vnc_api.Project(project_name)
            netipam_obj = vnc_api.NetworkIpam(ipam_name, project_obj)
        else:  # link subnet with default ipam
            project_obj = vnc_api.Project(net_obj.parent_name)
            netipam_obj = vnc_api.NetworkIpam(project_obj=project_obj)
            ipam_fq_name = netipam_obj.get_fq_name()

        subnet_vnc = self._subnet_neutron_to_vnc(subnet_q)
        subnet_key = self._subnet_vnc_get_key(subnet_vnc, net_id)

        # Locate list of subnets to which this subnet has to be appended
        net_ipam_ref = None
        ipam_refs = net_obj.get_network_ipam_refs()
        if ipam_refs:
            for ipam_ref in ipam_refs:
                if ipam_ref['to'] == ipam_fq_name:
                    net_ipam_ref = ipam_ref
                    break

        if not net_ipam_ref:
            # First link from net to this ipam
            vnsn_data = vnc_api.VnSubnetsType(ipam_subnets=[subnet_vnc])
            net_obj.add_network_ipam(netipam_obj, vnsn_data)
        else:  # virtual-network already linked to this ipam
            for subnet in net_ipam_ref['attr'].get_ipam_subnets():
                if subnet_key == self._subnet_vnc_get_key(subnet, net_id):
                    # duplicate !!
                    subnet_info = self._subnet_vnc_to_neutron(subnet,
                                                              net_obj,
                                                              ipam_fq_name)
                    return subnet_info
            vnsn_data = net_ipam_ref['attr']
            vnsn_data.ipam_subnets.append(subnet_vnc)

        self._virtual_network_update(net_obj)

        # allocate an id to the subnet and store mapping with
        # api-server
        subnet_id = str(uuid.uuid4())
        self._subnet_vnc_create_mapping(subnet_id, subnet_key)

        # Read in subnet from server to get updated values for gw etc.
        subnet_vnc = self._subnet_read(net_obj.uuid, subnet_key)
        subnet_info = self._subnet_vnc_to_neutron(subnet_vnc, net_obj,
                                                  ipam_fq_name)

        #self._db_cache['q_subnets'][subnet_id] = subnet_info

        return subnet_info

    def subnet_read(self, subnet_id):
        subnet_key = self._subnet_vnc_read_mapping(id=subnet_id)
        net_id = subnet_key.split()[0]

        net_obj = self._network_read(net_id)
        ipam_refs = net_obj.get_network_ipam_refs()
        if ipam_refs:
            for ipam_ref in ipam_refs:
                subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
                for subnet_vnc in subnet_vncs:
                    if self._subnet_vnc_get_key(subnet_vnc,
                                                net_id) == subnet_key:
                        ret_subnet_q = self._subnet_vnc_to_neutron(
                            subnet_vnc, net_obj, ipam_ref['to'])
                        self._db_cache['q_subnets'][subnet_id] = ret_subnet_q
                        return ret_subnet_q

        return {}

    def subnet_update(self, subnet_id, subnet_q):
        ret_subnet_q = self.subnet_read(subnet_id)
        if 'name' in subnet_q:
            ret_subnet_q['q_api_data']['name'] = subnet_q['name']
        return ret_subnet_q

    def subnet_delete(self, subnet_id):
        subnet_key = self._subnet_vnc_read_mapping(id=subnet_id)
        net_id = subnet_key.split()[0]

        net_obj = self._network_read(net_id)
        ipam_refs = net_obj.get_network_ipam_refs()
        if ipam_refs:
            for ipam_ref in ipam_refs:
                orig_subnets = ipam_ref['attr'].get_ipam_subnets()
                new_subnets = [subnet_vnc for subnet_vnc in orig_subnets
                               if self._subnet_vnc_get_key(subnet_vnc, net_id)
                               != subnet_key]
                if len(orig_subnets) != len(new_subnets):
                    # matched subnet to be deleted
                    ipam_ref['attr'].set_ipam_subnets(new_subnets)
                    self._virtual_network_update(net_obj)
                    self._subnet_vnc_delete_mapping(subnet_id, subnet_key)
                    try:
                        del self._db_cache['q_subnets'][subnet_id]
                    except KeyError:
                        pass

    def subnets_list(self, filters=None):
        ret_subnets = []

        if filters and 'id' in filters:
            # required subnets are specified,
            # just read in corresponding net_ids
            net_ids = set([])
            for subnet_id in filters['id']:
                subnet_key = self._subnet_vnc_read_mapping(id=subnet_id)
                net_id = subnet_key.split()[0]
                net_ids.add(net_id)
        else:
            nets_info = self.network_list()
            net_ids = [n_info['q_api_data']['id'] for n_info in nets_info]

        for net_id in net_ids:
            net_obj = self._network_read(net_id)
            ipam_refs = net_obj.get_network_ipam_refs()
            if ipam_refs:
                for ipam_ref in ipam_refs:
                    subnet_vncs = ipam_ref['attr'].get_ipam_subnets()
                    for subnet_vnc in subnet_vncs:
                        sn_info = self._subnet_vnc_to_neutron(subnet_vnc,
                                                              net_obj,
                                                              ipam_ref['to'])
                        sn_id = sn_info['q_api_data']['id']
                        sn_proj_id = sn_info['q_api_data']['tenant_id']
                        sn_net_id = sn_info['q_api_data']['network_id']

                        if filters:
                            if not self._filters_is_present(filters, 'id',
                                                            sn_id):
                                continue
                            if not self._filters_is_present(filters,
                                                            'tenant_id',
                                                            sn_proj_id):
                                continue
                            if not self._filters_is_present(filters,
                                                            'network_id',
                                                            sn_net_id):
                                continue

                        ret_subnets.append(sn_info)

        return ret_subnets

    def subnets_count(self, filters=None):
        subnets_info = self.subnets_list(filters)
        return len(subnets_info)

    # floatingip api handlers
    def floatingip_create(self, fip_q):
        fip_obj = self._floatingip_neutron_to_vnc(fip_q, CREATE)
        fip_uuid = self._vnc_lib.floating_ip_create(fip_obj)
        fip_obj = self._vnc_lib.floating_ip_read(id=fip_uuid)

        return self._floatingip_vnc_to_neutron(fip_obj)

    def floatingip_read(self, fip_uuid):
        fip_obj = self._vnc_lib.floating_ip_read(id=fip_uuid)

        return self._floatingip_vnc_to_neutron(fip_obj)

    def floatingip_update(self, fip_id, fip_q):
        fip_q['id'] = fip_id
        fip_obj = self._floatingip_neutron_to_vnc(fip_q, UPDATE)
        self._vnc_lib.floating_ip_update(fip_obj)

        return self._floatingip_vnc_to_neutron(fip_obj)

    def floatingip_delete(self, fip_id):
        self._vnc_lib.floating_ip_delete(id=fip_id)

    def floatingip_list(self, filters=None):
        # Find networks, get floatingip backrefs and return
        ret_list = []

        if filters:
            if 'tenant_id' in filters:
                proj_ids = [str(uuid.UUID(id)) for id in filters['tenant_id']]
            elif 'port_id' in filters:
                # required ports are specified, just read and populate ret_list
                # prune is skipped because proj_objs is empty
                proj_ids = []
                for port_id in filters['port_id']:
                    port_obj = self._virtual_machine_interface_read(
                        port_id=port_id)
                    fip_back_refs = port_obj.get_floating_ip_back_refs()
                    if not fip_back_refs:
                        continue
                    for fip_back_ref in fip_back_refs:
                        fip_obj = self._vnc_lib.floating_ip_read(
                            id=fip_back_ref['uuid'])
                        ret_list.append(self._floatingip_vnc_to_neutron(
                            fip_obj))
        else:  # no filters
            dom_projects = self._project_list_domain(None)
            proj_ids = [proj['uuid'] for proj in dom_projects]

        proj_objs = [self._project_read(proj_id=id) for id in proj_ids]

        for proj_obj in proj_objs:
            fip_back_refs = proj_obj.get_floating_ip_back_refs()
            if not fip_back_refs:
                continue
            for fip_back_ref in fip_back_refs:
                fip_obj = self._vnc_lib.floating_ip_read(
                    id=fip_back_ref['uuid'])
                ret_list.append(self._floatingip_vnc_to_neutron(fip_obj))

        return ret_list

    def floatingip_count(self, filters=None):
        floatingip_info = self.floatingip_list(filters)
        return len(floatingip_info)

    # port api handlers
    def port_create(self, port_q):
        net_id = port_q['network_id']
        net_obj = self._network_read(net_id)
        proj_id = net_obj.parent_uuid

        self._ensure_instance_exists(port_q['device_id'])

        # initialize port object
        port_obj = self._port_neutron_to_vnc(port_q, net_obj, CREATE)

        # if ip address passed then use it
        ip_addr = None
        ip_obj = None
        if port_q['fixed_ips'].__class__ is not object:
            ip_addr = port_q['fixed_ips'][0]['ip_address']
            ip_name = '%s %s' % (net_id, ip_addr)
            try:
                ip_obj = self._instance_ip_read(fq_name=[ip_name])
                #ip_id = ip_obj.uuid
            except Exception as e:
                ip_obj = None

        # create the object
        port_id = self._virtual_machine_interface_create(port_obj)

        # initialize ip object
        if ip_obj is None:
            # Allocate an IP address only if there is a defined subnet
            if net_obj.get_network_ipam_refs():
                ip_name = str(uuid.uuid4())
                ip_obj = vnc_api.InstanceIp(name=ip_name)
                ip_obj.uuid = ip_name
                ip_obj.set_virtual_machine_interface(port_obj)
                ip_obj.set_virtual_network(net_obj)
                if ip_addr:
                    ip_obj.set_instance_ip_address(ip_addr)
                try:
                    self._instance_ip_create(ip_obj)
                except Exception as e:
                    # ResourceExhaustionError, resources are not available
                    self._virtual_machine_interface_delete(port_id=port_id)
                    raise e
        # shared ip address
        else:
            if ip_addr == ip_obj.get_instance_ip_address():
                ip_obj.add_virtual_machine_interface(port_obj)
                self._instance_ip_update(ip_obj)

        port_obj = self._virtual_machine_interface_read(port_id=port_id)

        ret_port_q = self._port_vnc_to_neutron(port_obj, net_obj)
        #self._db_cache['q_ports'][port_id] = ret_port_q
        self._set_obj_tenant_id(port_id, proj_id)

        # update cache on successful creation
        tenant_id = proj_id.replace('-', '')
        if tenant_id not in self._db_cache['q_tenant_port_count']:
            ncurports = self.port_count({'tenant_id': tenant_id})
        else:
            ncurports = self._db_cache['q_tenant_port_count'][tenant_id]

        self._db_cache['q_tenant_port_count'][tenant_id] = ncurports + 1

        return ret_port_q

    def port_read(self, port_id):
        port_obj = self._virtual_machine_interface_read(port_id=port_id)

        ret_port_q = self._port_vnc_to_neutron(port_obj)
        self._db_cache['q_ports'][port_id] = ret_port_q

        return ret_port_q

    def port_update(self, port_id, port_q):
        port_q['id'] = port_id
        port_obj = self._port_neutron_to_vnc(port_q, None, UPDATE)
        self._virtual_machine_interface_update(port_obj)

        ret_port_q = self._port_vnc_to_neutron(port_obj)
        self._db_cache['q_ports'][port_id] = ret_port_q

        return ret_port_q

    def port_delete(self, port_id):
        port_obj = self._port_neutron_to_vnc({'id': port_id}, None, READ)
        instance_id = port_obj.parent_uuid

        # release instance IP address
        iip_back_refs = port_obj.get_instance_ip_back_refs()
        if iip_back_refs:
            for iip_back_ref in iip_back_refs:
                # if name contains IP address then this is shared ip
                iip_obj = self._vnc_lib.instance_ip_read(
                    id=iip_back_ref['uuid'])
                name = iip_obj.name
                if len(name.split(' ')) > 1:
                    name = name.split(' ')[1]

                # in case of shared ip only delete the link to the VMI
                try:
                    socket.inet_aton(name)
                    iip_obj.del_virtual_machine_interface(port_obj)
                    self._instance_ip_update(iip_obj)
                except socket.error:
                    self._instance_ip_delete(
                        instance_ip_id=iip_back_ref['uuid'])

        # disassociate any floating IP used by instance
        fip_back_refs = port_obj.get_floating_ip_back_refs()
        if fip_back_refs:
            for fip_back_ref in fip_back_refs:
                fip_obj = self._vnc_lib.floating_ip_read(
                    id=fip_back_ref['uuid'])
                self.floatingip_update(fip_obj.uuid, {'port_id': None})

        self._virtual_machine_interface_delete(port_id=port_id)

        # delete instance if this was the last port
        inst_obj = self._vnc_lib.virtual_machine_read(id=instance_id)
        inst_intfs = inst_obj.get_virtual_machine_interfaces()
        if not inst_intfs:
            self._vnc_lib.virtual_machine_delete(id=inst_obj.uuid)

        try:
            del self._db_cache['q_ports'][port_id]
        except KeyError:
            pass

        # update cache on successful deletion
        try:
            tenant_id = self._get_obj_tenant_id('port', port_id)
            self._db_cache['q_tenant_port_count'][tenant_id] = \
                self._db_cache['q_tenant_port_count'][tenant_id] - 1
        except KeyError:
            pass

        self._del_obj_tenant_id(port_id)

    def port_list(self, filters=None):
        ret_q_ports = []
        all_project_ids = []

        if 'device_owner' in filters:
            return ret_q_ports

        if 'device_id' not in filters:
            # Listing from back references
            if not filters:
                # no filters => return all ports!
                all_projects = self._project_list_domain(None)
                all_project_ids = [project['uuid'] for project in all_projects]
            elif 'tenant_id' in filters:
                all_project_ids = filters.get('tenant_id')

            for proj_id in all_project_ids:
                proj_ports = self._port_list_project(proj_id)
                for port in proj_ports:
                    try:
                        port_info = self.port_read(port['id'])
                    except vnc_exc.NoIdError:
                        continue
                    ret_q_ports.append(port_info)

            for net_id in filters.get('network_id', []):
                net_ports = self._port_list_network(net_id)
                for port in net_ports:
                    port_info = self.port_read(port['id'])
                    ret_q_ports.append(port_info)

            return ret_q_ports

        # Listing from parent to children
        virtual_machine_ids = filters['device_id']
        for vm_id in virtual_machine_ids:
            resp_dict = self._vnc_lib.virtual_machine_interfaces_list(
                parent_id=vm_id)
            vm_intf_ids = resp_dict['virtual-machine-interfaces']
            for vm_intf in vm_intf_ids:
                try:
                    port_info = self.port_read(vm_intf['uuid'])
                except vnc_exc.NoIdError:
                    continue
                ret_q_ports.append(port_info)

        return ret_q_ports

    def port_count(self, filters=None):
        if 'device_owner' in filters:
            return 0

        if 'tenant_id' in filters:
            project_id = filters['tenant_id'][0]
            try:
                return self._db_cache['q_tenant_port_count'][project_id]
            except KeyError:
                # do it the hard way but remember for next time
                nports = len(self._port_list_project(project_id))
                self._db_cache['q_tenant_port_count'][project_id] = nports
        else:
            # across all projects
            # get only a count from api-server!
            nports = len(self.port_list(filters))

        return nports

    # security group api handlers
    def security_group_create(self, sg_q):
        sg_obj = self._security_group_neutron_to_vnc(sg_q, CREATE)
        sg_uuid = self._security_group_create(sg_obj)

        #allow all egress traffic
        def_rule = {
            'port_range_min': 0,
            'port_range_max': 65535,
            'direction': 'egress',
            'remote_ip_prefix': None,
            'remote_group_id': None,
            'protocol': 'any',
        }
        rule = self._security_group_rule_neutron_to_vnc(def_rule, CREATE)
        self._security_group_rule_create(sg_uuid, rule)

        ret_sg_q = self._security_group_vnc_to_neutron(sg_obj)
        return ret_sg_q

    def security_group_read(self, sg_id):
        try:
            sg_obj = self._vnc_lib.security_group_read(id=sg_id)
        except vnc_exc.NoIdError:
            raise exceptions.NetworkNotFound(net_id=sg_id)

        return self._security_group_vnc_to_neutron(sg_obj)

    def security_group_delete(self, sg_id):
        self._security_group_delete(sg_id)

    def security_group_list(self, context, filters=None):
        ret_list = []

        # all_sgs[]  all sgs in all projects
        # collect phase
        if filters and 'tenant_id' in filters:
            project_ids = filters['tenant_id']
            all_sgs = [self._security_group_list_project(p_id) for
                       p_id in project_ids]
        elif filters and 'name' in filters:
            all_sgs = [self._security_group_list_project(
                       str(uuid.UUID(context.tenant)))]
        else:  # no filters
            dom_projects = self._project_list_domain(None)
            all_sgs = [self._security_group_list_project(project['uuid']) for
                       project in dom_projects]

        # prune phase
        for project_sgs in all_sgs:
            for proj_sg in project_sgs:
                proj_sg_id = proj_sg['uuid']
                if not self._filters_is_present(filters, 'id', proj_sg_id):
                    continue
                sg_info = self.security_group_read(proj_sg_id)
                if not self._filters_is_present(filters, 'name',
                                                sg_info['q_api_data']['name']):
                    continue
                ret_list.append(sg_info)

        return ret_list

    def security_group_rule_create(self, sgr_q):
        sg_id = sgr_q['security_group_id']
        sg_rule = self._security_group_rule_neutron_to_vnc(sgr_q, CREATE)
        self._security_group_rule_create(sg_id, sg_rule)
        ret_sg_rule_q = self._security_group_rule_vnc_to_neutron(sg_id,
                                                                 sg_rule)

        return ret_sg_rule_q

    def security_group_rule_read(self, sgr_id):
        sg_obj, sg_rule = self._security_group_rule_find(sgr_id)
        if sg_obj and sg_rule:
            return self._security_group_rule_vnc_to_neutron(sg_obj.uuid,
                                                            sg_rule)

        return {}

    def security_group_rule_delete(self, sgr_id):
        sg_obj, sg_rule = self._security_group_rule_find(sgr_id)
        if sg_obj and sg_rule:
            return self._security_group_rule_delete(sg_obj, sg_rule)

    def security_group_rules_read(self, sg_id):
        try:
            sg_obj = self._vnc_lib.security_group_read(id=sg_id)
            sgr_entries = sg_obj.get_security_group_entries()
            if sgr_entries is None:
                return

            sg_rules = [self._security_group_rule_vnc_to_neutron(
                sg_obj.uuid, sg_rule) for
                sg_rule in sgr_entries.get_policy_rule()]
        except vnc_exc.NoIdError:
            raise exceptions.NetworkNotFound(net_id=sg_id)

        return sg_rules

    def security_group_rule_list(self, filters=None):
        ret_list = []

        # collect phase
        if filters and 'tenant_id' in filters:
            project_ids = filters['tenant_id']
            all_sgs = [self._security_group_list_project(p_id) for
                       p_id in project_ids]
        else:  # no filters
            dom_projects = self._project_list_domain(None)
            all_sgs = [self._security_group_list_project(project['uuid'])
                       for project in dom_projects]

        # prune phase
        for project_sgs in all_sgs:
            ret_list.extend(
                self.security_group_rules_read(proj_sg['uuid'])
                for proj_sg in project_sgs
                if self._filters_is_present(filters, 'id', proj_sg['uuid'])
            )

        return ret_list
