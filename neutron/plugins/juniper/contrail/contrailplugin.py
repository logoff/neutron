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

import ctdb.config_db
import httplib2
from oslo.config import cfg
import re
import string

from neutron.common import exceptions as exc
from neutron.db import db_base_plugin_v2
from neutron.db import portbindings_base
from neutron.extensions import l3
from neutron.extensions import securitygroup
from neutron.extensions import portbindings
from neutron.openstack.common import log as logging


LOG = logging.getLogger(__name__)

vnc_opts = [
    cfg.StrOpt('api_server_ip', default='127.0.0.1'),
    cfg.StrOpt('api_server_port', default='8082'),
]


def _read_cfg(multi_parser, section, option, default):
        name_tuple = (section, option)
        cfg_names = []
        cfg_names.append(name_tuple)
        try:
            val = multi_parser.get(names=cfg_names, multi=False)
        except KeyError:
            val = default

        return val


class ContrailPlugin(db_base_plugin_v2.NeutronDbPluginV2,
                     l3.RouterPluginBase,
                     securitygroup.SecurityGroupPluginBase,
                     portbindings_base.PortBindingBaseMixin):

    # only floatingip part of router extension is supported.
    supported_extension_aliases = ["ipam", "policy", "security-group",
                                   "router", "route-table", "port-security",
                                   "binding",]
    __native_bulk_support = False
    _cfgdb = None
    _args = None
    _tenant_id_dict = {}
    _tenant_name_dict = {}

    @classmethod
    def _parse_class_args(cls, multi_parser):
        read_ok = multi_parser.read(cfg.CONF.config_file)

        if len(read_ok) != len(cfg.CONF.config_file):
            raise cfg.Error("Some config files were not parsed properly")

        cls._multi_tenancy = _read_cfg(multi_parser, 'APISERVER',
                                       'multi_tenancy', False)
        cls._max_retries = _read_cfg(multi_parser, 'APISERVER',
                                     'max_retries', -1)
        cls._retry_interval = _read_cfg(multi_parser, 'APISERVER',
                                        'retry_interval', 3)
        cls._admin_token = _read_cfg(multi_parser, 'KEYSTONE',
                                     'admin_token', '')
        cls._auth_url = _read_cfg(multi_parser, 'KEYSTONE', 'auth_url', '')
        cls._admin_user = _read_cfg(multi_parser, 'KEYSTONE', 'admin_user',
                                    'user1')
        cls._admin_password = _read_cfg(multi_parser, 'KEYSTONE',
                                        'admin_password', 'password1')
        cls._admin_tenant_name = _read_cfg(multi_parser, 'KEYSTONE',
                                           'admin_tenant_name',
                                           'default-domain')
        cls._tenants_api = '%s/tenants' % (cls._auth_url)

    @classmethod
    def _connect_to_db(cls):
        """Connection to config db.

        Many instantiations of plugin (base + extensions) but need to have
        only one config db conn (else error from ifmap-server)
        """
        cls._cfgdb_map = {}
        if cls._cfgdb is None:
            sip = cfg.CONF.APISERVER.api_server_ip
            sport = cfg.CONF.APISERVER.api_server_port
            # Initialize connection to DB and add default entries
            cls._cfgdb = ctdb.config_db.DBInterface(cls._admin_user,
                                                    cls._admin_password,
                                                    cls._admin_tenant_name,
                                                    sip, sport,
                                                    cls._max_retries,
                                                    cls._retry_interval)
            cls._cfgdb.manager = cls

    @classmethod
    def _get_user_cfgdb(cls, context):
        if not cls._multi_tenancy:
            return cls._cfgdb
        user_id = context.user_id
        role = string.join(context.roles, ",")
        if user_id not in cls._cfgdb_map:
            cls._cfgdb_map[user_id] = ctdb.config_db.DBInterface(
                cls._admin_user, cls._admin_password, cls._admin_tenant_name,
                cfg.CONF.APISERVER.api_server_ip,
                cfg.CONF.APISERVER.api_server_port,
                cls._max_retries, cls._retry_interval,
                user_info={'user_id': user_id, 'role': role})
            cls._cfgdb_map[user_id].manager = cls

        return cls._cfgdb_map[user_id]

    @classmethod
    def _tenant_list_from_keystone(cls):
        # get all tenants
        hdrs = {'X-Auth-Token': cls._admin_token,
                'Content-Type': 'application/json'}
        try:
            rsp, content = httplib2.Http().request(cls._tenants_api,
                                                   method="GET", headers=hdrs)
            if rsp.status != 200:
                return
        except Exception:
            return

        # transform needed for python compatibility
        content = re.sub('true', 'True', content)
        content = re.sub('null', 'None', content)
        content = eval(content)

        # bail if response is unexpected
        if 'tenants' not in content:
            return

        # create a dictionary for id->name and name->id mapping
        for tenant in content['tenants']:
            print 'Adding tenant %s:%s to cache' % (tenant['name'],
                                                    tenant['id'])
            cls._tenant_id_dict[tenant['id']] = tenant['name']
            cls._tenant_name_dict[tenant['name']] = tenant['id']

    def update_security_group(self, context, id, security_group):
        pass

    def __init__(self):
        cfg.CONF.register_opts(vnc_opts, 'APISERVER')

        multi_parser = cfg.MultiConfigParser()
        ContrailPlugin._parse_class_args(multi_parser)

        ContrailPlugin._connect_to_db()
        self._cfgdb = ContrailPlugin._cfgdb

        ContrailPlugin._tenant_list_from_keystone()
        self.base_binding_dict = self._get_base_binding_dict()
        portbindings_base.register_port_dict_function()

    def _get_base_binding_dict(self):
        binding = {
            portbindings.VIF_TYPE: portbindings.VIF_TYPE_VROUTER,
            portbindings.CAPABILITIES: {
                portbindings.CAP_PORT_FILTER:
                'security-group' in self.supported_extension_aliases}}
        return binding

    # Network API handlers
    def create_network(self, context, network):
        """Creates a new Virtual Network, and assigns it a symbolic name."""
        cfgdb = self._get_user_cfgdb(context)
        net_info = cfgdb.network_create(network['network'])

        # verify transformation is conforming to api
        net_dict = self._make_network_dict(net_info['q_api_data'],
                                           None, False)

        LOG.debug(_("create_network(): %r"), net_dict)
        return net_dict

    def get_network(self, context, id, fields=None):
        cfgdb = self._get_user_cfgdb(context)
        net_info = cfgdb.network_read(id, fields)

        # verify transformation is conforming to api
        if not fields:
            # should return all fields
            net_dict = self._make_network_dict(net_info['q_api_data'],
                                               fields, False)
        else:
            net_dict = net_info['q_api_data']

        LOG.debug(_("get_network(): %r"), net_dict)
        return self._fields(net_dict, fields)

    def update_network(self, context, net_id, network):
        """Updates the attributes of a particular Virtual Network."""
        cfgdb = self._get_user_cfgdb(context)
        net_info = cfgdb.network_update(net_id, network['network'])

        # verify transformation is confirming to api
        net_dict = self._make_network_dict(net_info['q_api_data'],
                                           None, False)

        LOG.debug(_("update_network(): %r"), net_dict)
        return net_dict

    def delete_network(self, context, net_id):
        """Network delete operation.

        Deletes the network with the specified network identifier
        belonging to the specified tenant.
        """
        cfgdb = self._get_user_cfgdb(context)
        cfgdb.network_delete(net_id)
        LOG.debug(_("delete_network(): %r"), net_id)

    def get_networks(self, context, filters=None, fields=None):
        cfgdb = self._get_user_cfgdb(context)
        nets_info = cfgdb.network_list(filters)

        nets_dicts = []
        for n_info in nets_info:
            # verify transformation is conforming to api
            n_dict = self._make_network_dict(n_info['q_api_data'], fields,
                                             False)

            nets_dicts.append(n_dict)

        LOG.debug(
            "get_networks(): filters: %r data: %r", filters, nets_dicts)
        return nets_dicts

    def get_networks_count(self, context, filters=None):
        cfgdb = self._get_user_cfgdb(context)
        nets_count = cfgdb.network_count(filters)
        LOG.debug(_("get_networks_count(): %r"), str(nets_count))
        return nets_count

    def create_subnet(self, context, subnet):
        cfgdb = self._get_user_cfgdb(context)
        subnet_info = cfgdb.subnet_create(subnet['subnet'])

        # verify transformation is conforming to api
        subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'])

        LOG.debug(_("create_subnet(): %r"), subnet_dict)
        return subnet_dict

    def get_subnet(self, context, subnet_id, fields=None):
        cfgdb = self._get_user_cfgdb(context)
        subnet_info = cfgdb.subnet_read(subnet_id)

        # verify transformation is conforming to api
        subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'],
                                             fields)

        LOG.debug(_("get_subnet(): %r"), subnet_dict)
        return self._fields(subnet_dict, fields)

    def update_subnet(self, context, subnet_id, subnet):
        cfgdb = self._get_user_cfgdb(context)
        subnet_info = cfgdb.subnet_update(subnet_id, subnet['subnet'])

        # verify transformation is conforming to api
        subnet_dict = self._make_subnet_dict(subnet_info['q_api_data'])

        LOG.debug(_("update_subnet(): %r"), subnet_dict)
        return subnet_dict

    def delete_subnet(self, context, subnet_id):
        cfgdb = self._get_user_cfgdb(context)
        cfgdb.subnet_delete(subnet_id)

        LOG.debug(_("delete_subnet(): %r"), subnet_id)

    def get_subnets(self, context, filters=None, fields=None):
        """Called from Neutron API -> get_<resource>."""
        cfgdb = self._get_user_cfgdb(context)
        subnets_info = cfgdb.subnets_list(filters)

        subnets_dicts = []
        for sn_info in subnets_info:
            # verify transformation is conforming to api
            sn_dict = self._make_subnet_dict(sn_info['q_api_data'], fields)

            subnets_dicts.append(sn_dict)

        LOG.debug(
            "get_subnets(): filters: %r data: %r", filters, subnets_dicts)
        return subnets_dicts

    def get_subnets_count(self, context, filters=None):
        cfgdb = self._get_user_cfgdb(context)
        subnets_count = cfgdb.subnets_count(filters)
        LOG.debug(_("get_subnets_count(): %r"), str(subnets_count))
        return subnets_count

    def _make_floatingip_dict(self, floatingip, fields=None):
        res = {'id': floatingip['id'],
               'tenant_id': floatingip['tenant_id'],
               'floating_ip_address': floatingip['floating_ip_address'],
               'floating_network_id': floatingip['floating_network_id'],
               'router_id': floatingip['router_id'],
               'port_id': floatingip['fixed_port_id'],
               'fixed_ip_address': floatingip['fixed_ip_address']}
        return self._fields(res, fields)

    def create_floatingip(self, context, floatingip):
        cfgdb = self._get_user_cfgdb(context)
        fip_info = cfgdb.floatingip_create(floatingip['floatingip'])

        # verify transformation is conforming to api
        fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

        LOG.debug(_("create_floatingip(): %r"), fip_dict)
        return fip_dict

    def update_floatingip(self, context, fip_id, floatingip):
        cfgdb = self._get_user_cfgdb(context)
        fip_info = cfgdb.floatingip_update(fip_id,
                                           floatingip['floatingip'])

        # verify transformation is conforming to api
        fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

        LOG.debug(_("update_floatingip(): %r"), fip_dict)
        return fip_dict

    def get_floatingip(self, context, id, fields=None):
        cfgdb = self._get_user_cfgdb(context)
        fip_info = cfgdb.floatingip_read(id)

        # verify transformation is conforming to api
        fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

        LOG.debug(_("get_floatingip(): %r"), fip_dict)
        return fip_dict

    def delete_floatingip(self, context, fip_id):
        cfgdb = self._get_user_cfgdb(context)
        cfgdb.floatingip_delete(fip_id)
        LOG.debug(_("delete_floating(): %r"), fip_id)

    def get_floatingips(self, context, filters=None, fields=None):
        cfgdb = self._get_user_cfgdb(context)
        fips_info = cfgdb.floatingip_list(filters)

        fips_dicts = []
        for fip_info in fips_info:
            # verify transformation is conforming to api
            fip_dict = self._make_floatingip_dict(fip_info['q_api_data'])

            fips_dicts.append(fip_dict)

        LOG.debug(_("get_floatingips(): %r"), fips_dicts)
        return fips_dicts

    def get_floatingips_count(self, context, filters=None):
        cfgdb = self._get_user_cfgdb(context)
        floatingips_count = cfgdb.floatingip_count(filters)
        LOG.debug(_("get_floatingips_count(): %r"), str(floatingips_count))
        return floatingips_count

    def create_port(self, context, port):
        """Creates a port on the specified Virtual Network."""
        cfgdb = self._get_user_cfgdb(context)
        port_info = cfgdb.port_create(port['port'])

        # verify transformation is conforming to api
        port_dict = self._make_port_dict(port_info['q_api_data'])
        self._process_portbindings_create_and_update(context,
                                                     port['port'],
                                                     port_dict)

        LOG.debug(_("create_port(): %r"), port_dict)
        return port_dict

    def get_port(self, context, port_id, fields=None):
        cfgdb = self._get_user_cfgdb(context)
        port_info = cfgdb.port_read(port_id)

        # verify transformation is conforming to api
        port_dict = self._make_port_dict(port_info['q_api_data'], fields)
        self._process_portbindings_create_and_update(context,
                                                     port_info,
                                                     port_dict)

        LOG.debug(_("get_port(): %r"), port_dict)
        return self._fields(port_dict, fields)

    def update_port(self, context, port_id, port):
        """Port update on a virtual network.

        Updates the attributes of a port on the specified Virtual Network.
        """
        cfgdb = self._get_user_cfgdb(context)
        port_info = cfgdb.port_update(port_id, port['port'])
        self._process_portbindings_create_and_update(context,
                                                     port['port'],
                                                     port_info)

        # verify transformation is conforming to api
        port_dict = self._make_port_dict(port_info['q_api_data'])

        LOG.debug(_("update_port(): %r"), port_dict)
        return port_dict

    def delete_port(self, context, port_id):
        """port delete on a virtual network.

        Deletes a port on a specified Virtual Network,
        if the port contains a remote interface attachment,
        the remote interface is first un-plugged and then the port
        is deleted.
        """
        cfgdb = self._get_user_cfgdb(context)
        cfgdb.port_delete(port_id)
        LOG.debug(_("delete_port(): %r"), port_id)

    def get_ports(self, context, filters=None, fields=None):
        """Get all port identifiers in the specified Virtual Network."""
        cfgdb = self._get_user_cfgdb(context)
        ports_info = cfgdb.port_list(filters)

        ports_dicts = []
        for p_info in ports_info:
            # verify transformation is conforming to api
            p_dict = self._make_port_dict(p_info['q_api_data'], fields)
            self._process_portbindings_create_and_update(context,
                                                         p_info,
                                                         p_dict)

            ports_dicts.append(p_dict)

        LOG.debug(
            "get_ports(): filter: %r data: %r", filters, ports_dicts)
        return ports_dicts

    def get_ports_count(self, context, filters=None):
        cfgdb = self._get_user_cfgdb(context)
        ports_count = cfgdb.port_count(filters)
        LOG.debug(_("get_ports_count(): %r"), str(ports_count))
        return ports_count

    def plug_interface(self, tenant_id, net_id, port_id, remote_interface_id):
        """Plug in a remote interface.

        Attaches a remote interface to the specified port on the
        specified Virtual Network.
        """
        port = self._get_port(tenant_id, net_id, port_id)
        # Validate attachment
        self._validate_attachment(tenant_id, net_id, port_id,
                                  remote_interface_id)
        if port['interface_id']:
            raise exc.PortInUse(net_id=net_id, port_id=port_id,
                                att_id=port['interface_id'])

    def unplug_interface(self, tenant_id, net_id, port_id):
        """Unplug a remote interface.

        Detaches a remote interface from the specified port on the
        specified Virtual Network.
        """
        self._get_port(tenant_id, net_id, port_id)

    # Security Group handlers
    def _make_security_group_rule_dict(self, security_group_rule, fields=None):
        res = {'id': security_group_rule['id'],
               'tenant_id': security_group_rule['tenant_id'],
               'security_group_id': security_group_rule['security_group_id'],
               'ethertype': security_group_rule['ethertype'],
               'direction': security_group_rule['direction'],
               'protocol': security_group_rule['protocol'],
               'port_range_min': security_group_rule['port_range_min'],
               'port_range_max': security_group_rule['port_range_max'],
               'remote_ip_prefix': security_group_rule['remote_ip_prefix'],
               'remote_group_id': security_group_rule['remote_group_id']}

        return self._fields(res, fields)

    def _make_security_group_dict(self, security_group, fields=None):
        res = {'id': security_group['id'],
               'name': security_group['name'],
               'tenant_id': security_group['tenant_id'],
               'description': security_group['description']}
        res['security_group_rules'] = [self._make_security_group_rule_dict(r)
                                       for r in security_group['rules']]
        return self._fields(res, fields)

    def create_security_group(self, context, security_group):
        cfgdb = self._get_user_cfgdb(context)
        sg_info = cfgdb.security_group_create(
            security_group['security_group'])

        # verify transformation is conforming to api
        sg_dict = self._make_security_group_dict(sg_info['q_api_data'])

        LOG.debug(_("create_security_group(): %r"), sg_dict)
        return sg_dict

    def delete_security_group(self, context, id):
        cfgdb = self._get_user_cfgdb(context)
        cfgdb.security_group_delete(id)
        LOG.debug(_("delete_security_group(): %r"), id)

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        cfgdb = self._get_user_cfgdb(context)
        security_groups_info = cfgdb.security_group_list(context, filters)

        security_groups_dicts = []
        for sg_info in security_groups_info:
            # verify transformation is conforming to api
            sg_dict = self._make_security_group_dict(sg_info['q_api_data'],
                                                     fields)

            security_groups_dicts.append(sg_dict)

        LOG.debug(
            "get_security_groups(): filter: %r data: %r",
            filters, security_groups_dicts)
        return security_groups_dicts

    def get_security_group(self, context, id, fields=None):
        cfgdb = self._get_user_cfgdb(context)
        sg_info = cfgdb.security_group_read(id)

        # verify transformation is conforming to api
        sg_dict = self._make_security_group_dict(sg_info['q_api_data'],
                                                 fields)

        LOG.debug(_("get_security_group(): %r"), sg_dict)
        return self._fields(sg_dict, fields)

    def create_security_group_rule(self, context, security_group_rule):
        cfgdb = self._get_user_cfgdb(context)
        sgr_info = cfgdb.security_group_rule_create(
            security_group_rule['security_group_rule'])

        # verify transformation is conforming to api
        sgr_dict = self._make_security_group_rule_dict(sgr_info['q_api_data'])

        LOG.debug(_("create_security_group_rule(): %r"), sgr_dict)
        return sgr_dict

    def delete_security_group_rule(self, context, id):
        cfgdb = self._get_user_cfgdb(context)
        cfgdb.security_group_rule_delete(id)
        LOG.debug(_("delete_security_group_rule(): %r"), id)

    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        cfgdb = self._get_user_cfgdb(context)
        security_group_rules_info = cfgdb.security_group_rule_list(filters)

        security_group_rules_dicts = []
        for sgr_info in security_group_rules_info:
            for sgr in sgr_info:
                # verify transformation is conforming to api
                sgr_dict = self._make_security_group_rule_dict(
                    sgr['q_api_data'], fields)
                security_group_rules_dicts.append(sgr_dict)

        LOG.debug(
            "get_security_group_rules(): filter: %r data: %r ",
            filters, security_group_rules_dicts)
        return security_group_rules_dicts

    def get_security_group_rule(self, context, id, fields=None):
        cfgdb = self._get_user_cfgdb(context)
        sgr_info = cfgdb.security_group_rule_read(id)

        # verify transformation is conforming to api
        sgr_dict = {}
        if sgr_info != {}:
            sgr_dict = self._make_security_group_rule_dict(
                sgr_info['q_api_data'], fields)

        LOG.debug(_("get_security_group_rule(): %r"), sgr_dict)
        return self._fields(sgr_dict, fields)
