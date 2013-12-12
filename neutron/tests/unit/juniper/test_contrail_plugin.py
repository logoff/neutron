# Copyright (c) 2012 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import mock
import sys
import uuid

import neutron.db.api
from neutron.manager import NeutronManager
from neutron.tests.unit import test_db_plugin as test_plugin


subnet_obj = {u'subnet':
              {'name': '', 'enable_dhcp': True,
               u'network_id': u'b11ffca3-3dfc-435e-ae0e-8f44da7188b7',
               'tenant_id': u'8162e75da480419a8b2ae7088dbc14f5',
               'dns_nameservers': '',
               u'contrail:ipam_fq_name':
               [u'default-domain', u'admin', u'default-network-ipam'],
               'allocation_pools': '', 'host_routes': '', u'ip_version': 4,
               'gateway_ip': '', u'cidr': u'20.20.1.0/29'}}

vn_list = []
GlobalProjects = []


class MockVncApi(mock.MagicMock):
    def __init__(self, *args, **kwargs):
        pass

    def kv_retrieve(self, *args, **kwargs):
        return []

    def kv_store(self, *args, **kwargs):
        return

    def kv_delete(self, *args, **kwargs):
        return

    def project_read(self, *args, **kwargs):
        return GlobalProjects[0]

    def virtual_network_create(self, net_obj):
        net_id = unicode(str(uuid.uuid4()))
        net_obj.set_uuid(net_id)
        vn_list.append(net_obj)
        return net_id

    def virtual_network_read(self, id, *args, **kwargs):
        if len(vn_list):
            for index in range(len(vn_list)):
                if ((vn_list[index].get_uuid()) == id):
                    return vn_list[index]

        #return a mock object if it is not created so far
        return MockVirtualNetwork('dummy-net', MockProject())

    def virtual_network_delete(self, *args, **kwargs):
        return

    def virtual_network_update(self, *args, **kwargs):
        return

    def virtual_networks_list(self, *args, **kwargs):
        return vn_list


class MockVncObject(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        if not parent_obj:
            self._fq_name = [name]
        else:
            self._fq_name = parent_obj.get_fq_name() + [name]

        self._ipam_refs = [{'to': [u'default-domain', u'admin',
                           u'default-network-ipam']}]
        self.uuid = None
        self.name = name
        self.network_ipam_refs = []

    def set_uuid(self, uuid):
        self.uuid = uuid

    def get_uuid(self):
        return self.uuid

    def get_fq_name(self):
        return self._fq_name

    def get_network_ipam_refs(self):
        return getattr(self, 'network_ipam_refs', None)

    def add_network_ipam(self, ref_obj, ref_data):
        refs = getattr(self, 'network_ipam_refs', [])
        if not refs:
            self.network_ipam_refs = []

        # if ref already exists, update any attr with it
        for ref in refs:
            if ref['to'] == ref_obj.get_fq_name():
                ref = {'to': ref_obj.get_fq_name(), 'attr': ref_data}
                if ref_obj.uuid:
                    ref['uuid'] = ref_obj.uuid
                return

        # ref didn't exist before
        ref_info = {'to': ref_obj.get_fq_name(), 'attr': ref_data}
        if ref_obj.uuid:
            ref_info['uuid'] = ref_obj.uuid

        self.network_ipam_refs.append(ref_info)


class MockVirtualNetwork(MockVncObject):
    pass


class MockSubnetType(mock.MagicMock):
    def __init__(self, name=None, ip_prefix=None, ip_prefix_len=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self.ip_prefix = ip_prefix
        self.ip_prefix_len = ip_prefix_len

    def get_ip_prefix(self):
        return self.ip_prefix

    def set_ip_prefix(self, ip_prefix):
        self.ip_prefix = ip_prefix

    def get_ip_prefix_len(self):
        return self.ip_prefix_len

    def set_ip_prefix_len(self, ip_prefix_len):
        self.ip_prefix_len = ip_prefix_len


class MockIpamSubnetType(mock.MagicMock):
    def __init__(self, name=None, subnet=None, default_gateway=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self.subnet = subnet
        self.default_gateway = default_gateway

    def get_subnet(self):
        return self.subnet

    def set_subnet(self, subnet):
        self.subnet = subnet

    def get_default_gateway(self):
        return self.default_gateway

    def set_default_gateway(self, default_gateway):
        self.default_gateway = default_gateway

    def validate_IpAddressType(self, value):
        pass


class MockVnSubnetsType(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, ipam_subnets=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self.ipam_subnets = []
        if ipam_subnets:
            #self.ipam_subnets = copy.deepcopy(ipam_subnets)
            self.ipam_subnets = ipam_subnets

    def get_ipam_subnets(self):
        return self.ipam_subnets

    def set_ipam_subnets(self, ipam_subnets):
        self.ipam_subnets = ipam_subnets

    def add_ipam_subnets(self, value):
        self.ipam_subnets.append(value)

    def insert_ipam_subnets(self, index, value):
        self.ipam_subnets[index] = value

    def delete_ipam_subnets(self, value):
        self.ipam_subnets.remove(value)


class MockNetworkIpam(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None,
                 network_ipam_mgmt=None, id_perms=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self._type = 'default-network-ipam'
        self.name = name
        self.uuid = None
        if parent_obj:
            self.parent_type = parent_obj._type
            # copy parent's fq_name
            self.fq_name = list(parent_obj.fq_name)
            self.fq_name.append(name)
            if not parent_obj.get_network_ipams():
                parent_obj.network_ipams = []
            parent_obj.network_ipams.append(self)
        else:  # No parent obj specified
            self.parent_type = 'project'
            self.fq_name = [u'default-domain', u'default-project']
            self.fq_name.append(name)

        # property fields
        if network_ipam_mgmt:
            self.network_ipam_mgmt = network_ipam_mgmt
        if id_perms:
            self.id_perms = id_perms

    def get_fq_name(self):
        return self.fq_name


class MockProject(mock.MagicMock):
    def __init__(self, name=None, parent_obj=None, id_perms=None,
                 *args, **kwargs):
        super(mock.MagicMock, self).__init__()
        self._type = 'project'
        self.uuid = None
        self.parent_type = 'domain'
        self.fq_name = [u'default-domain']
        self.fq_name.append(name)

    def get_fq_name(self):
        return self.fq_name


def GlobalProjectApi(project_name):
    if not GlobalProjects:
        GlobalProjects.append(MockProject(name=project_name))

    return GlobalProjects[0]


# Mock definations for different pkgs, modules and VncApi
mock_vnc_api_cls = mock.MagicMock(name='MockVncApi', side_effect=MockVncApi)
mock_vnc_api_mod = mock.MagicMock(name='vnc_api_mock_mod')
mock_vnc_api_mod.VncApi = mock_vnc_api_cls
mock_vnc_api_mod.VirtualNetwork = MockVirtualNetwork
mock_vnc_api_mod.SubnetType = MockSubnetType
mock_vnc_api_mod.IpamSubnetType = MockIpamSubnetType
mock_vnc_api_mod.VnSubnetsType = MockVnSubnetsType
mock_vnc_api_mod.NetworkIpam = MockNetworkIpam
mock_vnc_api_mod.Project = GlobalProjectApi

mock_vnc_api_pkg = mock.MagicMock(name='vnc_api_mock_pkg')
mock_vnc_api_pkg.vnc_api = mock_vnc_api_mod
mock_vnc_common_mod = mock.MagicMock(name='vnc_common_mock_mod')
mock_vnc_exception_mod = mock.MagicMock(name='vnc_exception_mock_mod')
sys.modules['neutron.plugins.juniper.contrail.ctdb.vnc_api'] = \
    mock_vnc_api_pkg
sys.modules['neutron.plugins.juniper.contrail.ctdb.vnc_api.vnc_api'] = \
    mock_vnc_api_mod
sys.modules['neutron.plugins.juniper.contrail.ctdb.vnc_api.common'] = \
    mock_vnc_common_mod
sys.modules[('neutron.plugins.juniper.contrail.ctdb.vnc_api.common.'
             'exceptions')] = \
    mock_vnc_exception_mod

CONTRAIL_PKG_PATH = "neutron.plugins.juniper.contrail.contrailplugin"


class RouterInstance(object):
    def __init__(self):
        self._name = 'rounter_instance'


class Context(object):
    def __init__(self, tenant_id=''):
        self.read_only = False
        self.show_deleted = False
        self.roles = [u'admin', u'KeystoneServiceAdmin', u'KeystoneAdmin']
        self._read_deleted = 'no'
        self.timestamp = datetime.datetime.now()
        self.auth_token = None
        self._session = None
        self._is_admin = True
        self.admin = uuid.uuid4().hex.decode()
        self.request_id = 'req-' + str(uuid.uuid4())
        self.tenant = tenant_id


class JVContrailPluginTestCase(test_plugin.NeutronDbPluginV2TestCase):
    _plugin_name = ('%s.ContrailPlugin' % CONTRAIL_PKG_PATH)

    def setUp(self):

        mock_vnc_common_mod.exceptions = mock_vnc_exception_mod

        mock_vnc_api_mod.common = mock_vnc_common_mod
        mock_vnc_api_mod.VncApi = mock_vnc_api_cls

        mock_vnc_api_pkg.vnc_api = mock_vnc_api_mod

        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)
        neutron.db.api._ENGINE = mock.MagicMock()

    def teardown(self):
        super(JVContrailPluginTestCase, self).setUp(self._plugin_name)


class TestContrailNetworks(test_plugin.TestNetworksV2,
                           JVContrailPluginTestCase):

    def test_create_network(self):
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        networks_req[u'network'] = network
        context_obj = Context(network['tenant_id'])

        #create project
        if not GlobalProjects:
            project_name = 'admin'
            GlobalProjects.append(MockProject(name=project_name))

        net = plugin_obj.create_network(context_obj, networks_req)
        if 'contrail:fq_name' not in net.keys():
            assert False
        else:
            assert True

    def test_delete_network(self):
        # First create the network and request to delete the same
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        context_obj = Context(network['tenant_id'])
        #create project
        if not GlobalProjects:
            project_name = 'admin'
            GlobalProjects.append(MockProject(name=project_name))

        networks_req[u'network'] = network
        net_dict = plugin_obj.create_network(context_obj, networks_req)
        net_id = net_dict.get('id')

        plugin_obj.delete_network(context_obj, net_id)
        mock_vnc_api_cls.virtual_network_delete.assert_called_once()

    def test_update_network(self):
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        context_obj = Context(network['tenant_id'])
        #create project
        if not GlobalProjects:
            project_name = 'admin'
            GlobalProjects.append(MockProject(name=project_name))

        networks_req[u'network'] = network
        net_dict = plugin_obj.create_network(context_obj, networks_req)
        net_id = net_dict.get('id')
        # change one of the attribute and update the network
        network['admin_state_up'] = 'False'
        new_dict = plugin_obj.update_network(context_obj, net_id,
                                             networks_req)
        self.assertNotEqual(net_dict.get('admin_state_up'),
                            new_dict.get('admin_state_up'))

    # Not supported test cases in the this TestClass
    def test_create_networks_bulk_emulated(self):
        pass

    def test_create_networks_bulk_emulated_plugin_failure(self):
        pass

    def test_create_public_network(self):
        pass

    def test_create_networks_bulk_wrong_input(self):
        pass

    def test_update_shared_network_noadmin_returns_403(self):
        pass

    def test_update_network_set_shared(self):
        pass

    def test_update_network_set_not_shared_multi_tenants_returns_409(self):
        pass

    def test_update_network_set_not_shared_multi_tenants2_returns_409(self):
        pass

    def test_update_network_set_not_shared_single_tenant(self):
        pass

    def test_update_network_set_not_shared_other_tenant_returns_409(self):
        pass

    def test_update_network_with_subnet_set_shared(self):
        pass

    def test_show_network(self):
        pass

    def test_show_network_with_subnet(self):
        pass

    def test_list_networks(self):
        pass

    def test_list_shared_networks_with_non_admin_user(self):
        pass

    def test_list_networks_with_parameters(self):
        pass

    def test_list_networks_with_fields(self):
        pass

    def test_list_networks_with_parameters_invalid_values(self):
        pass

    def test_list_networks_with_pagination_emulated(self):
        pass

    def test_list_networks_without_pk_in_fields_pagination_emulated(self):
        pass

    def test_list_networks_with_sort_emulated(self):
        pass

    def test_list_networks_with_pagination_reverse_emulated(self):
        pass

    def test_invalid_admin_status(self):
        pass


class TestContrailSubnetsV2(test_plugin.TestSubnetsV2,
                            JVContrailPluginTestCase):

    def test_create_subnet(self):
        #First create virtual network without subnet and then
        #create subnet to update given network.
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        networks_req[u'network'] = network
        context_obj = Context(network['tenant_id'])
        #create project
        if not GlobalProjects:
            project_name = 'admin'
            GlobalProjects.append(MockProject(name=project_name))

        net = plugin_obj.create_network(context_obj, networks_req)

        subnet_obj[u'subnet']['network_id'] = net['id']
        subnet_dict = plugin_obj.create_subnet(context_obj, subnet_obj)
        self.assertEqual(subnet_dict['cidr'],
                         subnet_obj['subnet']['cidr'])

    def test_delete_subnet(self):
        #First create virtual network without subnet and then
        #create subnet to update given network.
        plugin_obj = NeutronManager.get_plugin()
        networks_req = {}
        router_inst = RouterInstance()
        network = {
            'router:external': router_inst,
            u'name': u'network1',
            'admin_state_up': 'True',
            'tenant_id': uuid.uuid4().hex.decode(),
            'vpc:route_table': '',
            'shared': False,
            'port_security_enabled': True,
            u'contrail:policys': [],
        }

        networks_req[u'network'] = network
        context_obj = Context(network['tenant_id'])
        #create project
        if not GlobalProjects:
            project_name = 'admin'
            GlobalProjects.append(MockProject(name=project_name))

        net = plugin_obj.create_network(context_obj, networks_req)

        subnet_obj[u'subnet']['network_id'] = net['id']
        subnet_dict = plugin_obj.create_subnet(context_obj, subnet_obj)
        subnet_id = subnet_dict['id']
        plugin_obj.delete_subnet(context_obj, subnet_id)

    def test_update_subnet_gateway_in_allocation_pool_returns_409(self):
        pass

    def test_delete_network(self):
        pass

    def test_update_subnet_gw_outside_cidr_force_on_returns_400(self):
        pass

    def test_update_subnet_adding_additional_host_routes_and_dns(self):
        pass

    def test_update_subnet_no_gateway(self):
        pass

    def test_create_subnet_bad_cidr(self):
        pass

    def test_create_subnet_gw_of_network_force_on_returns_400(self):
        pass

    def test_create_subnet_gw_outside_cidr_force_on_returns_400(self):
        pass

    def test_create_two_subnets(self):
        pass

    def test_create_two_subnets_same_cidr_returns_400(self):
        pass

    def test_create_subnet_bad_V4_cidr(self):
        pass

    def test_create_subnet_bad_V6_cidr(self):
        pass

    def test_create_2_subnets_overlapping_cidr_allowed_returns_200(self):
        pass

    def test_create_2_subnets_overlapping_cidr_not_allowed_returns_400(self):
        pass

    def test_create_subnets_bulk_native(self):
        pass

    def test_create_subnets_bulk_emulated(self):
        pass

    def test_create_subnets_bulk_emulated_plugin_failure(self):
        pass

    def test_create_subnets_bulk_native_plugin_failure(self):
        pass

    def test_delete_subnet_port_exists_owned_by_network(self):
        pass

    def test_delete_subnet_port_exists_owned_by_other(self):
        pass

    def test_create_subnet_bad_tenant(self):
        pass

    def test_create_subnet_bad_ip_version(self):
        pass

    def test_create_subnet_bad_ip_version_null(self):
        pass

    def test_create_subnet_bad_uuid(self):
        pass

    def test_create_subnet_bad_boolean(self):
        pass

    def test_create_subnet_bad_pools(self):
        pass

    def test_create_subnet_bad_nameserver(self):
        pass

    def test_create_subnet_bad_hostroutes(self):
        pass

    def test_create_subnet_defaults(self):
        pass

    def test_create_subnet_gw_values(self):
        pass

    def test_create_force_subnet_gw_values(self):
        pass

    def test_create_subnet_with_allocation_pool(self):
        pass

    def test_create_subnet_with_none_gateway(self):
        pass

    def test_create_subnet_with_none_gateway_fully_allocated(self):
        pass

    def test_subnet_with_allocation_range(self):
        pass

    def test_create_subnet_with_none_gateway_allocation_pool(self):
        pass

    def test_create_subnet_with_v6_allocation_pool(self):
        pass

    def test_create_subnet_with_large_allocation_pool(self):
        pass

    def test_create_subnet_multiple_allocation_pools(self):
        pass

    def test_create_subnet_with_dhcp_disabled(self):
        pass

    def test_create_subnet_default_gw_conflict_allocation_pool_returns_409(
            self):
        pass

    def test_create_subnet_gateway_in_allocation_pool_returns_409(self):
        pass

    def test_create_subnet_overlapping_allocation_pools_returns_409(self):
        pass

    def test_create_subnet_invalid_allocation_pool_returns_400(self):
        pass

    def test_create_subnet_out_of_range_allocation_pool_returns_400(self):
        pass

    def test_create_subnet_shared_returns_400(self):
        pass

    def test_create_subnet_inconsistent_ipv6_cidrv4(self):
        pass

    def test_create_subnet_inconsistent_ipv4_cidrv6(self):
        pass

    def test_create_subnet_inconsistent_ipv4_gatewayv6(self):
        pass

    def test_create_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_create_subnet_inconsistent_ipv6_dns_v4(self):
        pass

    def test_create_subnet_inconsistent_ipv4_hostroute_dst_v6(self):
        pass

    def test_create_subnet_inconsistent_ipv4_hostroute_np_v6(self):
        pass

    def test_create_subnet_gw_bcast_force_on_returns_400(self):
        pass

    def test_update_subnet(self):
        pass

    def test_update_subnet_shared_returns_400(self):
        pass

    def test_update_subnet_inconsistent_ipv4_gatewayv6(self):
        pass

    def test_update_subnet_inconsistent_ipv6_gatewayv4(self):
        pass

    def test_update_subnet_inconsistent_ipv4_dns_v6(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_dst_v4(self):
        pass

    def test_update_subnet_inconsistent_ipv6_hostroute_np_v4(self):
        pass

    def test_show_subnet(self):
        pass

    def test_list_subnets(self):
        pass

    def test_list_subnets_shared(self):
        pass

    def test_list_subnets_with_parameter(self):
        pass

    def test_invalid_ip_version(self):
        pass

    def test_invalid_subnet(self):
        pass

    def test_invalid_ip_address(self):
        pass

    def test_invalid_uuid(self):
        pass

    def test_create_subnet_with_one_dns(self):
        pass

    def test_create_subnet_with_two_dns(self):
        pass

    def test_create_subnet_with_too_many_dns(self):
        pass

    def test_create_subnet_with_one_host_route(self):
        pass

    def test_create_subnet_with_two_host_routes(self):
        pass

    def test_create_subnet_with_too_many_routes(self):
        pass

    def test_create_subnet_as_admin(self):
        pass

    def test_update_subnet_dns(self):
        pass

    def test_update_subnet_dns_to_None(self):
        pass

    def test_update_subnet_dns_with_too_many_entries(self):
        pass

    def test_update_subnet_route(self):
        pass

    def test_update_subnet_route_to_None(self):
        pass

    def test_update_subnet_route_with_too_many_entries(self):
        pass

    def test_delete_subnet_with_dns(self):
        pass

    def test_delete_subnet_with_route(self):
        pass

    def test_delete_subnet_with_dns_and_route(self):
        pass

    def test_list_subnets_with_pagination_emulated(self):
        pass

    def test_list_subnets_with_pagination_reverse_emulated(self):
        pass

    def test_list_subnets_with_sort_emulated(self):
        pass

    def test_validate_subnet_host_routes_exhausted(self):
        pass

    def test_validate_subnet_dns_nameservers_exhausted(self):
        pass

    def test_update_subnet_gw_ip_in_use_returns_409(self):
        pass


class TestContrailPortsV2(test_plugin.TestPortsV2,
                          JVContrailPluginTestCase):

    def test_create_port(self):
        pass

    def test_create_port_json(self):
        pass

    def test_create_port_bad_tenant(self):
        pass

    def test_create_port_public_network(self):
        pass

    def test_create_port_public_network_with_ip(self):
        pass

    def test_create_ports_bulk_native(self):
        pass

    def test_create_ports_bulk_emulated(self):
        pass

    def test_create_ports_bulk_wrong_input(self):
        pass

    def test_create_ports_bulk_emulated_plugin_failure(self):
        pass

    def test_create_ports_bulk_native_plugin_failure(self):
        pass

    def test_create_port_as_admin(self):
        pass

    def test_list_ports(self):
        pass

    def test_list_ports_filtered_by_fixed_ip(self):
        pass

    def test_list_ports_public_network(self):
        pass

    def test_show_port(self):
        pass

    def test_delete_port(self):
        pass

    def test_delete_port_public_network(self):
        pass

    def test_update_port(self):
        pass

    def test_update_device_id_null(self):
        pass

    def test_delete_network_if_port_exists(self):
        pass

    def test_delete_network_port_exists_owned_by_network(self):
        pass

    def test_update_port_delete_ip(self):
        pass

    def test_no_more_port_exception(self):
        pass

    def test_update_port_update_ip(self):
        pass

    def test_update_port_update_ip_address_only(self):
        pass

    def test_update_port_update_ips(self):
        pass

    def test_update_port_add_additional_ip(self):
        pass

    def test_requested_duplicate_mac(self):
        pass

    def test_mac_generation(self):
        pass

    def test_mac_generation_4octet(self):
        pass

    def test_bad_mac_format(self):
        pass

    def test_mac_exhaustion(self):
        pass

    def test_requested_duplicate_ip(self):
        pass

    def test_requested_subnet_delete(self):
        pass

    def test_requested_subnet_id(self):
        pass

    def test_requested_subnet_id_not_on_network(self):
        pass

    def test_overlapping_subnets(self):
        pass

    def test_requested_subnet_id_v4_and_v6(self):
        pass

    def test_range_allocation(self):
        pass

    def test_requested_invalid_fixed_ips(self):
        pass

    def test_invalid_ip(self):
        pass

    def test_requested_split(self):
        pass

    def test_duplicate_ips(self):
        pass

    def test_fixed_ip_invalid_subnet_id(self):
        pass

    def test_fixed_ip_invalid_ip(self):
        pass

    def test_requested_ips_only(self):
        pass

    def test_recycling(self):
        pass

    def test_invalid_admin_state(self):
        pass

    def test_invalid_mac_address(self):
        pass

    def test_default_allocation_expiration(self):
        pass

    def test_update_fixed_ip_lease_expiration(self):
        pass

    def test_port_delete_holds_ip(self):
        pass

    def test_update_fixed_ip_lease_expiration_invalid_address(self):
        pass

    def test_hold_ip_address(self):
        pass

    def test_recycle_held_ip_address(self):
        pass

    def test_recycle_expired_previously_run_within_context(self):
        pass

    def test_update_port_not_admin(self):
        pass

    def test_list_ports_with_pagination_emulated(self):
        pass

    def test_list_ports_with_pagination_reverse_emulated(self):
        pass

    def test_list_ports_with_sort_emulated(self):
        pass

    def test_max_fixed_ips_exceeded(self):
        pass

    def test_update_max_fixed_ips_exceeded(self):
        pass

    def test_recycle_ip_address_without_allocation_pool(self):
        pass

    def test_recycle_ip_address_on_exhausted_allocation_pool(self):
        pass

    def test_recycle_ip_address_outside_allocation_pool(self):
        pass

    def test_recycle_ip_address_in_allocation_pool(self):
        pass
