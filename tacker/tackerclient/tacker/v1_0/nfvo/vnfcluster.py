# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from tackerclient.tacker import v1_0 as tackerV10


_VNFCLUSTER = 'vnfcluster'
_VNFCLUSTERMEMBER = 'vnfclustermember'


class ListCluster(tackerV10.ListCommand):
    """List Clusters that belong to a given tenant."""

    resource = _VNFCLUSTER
    list_columns = ['id', 'name', 'status']


class ShowCluster(tackerV10.ShowCommand):
    """Show information of a given Cluster."""

    resource = _VNFCLUSTER


class DeleteCluster(tackerV10.DeleteCommand):
    """Delete a given Cluster."""

    resource = _VNFCLUSTER

class CreateCluster(tackerV10.CreateCommand):
    """Create a Cluster."""

    resource = _VNFCLUSTER

    def add_known_arguments(self, parser):
        parser.add_argument(
            'name', metavar='NAME',
            help='Set a name for the VNFFG')       
        vnfd_group = parser.add_mutually_exclusive_group(required=True)
        vnfd_group.add_argument(
            '--vnfd-id',
            help='Set a id for the VNF')
        vnfd_group.add_argument(
            '--vnfd-name',
            help='Set a name for the VNF')
        parser.add_argument(
            '--active',
            help='Active number of VNF')
        parser.add_argument(
            '--standby',
            help='Standby number of VNF')

    def args2body(self, parsed_args):
        body = {self.resource: {}}
        tacker_client = self.get_client()
        tacker_client.format = parsed_args.request_format

        if parsed_args.vnfd_name:
            _id = tackerV10.find_resourceid_by_name_or_id(tacker_client,
                                                          'vnfd',
                                                          parsed_args.
                                                          vnfd_name)
            parsed_args.vnfd_id = _id

        tackerV10.update_dict(parsed_args, body[self.resource],
                              ['tenant_id', 'name', 'vnfd_id',
                               'active', 'standby'])
        return body


class AddClusterMember(tackerV10.CreateCommand):
    """Add VNF to specific cluster."""

    resource = _VNFCLUSTERMEMBER

    def add_known_arguments(self, parser):
        vnfs_group = parser.add_mutually_exclusive_group(required=True)
        vnfs_group.add_argument(
            '--vnf-ids',
            help='Set a id for the VNFD')
        vnfs_group.add_argument(
            '--vnf-names',
            help='Set a name for the VNFD')
        parser.add_argument(
            '--role',
            help='Set a [Active/Standby] role to VNFs')

    def args2body(self, parsed_args):
        body = {self.resource: {}}

        tacker_client = self.get_client()
        tacker_client.format = parsed_args.request_format

        if parsed_args.vnf_names:
            _vnf_id_list = list()
            _vnf_name_list = parsed_args.vnf_names.split(",")
            for vnf_name in _vnf_name_list:
                _vnf_id_list.append(
                    tackerV10.find_resourceid_by_name_or_id(
                        tacker_client, 'vnf', vnf_name))
            parsed_args.vnf_ids = _vnf_id_list
        
        if parsed_args.vnf_ids:
            parsed_args.vnf_ids = parsed_args.vnf_names.split(",")

        tackerV10.update_dict(parsed_args, body[self.resource],
                              ['tenant_id', 'vnf_ids', 'role'])
        return body


class UpdateClusterMember(tackerV10.UpdateCommand):
    """Add VNF to specific cluster."""

    resource = _VNFCLUSTERMEMBER

    def add_known_arguments(self, parser):
        vnfs_group = parser.add_mutually_exclusive_group(required=True)
        vnfs_group.add_argument(
            '--vnf-ids',
            help='Set a id for the VNFD')
        vnfs_group.add_argument(
            '--vnf-names',
            help='Set a name for the VNFD')
        parser.add_argument(
            '--role',
            help='Set a [Active/Standby] role to VNFs')

    def args2body(self, parsed_args):
        body = {self.resource: {}}

        tacker_client = self.get_client()
        tacker_client.format = parsed_args.request_format

        if parsed_args.vnf_names:
            _vnf_id_list = list()
            _vnf_name_list = parsed_args.vnf_names.split(",")
            for vnf_name in _vnf_name_list:
                _vnf_id_list.append(
                    tackerV10.find_resourceid_by_name_or_id(
                        tacker_client, 'vnf', vnf_name))
            parsed_args.vnf_ids = _vnf_id_list
        
        if parsed_args.vnf_ids:
            parsed_args.vnf_ids = parsed_args.vnf_names.split(",")

        tackerV10.update_dict(parsed_args, body[self.resource],
                              ['tenant_id', 'vnf_ids', 'role'])
        return body

class ListClusterMember(tackerV10.ListCommand):
    """List ClusterMembers that belong to a given tenant."""

    resource = _VNFCLUSTERMEMBER
    list_columns = ['id', 'cluster_id', 'index', 'role']

class DeleteClusterMember(tackerV10.DeleteCommand):
    """Delete a given VnfClusterMember."""

    resource = _VNFCLUSTERMEMBER


class ShowClusterMember(tackerV10.ShowCommand):
    """Show information of a given VnfClusterMember."""

    resource = _VNFCLUSTERMEMBER
    list_columns = ['id', 'cluster_id', 'index', 'role']