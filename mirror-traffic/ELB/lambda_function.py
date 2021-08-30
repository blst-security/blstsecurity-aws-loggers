import json
import boto3
import os
import time

ram = boto3.client('ram')
ec2 = boto3.client('ec2')

blstsec_account = os.environ['BLSTSECURITY_ACCOUNT']
blstsec_destination = os.environ['BLSTSECURITY_ROUTE_DESTINATION']
network_interface_ids = os.environ['NETWORK_INTERFACE_IDS'].split(',')

def get_network_interface_data():
    network_interfaces = []
    try:
        network_interfaces = ec2.describe_network_interfaces(
            NetworkInterfaceIds=network_interface_ids
        )['NetworkInterfaces']
    except:
        return {'error':'Couldnt find network interface, please make sure that the network_interface_ids is correct'}
    source_cidr = ''
    if len(network_interfaces):
        source_cidr = ec2.describe_vpcs(
            VpcIds=[
                network_interfaces[0]['VpcId']
            ]
        )['Vpcs'][0]['CidrBlock']
        print('Your CIDR Block is: ' + source_cidr)
        route_table_id = ''
        try:
            route_table_id = ec2.describe_route_tables(
                Filters=[
                    {
                        'Name': 'association.subnet-id',
                        'Values': [
                            network_interfaces[0]['SubnetId']
                        ]
                    }
                ]
            )['RouteTables'][0]['RouteTableId']
        except Exception as e:
            route_tables_data = ec2.describe_route_tables(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [
                            network_interfaces[0]['VpcId']
                        ]
                    }
                ]
            )['RouteTables']
            is_main = False
            if route_tables_data[0]['Associations'][0]['Main']:
                route_table_id = route_tables_data[0]['Associations'][0]['RouteTableId']
                is_main = True
            route_tables_index = 1
            while not is_main and len(route_tables_data) > route_tables_index:
                if route_tables_data[route_tables_index]['Associations'][0]['Main']:
                    route_table_id = route_tables_data[route_tables_index]['Associations'][0]['RouteTableId']
                    is_main = True
            if not is_main:
                return {'error':'There was an error with finding your route table id, please contact blstsecurity'}
        return {'vpc_id':network_interfaces[0]['VpcId'], 'subnet_id':network_interfaces[0]['SubnetId'], 'cidr':source_cidr, 'route_table_id':route_table_id}
    else:
        return {'error':'Couldnt find network interface, please make sure that the network_interface_ids is correct'}
    
def get_resource_share_list():
    shared_resources_inv = ram.get_resource_share_invitations()
    shared_resources_list = []
    for resource in shared_resources_inv['resourceShareInvitations']:
        if resource['senderAccountId'] == blstsec_account:
            if resource['status'] != 'ACCEPTED':
                ram.accept_resource_share_invitation(
                    resourceShareInvitationArn=resource['resourceShareInvitationArn']
                )
            shared_resources_list.append(resource['resourceShareArn'])
    return shared_resources_list

def get_resource_share_ids(shared_resources_list):
    shared_resources_ids_list = {}
    shared_resources_ram_list = []
    if not len(shared_resources_list):
        return shared_resources_ram_list
    while len(shared_resources_ram_list) != 2:
        shared_resources_ram_list = ram.list_resources(
            resourceOwner='OTHER-ACCOUNTS',
            resourceShareArns=shared_resources_list
        )['resources']
        time.sleep(0.05)
    for resource in shared_resources_ram_list:
        if resource['type'] == 'ec2:TransitGateway':
            shared_resources_ids_list['tgw'] = resource['arn'].split('/')[1]
        elif resource['type'] == 'ec2:TrafficMirrorTarget':
            shared_resources_ids_list['tmt'] = resource['arn'].split('/')[1]
    return shared_resources_ids_list

def create_transit_gateway_attachment(tgw_id, source_vpc_id, source_subnet_id):
    tgwa = ''
    try:
        tgwa = ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw_id,
            VpcId=source_vpc_id,
            SubnetIds=[source_subnet_id]
        )['TransitGatewayVpcAttachment']['TransitGatewayAttachmentId']
    except Exception as e:
        tgwa = e
        
def create_traffic_mirror_filter_rule(tmf_id, direction, number):
    tmf_rule_id = ''
    while tmf_rule_id == '':
        try:
            tmf_rule_id = ec2.create_traffic_mirror_filter_rule(
                TrafficMirrorFilterId=tmf_id,
                TrafficDirection=direction,
                RuleNumber=number,
                RuleAction='accept',
                Protocol=6,
                DestinationCidrBlock='0.0.0.0/0',
                SourceCidrBlock='0.0.0.0/0'
            )['TrafficMirrorFilterRule']['TrafficMirrorFilterRuleId']
        except Exception as e:
            print(e)
            time.sleep(0.05)
            
def create_traffic_mirror_filter():
    traffic_mirror_filters = ec2.describe_traffic_mirror_filters(
        Filters=[
            {
                'Name': 'description',
                'Values': [
                    'blstsecurity traffic mirror filter'
                ]
            },
        ]
    )['TrafficMirrorFilters']
    if len(traffic_mirror_filters):
        return ''
    
    tmf_id = ec2.create_traffic_mirror_filter(
        Description='blstsecurity traffic mirror filter'
    )['TrafficMirrorFilter']['TrafficMirrorFilterId']
    create_traffic_mirror_filter_rule(tmf_id, 'ingress', 100)
    create_traffic_mirror_filter_rule(tmf_id, 'egress', 100)
    return tmf_id
    
def create_traffic_mirror_session(tmt_id, tmf_id):
    if tmf_id == '':
        return
    blstsecurity_tms = 0
    for network_interface_id in network_interface_ids:
        print(network_interface_id)
        blstsecurity_tms+=1
        tms = ec2.create_traffic_mirror_session(
            NetworkInterfaceId=network_interface_id,
            TrafficMirrorTargetId=tmt_id,
            TrafficMirrorFilterId=tmf_id,
            SessionNumber=10,
            Description='blstsecurity traffic mirror session ' + str(blstsecurity_tms)
        )
    
def add_tgw_route_table(route_table_id, tgw_id):
    try:
        ec2.create_route(
            DestinationCidrBlock=blstsec_destination,
            TransitGatewayId=tgw_id,
            RouteTableId=route_table_id
        )
        return 'traffic mirroring integration installed successfully'
    except:
        return 'Wait until blstsecurity will accept the transit gateway attachment and then run the lambda again'

def lambda_handler(event, context):
    source_network_interface_data = get_network_interface_data()
    if 'error' in source_network_interface_data:
        return source_network_interface_data['error']
    shared_resources_ids = get_resource_share_ids(get_resource_share_list())
    if len(shared_resources_ids):
        create_transit_gateway_attachment(shared_resources_ids['tgw'], source_network_interface_data['vpc_id'] , source_network_interface_data['subnet_id'])
        create_traffic_mirror_session(shared_resources_ids['tmt'], create_traffic_mirror_filter())
        return add_tgw_route_table(source_network_interface_data['route_table_id'], shared_resources_ids['tgw'])
    else:
        return 'Shared resources not found, please contact blstsecurity for more information'