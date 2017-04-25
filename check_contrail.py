import requests
import json
import argparse
from time import gmtime, strftime
from prettytable import PrettyTable
from keystoneclient.v2_0 import client
from keystoneclient.exceptions import AuthorizationFailure, Unauthorized
from vnc_api import vnc_api

# Keystone Authentication variables
username='admin'
password='contrail123'
tenant_name='admin'
auth_url='https://100.86.0.2:5000/v2.0'

# Keystone Client
keystone = client.Client(username=username,password=password,tenant_name=tenant_name,auth_url=auth_url,timeout=10)

contrail_api_service_id = keystone.services.find(name="contrail-api").__dict__['id']
contrail_api = keystone.endpoints.find(service_id=contrail_api_service_id).__dict__['internalurl']

contrail_analytics_api_service_id = keystone.services.find(name="contrail-analytics").__dict__['id']
contrail_analytics_api = keystone.endpoints.find(service_id=contrail_analytics_api_service_id).__dict__['internalurl']

token = keystone.auth_token
headers = {'X-Auth-Token': token}

# Contrail vnc_api instance
vnc_lib = vnc_api.VncApi(api_server_host='100.86.0.21', api_server_use_ssl=False, auth_token=token)

contrail_global_config = vnc_lib.global_system_config_read([ "default-global-system-config" ])

table_ps = PrettyTable()
table_ps._set_field_names ( [ 'Node Name', 'Process Name', 'Process State', 'Last Started', 'Start Count', 'Last Stopped', 'Stop Count', 'Last Exited', 'Exit Count' ] )

table_pc = PrettyTable()
table_pc._set_field_names ( [ 'Node Name', '1st Process Name', 'State', '2nd Process Name', 'Type', 'Connection Status' ] )


# functions for printing output from analytics urls provided
def print_process_status (url, headers, node_name):
  time_format = '%d %b %y %H:%M:%S'
  r = requests.get(url, headers=headers)
  json_resp = json.loads(r.text)
  if 'NodeStatus' in json_resp:
    for process_info in json_resp['NodeStatus']['process_info']:
      last_start_time = 'None'
      if process_info['last_start_time'] is not None:
        last_start_time = strftime(time_format, gmtime(float(process_info['last_start_time']) / 1000000))
      last_stop_time = 'None'
      if process_info['last_stop_time'] is not None:
        last_stop_time = strftime(time_format, gmtime(float(process_info['last_stop_time']) / 1000000))
      last_exit_time = 'None'
      if process_info['last_exit_time'] is not None:
        last_exit_time = strftime(time_format, gmtime(float(process_info['last_exit_time']) / 1000000))
      
      # table_ps.add_row ( [ process_info['process_name'], process_info['process_state'], last_start_time , process_info['start_count'], last_stop_time , process_info['stop_count'], last_exit_time, process_info['exit_count'] ] )
      table_ps.add_row ( [ node_name, process_info['process_name'], process_info['process_state'], last_start_time , process_info['start_count'], last_stop_time , process_info['stop_count'], last_exit_time, process_info['exit_count'] ] )
    table_ps.add_row ( [ '', '', '', '' , '', '', '', '', '' ] )
  else:
    # No info returned for the node
    print ("WARNING: No process status returned for node " + node_name)
  return;


def print_process_connections (url, headers, node_name):
  r = requests.get(url, headers=headers)
  json_resp = json.loads(r.text)
  if 'NodeStatus' in json_resp:
    for process_status in json_resp['NodeStatus']['process_status']:
      if 'connection_infos' in process_status:
        for connection_infos in process_status['connection_infos']:
          table_pc.add_row( [ node_name, process_status['module_id'],process_status['state'],connection_infos['name'],connection_infos['type'],connection_infos['status'] ] )
    
    table_pc.add_row ( [ '', '', '', '' , '', '' ] )
  else:
    # No info returned for the node
    print ("WARNING: No process connections returned for node " + node_name)
  return;


# check config nodes
contrail_config_nodes = contrail_global_config.get_config_nodes()
for contrail_config_node in contrail_config_nodes:
  contrail_config_node_name = contrail_config_node['to'][1]

  #Processes status
  url = contrail_analytics_api + '/analytics/uves/config-node/' + contrail_config_node_name + '?cfilt=NodeStatus:process_info'
  print_process_status ( url, headers, contrail_config_node_name )

  #Processes connections
  url = contrail_analytics_api + '/analytics/uves/config-node/' + contrail_config_node_name + '?cfilt=NodeStatus:process_status'
  print_process_connections ( url, headers, contrail_config_node_name )




# check control nodes
bgp_routers = vnc_lib.bgp_routers_list()
for bgp_router in bgp_routers['bgp-routers']:
  bgp_router_cont = vnc_lib.bgp_router_read(bgp_router['fq_name'])
  if bgp_router_cont.bgp_router_parameters.__dict__['router_type'] == 'control-node':
    contrail_controller_node_name = bgp_router_cont.name

    #Processes status
    url = contrail_analytics_api + '/analytics/uves/control-node/' + contrail_controller_node_name + '?cfilt=NodeStatus:process_info'
    print_process_status ( url, headers, contrail_controller_node_name )

    #Processes connections
    url = contrail_analytics_api + '/analytics/uves/control-node/' + contrail_controller_node_name + '?cfilt=NodeStatus:process_status'
    print_process_connections ( url, headers, contrail_controller_node_name )


# check analytics nodes
contrail_analytics_nodes = contrail_global_config.get_analytics_nodes()
for contrail_analytics_node in contrail_analytics_nodes:
  contrail_analytics_node_name = contrail_analytics_node['to'][1]

  #Processes status
  url = contrail_analytics_api + '/analytics/uves/analytics-node/' + contrail_analytics_node_name + '?cfilt=NodeStatus:process_info'
  print_process_status( url, headers, contrail_analytics_node_name )

  #Processes connections
  url = contrail_analytics_api + '/analytics/uves/analytics-node/' + contrail_analytics_node_name + '?cfilt=NodeStatus:process_status'
  print_process_connections ( url, headers, contrail_analytics_node_name )

# check discovery:

#check discovery service status
# url = 'http://100.86.0.21:5998/services'
# r = requests.get(url)
# json_resp = json.loads(r.text)



# check vRouter status
table_flow = PrettyTable()

contrail_vrouter_nodes = contrail_global_config.get_virtual_routers()
for contrail_vrouter_node in contrail_vrouter_nodes:
  contrail_vrouter_node_name = contrail_vrouter_node['to'][1]
  
  # Processes status
  url = contrail_analytics_api + '/analytics/uves/vrouter/' + contrail_vrouter_node_name + '?cfilt=NodeStatus:process_info'
  print_process_status ( url, headers, contrail_vrouter_node_name )
  
  # Processes connections
  url = contrail_analytics_api + '/analytics/uves/vrouter/' + contrail_vrouter_node_name + '?cfilt=NodeStatus:process_status'
  print_process_connections ( url, headers, contrail_vrouter_node_name )
  
  # add vRouter flow stats
  url = contrail_analytics_api + '/analytics/uves/vrouter/' + contrail_vrouter_node_name + '?cfilt=VrouterStatsAgent:flow_rate'
  r = requests.get(url, headers=headers)
  json_resp = json.loads(r.text)
  if 'VrouterStatsAgent' in json_resp:
    table_flow._set_field_names ([ 'vRouter', 'active_flows', 'added_flows', 'deleted_flows', 'max_flow_adds_per_second', 'max_flow_deletes_per_second', 'min_flow_adds_per_second', 'min_flow_deletes_per_second' ])
    table_flow.add_row( [ contrail_vrouter_node_name, json_resp['VrouterStatsAgent']['flow_rate']['active_flows'], json_resp['VrouterStatsAgent']['flow_rate']['added_flows'], json_resp['VrouterStatsAgent']['flow_rate']['deleted_flows'], json_resp['VrouterStatsAgent']['flow_rate']['max_flow_adds_per_second'], json_resp['VrouterStatsAgent']['flow_rate']['max_flow_deletes_per_second'], json_resp['VrouterStatsAgent']['flow_rate']['min_flow_adds_per_second'], json_resp['VrouterStatsAgent']['flow_rate']['min_flow_deletes_per_second'] ] )
  else:
    # No info returned for the node
    print ("WARNING: No vRouter stats returned for node " + contrail_vrouter_node_name)
 
  

# print tables

# print process status table
table = PrettyTable()
table._set_field_names(['Process Status'])
print table

print table_ps

# print process connections table
table = PrettyTable()
table._set_field_names(['Process Connections'])
print table

print table_pc

# print vRouter flow info table
table = PrettyTable()
table._set_field_names(['vRouter Flows'])
print table

table_flow.sortby = 'active_flows'
print table_flow
