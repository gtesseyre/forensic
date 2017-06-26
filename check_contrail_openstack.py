import os
import sys
import requests
import json
import argparse
from urlparse import urlparse
from time import gmtime, strftime, mktime
from prettytable import PrettyTable
from keystoneclient.v2_0 import client
from keystoneclient.exceptions import AuthorizationFailure, Unauthorized
from vnc_api import vnc_api




# functions for providing process status from analytics
def analytics_get_node_status (contrail_analytics_api, token, node_type, node_name ):
  node_process_info = []
  node_process_status = []
  warnings = []
  current_time = gmtime()
  process_started_time_warning_th = (24 * 3600)
  url = contrail_analytics_api + '/analytics/uves/' + node_type + '/' + node_name + '?cfilt=NodeStatus'
  headers = {'X-Auth-Token': token}
  time_format = '%d %b %y %H:%M:%S'

  r = requests.get(url, headers=headers)
  json_resp = json.loads(r.text)

  # check if Analytics has NodeStatus for that node
  if 'NodeStatus' in json_resp:
    # get NodeStatus:process_info
    if 'process_info' in json_resp['NodeStatus']:
      for process_info in json_resp['NodeStatus']['process_info']:
        # run some checks
        if process_info['process_state'] != 'PROCESS_STATE_RUNNING':
          # process is not running
            warnings.append ( [ node_name, 'process ' + process_info['process_name'] + ' not running'] )
        if process_info['exit_count'] > 0:
          # process has exited at some point
            warnings.append ( [ node_name, 'process ' + process_info['process_name'] + ' exit count > 0'] )
        if process_info['last_start_time'] is not None:
          last_start_time_struct = gmtime(float(process_info['last_start_time']) / 1000000)
          last_start_time = strftime(time_format, last_start_time_struct)
          time_diff = mktime(current_time) - mktime(last_start_time_struct)
          if time_diff < process_started_time_warning_th:
            warnings.append ( [ node_name, 'process ' + process_info['process_name'] + ' started less than 24 hours ago'] )
        last_stop_time = 'None'
        if process_info['last_stop_time'] is not None:
          last_stop_time = strftime(time_format, gmtime(float(process_info['last_stop_time']) / 1000000))
        last_exit_time = 'None'
        if process_info['last_exit_time'] is not None:
          last_exit_time = strftime(time_format, gmtime(float(process_info['last_exit_time']) / 1000000))

        # write fields to results array
        node_process_info.append ( [ node_name, process_info['process_name'], process_info['process_state'], last_start_time , process_info['start_count'], last_stop_time , process_info['stop_count'], last_exit_time, process_info['exit_count'] ] )
    # get NodeStatus:process_status
    if 'process_status' in json_resp['NodeStatus']:
      for process_status in json_resp['NodeStatus']['process_status']:
        if 'connection_infos' in process_status:
          for connection_infos in process_status['connection_infos']:
            node_process_status.append( [ node_name, process_status['module_id'],process_status['state'],connection_infos['name'],connection_infos['type'],connection_infos['status'] ] )
  else:
    # No info returned for the node
    warnings.append ( [ node_name, 'No NodeStatus available for node'])

  return [ node_process_info, node_process_status, warnings ]




# function for getting vrouter stats
def get_vrouter_stats (contrail_analytics_api, token, node_name):
  node_flow_stats = []
  url = contrail_analytics_api + '/analytics/uves/vrouter/' + node_name + '?cfilt=VrouterStatsAgent:flow_rate'
  headers = {'X-Auth-Token': token}
  r = requests.get(url, headers=headers)
  json_resp = json.loads(r.text)
  if 'VrouterStatsAgent' in json_resp:
    node_flow_stats.append( [ node_name, json_resp['VrouterStatsAgent']['flow_rate']['active_flows'], json_resp['VrouterStatsAgent']['flow_rate']['added_flows'], json_resp['VrouterStatsAgent']['flow_rate']['deleted_flows'], json_resp['VrouterStatsAgent']['flow_rate']['max_flow_adds_per_second'], json_resp['VrouterStatsAgent']['flow_rate']['max_flow_deletes_per_second'], json_resp['VrouterStatsAgent']['flow_rate']['min_flow_adds_per_second'], json_resp['VrouterStatsAgent']['flow_rate']['min_flow_deletes_per_second'] ] )
  else:
    # No info returned for the node
    warnings.append ( [ node_name, 'No vRouter stats returned for node'])

  return [ node_flow_stats, warnings ]





# main
if __name__ == '__main__':

  # define and parse input arguments
  argparser = argparse.ArgumentParser()
  argparser.add_argument("-a", "--os-auth-url", help="Openstack Authentication URL", required=False)
  argparser.add_argument("-t", "--os-project-name", help="Openstack Project/Tenant Name", required=False)
  argparser.add_argument("-u", "--os-username", help="Openstack Username", required=False)
  argparser.add_argument("-p", "--os-password", help="Openstack Password", required=False)
  argparser.add_argument("-c", "--contrail-api", help="Contrail API URL", required=False)
  argparser.add_argument("-C", "--contrail-analytics-api", help="Contrail Analytics API URL", required=False)
  parsedargs, _ = argparser.parse_known_args(sys.argv[1:])

  
  # Set parameters from input args or environment
  if parsedargs.os_username:
    username=parsedargs.os_username
  elif 'OS_USERNAME' in os.environ:
    username=os.environ.get('OS_USERNAME')
  else:
    sys.exit ( "No OS_USERNAME defined" )

  if parsedargs.os_password:
    password=parsedargs.os_password
  elif 'OS_PASSWORD' in os.environ:
    password=os.environ.get('OS_PASSWORD')
  else:
    sys.exit ( "No OS_PASSWORD defined" )

  if parsedargs.os_project_name:
    tenant_name=parsedargs.os_project_name
  elif 'OS_PROJECT_NAME' in os.environ:
    tenant_name=os.environ.get('OS_PROJECT_NAME')
  elif 'OS_TENANT_NAME' in os.environ:
    tenant_name=os.environ.get('OS_TENANT_NAME')
  else:
    sys.exit ( "No OS_PROJECT_NAME or OS_TENANT_NAME defined" )

  if parsedargs.os_auth_url:
    auth_url=parsedargs.os_auth_url
  elif 'OS_AUTH_URL' in os.environ:
    auth_url=os.environ.get('OS_AUTH_URL')
  else:
    sys.exit ( "No OS_AUTH_URL defined" )

  timeout = 10

  # Keystone Client
  # check if keystone endpoint is reachable and alive
  try:
    response = requests.get(url=auth_url)
  except requests.exceptions.RequestException:
    sys.exit ( "Connection error to " + str(auth_url) )

  if response.status_code != 200:
    sys.exit ( "Error connecting to " + str(auth_url) + " with response status code " + str(response.status_code) )

  try:
    keystone = client.Client ( username=username, password=password, tenant_name=tenant_name, auth_url=auth_url, timeout=timeout )
  except AuthorizationFailure as e:
      sys.exit ( 'Authorization Failure: %s' % (e.message) )
  except Unauthorized as e:
      sys.exit ( 'Unauthorized: %s' % (e.message) )
  except Timeout as e:
      sys.exit ( 'Timeout: %s' % (e.message) )
  except Exception as e:
      sys.exit ( 'Keystone Failure: %s' % (e.message) )

  # get token
  token = keystone.auth_token


  # if Contrail API endpoints are not defined, get them from keystone
  if parsedargs.contrail_api:
    contrail_api = parsedargs.contrail_api
  elif 'CONTRAIL_API' in os.environ:
    contrail_api = os.environ.get('CONTRAIL_API')
  else:
    try:
      contrail_api_service_id = keystone.services.find(name="contrail-api").__dict__['id']
      contrail_api = keystone.endpoints.find(service_id=contrail_api_service_id).__dict__['internalurl']
    except Exception as e:
      sys.exit ( "No CONTRAIL_API defined" )

  if parsedargs.contrail_analytics_api:
    contrail_analytics_api = parsedargs.contrail_analytics_api
  elif 'CONTRAIL_ANALYTICS_API' in os.environ:
    contrail_analytics_api = os.environ.get('CONTRAIL_ANALYTICS_API')
  else:
    try:
      contrail_analytics_api_service_id = keystone.services.find(name="contrail-analytics").__dict__['id']
      contrail_analytics_api = keystone.endpoints.find(service_id=contrail_analytics_api_service_id).__dict__['internalurl']
    except Exception as e:
      sys.exit ( "No CONTRAIL_ANALYTICS_API defined" )

  # parse contrail-api url
  contrail_api_url = urlparse (contrail_api)
  contrail_api_server_host = contrail_api_url.hostname
  contrail_api_server_port = contrail_api_url.port
  if contrail_api_url.scheme == 'http':
    contrail_api_server_use_ssl = False
  elif contrail_api_url.scheme == 'https':
    contrail_api_server_use_ssl = True
  else:
    sys.exit("Error: Contrail API URL has wrong scheme " + str(contrail_api_url.scheme) )

  # check if contrail-api is reachable and alive
  try:
    response = requests.get(url=contrail_api)
  except requests.exceptions.RequestException:
    sys.exit ( "Connection error to " + str(contrail_api) )

  if response.status_code != 200:
    sys.exit ( "Error connecting to " + str(contrail_api) + " with response status code " + str(response.status_code) )

  # parse contrail-analytics-api url
  contrail_analytics_api_url = urlparse (contrail_analytics_api)
  contrail_analytics_api_server_host = contrail_analytics_api_url.hostname
  contrail_analytics_api_server_port = contrail_analytics_api_url.port
  if contrail_analytics_api_url.scheme == 'http':
    contrail_analytics_api_server_use_ssl = False
  elif contrail_analytics_api_url.scheme == 'https':
    contrail_analytics_api_server_use_ssl = True
  else:
    sys.exit("Error: Contrail Analytics API URL has wrong scheme " + str(contrail_analytics_api_url.scheme) )

  # check if contrail-analytics-api is reachable and alive
  try:
    response = requests.get(url=contrail_analytics_api)
  except requests.exceptions.RequestException:
    sys.exit ( "Connection error to " + str(contrail_analytics_api) )

  if response.status_code != 200:
    sys.exit ( "Error connecting to " + str(contrail_analytics_api) + " with response status code " + str(response.status_code) )


  # Contrail vnc_api instance
  vnc_lib = vnc_api.VncApi(api_server_host=contrail_api_server_host, api_server_port=contrail_api_server_port, api_server_use_ssl=contrail_api_server_use_ssl, auth_token=token)

  # get Contrail global system configuration to get the list of contrail nodes
  contrail_global_config = vnc_lib.global_system_config_read([ "default-global-system-config" ])

  # prepare output tables
  table_ps = PrettyTable()
  table_ps._set_field_names ( [ 'Node Name', 'Process Name', 'Process State', 'Last Started', 'Start Count', 'Last Stopped', 'Stop Count', 'Last Exited', 'Exit Count' ] )

  table_pc = PrettyTable()
  table_pc._set_field_names ( [ 'Node Name', '1st Process Name', 'State', '2nd Process Name', 'Type', 'Connection Status' ] )

  table_flow = PrettyTable()
  table_flow._set_field_names ([ 'vRouter', 'active_flows', 'added_flows', 'deleted_flows', 'max_flow_adds_per_second', 'max_flow_deletes_per_second', 'min_flow_adds_per_second', 'min_flow_deletes_per_second' ])

  table_warnings = PrettyTable()
  table_warnings._set_field_names ([ 'Components', 'Warning Message' ])



  # check config nodes
  contrail_config_nodes = contrail_global_config.get_config_nodes()
  if contrail_config_nodes:
    for contrail_config_node in contrail_config_nodes:
      contrail_config_node_name = contrail_config_node['to'][1]

      #Processes status
      [ node_process_info, node_process_status, warnings ]  = analytics_get_node_status (contrail_analytics_api, token, 'config-node', contrail_config_node_name )
      for node_process_info_row in node_process_info:
        table_ps.add_row ( node_process_info_row )
      for node_process_status_row in node_process_status:
        table_pc.add_row ( node_process_status_row )
      for warnings_row in warnings:
        table_warnings.add_row ( warnings_row )

  else:
    table_warnings.add_row ("Global", "No config nodes in global config")



  # check control nodes
  bgp_routers = vnc_lib.bgp_routers_list()
  if bgp_routers:
    for bgp_router in bgp_routers['bgp-routers']:
      bgp_router_cont = vnc_lib.bgp_router_read(bgp_router['fq_name'])
      if bgp_router_cont.bgp_router_parameters.__dict__['router_type'] == 'control-node':
        contrail_controller_node_name = bgp_router_cont.name

        #Processes status
        [ node_process_info, node_process_status, warnings ]  = analytics_get_node_status (contrail_analytics_api, token, 'control-node', contrail_controller_node_name )
        for node_process_info_row in node_process_info:
          table_ps.add_row ( node_process_info_row )
        for node_process_status_row in node_process_status:
          table_pc.add_row ( node_process_status_row )
        for warnings_row in warnings:
          table_warnings.add_row ( warnings_row )

  else:
    table_warnings.add_row ("Global", "No control nodes in global config")


  # check analytics nodes
  contrail_analytics_nodes = contrail_global_config.get_analytics_nodes()
  if contrail_analytics_nodes:
    for contrail_analytics_node in contrail_analytics_nodes:
      contrail_analytics_node_name = contrail_analytics_node['to'][1]

      #Processes status
      [ node_process_info, node_process_status, warnings ]  = analytics_get_node_status (contrail_analytics_api, token, 'analytics-node', contrail_analytics_node_name )
      for node_process_info_row in node_process_info:
        table_ps.add_row ( node_process_info_row )
      for node_process_status_row in node_process_status:
        table_pc.add_row ( node_process_status_row )
      for warnings_row in warnings:
        table_warnings.add_row ( warnings_row )
  else:
    table_warnings.add_row ("Global", "No analytics nodes in global config")


  # check vRouter status
  contrail_vrouter_nodes = contrail_global_config.get_virtual_routers()
  if contrail_vrouter_nodes:
    for contrail_vrouter_node in contrail_vrouter_nodes:
      contrail_vrouter_node_name = contrail_vrouter_node['to'][1]
    
      # Processes status
      [ node_process_info, node_process_status, warnings ]  = analytics_get_node_status (contrail_analytics_api, token, 'vrouter', contrail_vrouter_node_name )
      for node_process_info_row in node_process_info:
        table_ps.add_row ( node_process_info_row )
      for node_process_status_row in node_process_status:
        table_pc.add_row ( node_process_status_row )
      for warnings_row in warnings:
        table_warnings.add_row ( warnings_row )
    
      # vRouter flow stats
      [ node_flow_stats, warnings ]  = get_vrouter_stats ( contrail_analytics_api, token, contrail_vrouter_node_name )
      for node_flow_stats_row in node_flow_stats:
        table_flow.add_row ( node_flow_stats_row )
      for warnings_row in warnings:
        table_warnings.add_row ( warnings_row )

  else:
    table_warnings.add_row ("Global", "No vrouter nodes in global config")

    

  # print tables

  # print Warnings
  print table_warnings

  # print process status table
  print table_ps

  # print process connections table
  print table_pc

  # print vRouter flow info table
  table_flow.sortby = 'active_flows'
  print table_flow

  sys.exit(0)
