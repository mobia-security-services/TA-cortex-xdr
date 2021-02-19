
# encoding = utf-8

import os
import sys
import time
import datetime
import pickle
import json
from pprint import pprint

state_file_name = "cortex_xdr.last"
state_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), state_file_name)

def get_state():
    # attempt to read state file
    try:
        with open(state_file_path, 'rb') as f:
            # return timestamp from state file
            return pickle.load(f)
    except IOError:
        # return current time - 30 minutes as default
        return (int(round(time.time() * 1000))-1800000)

def put_state(next_cursor):
    # set the current timestamp
    cursor = next_cursor

    # update the state file
    with open(state_file_path, 'wb') as f:
        pickle.dump(next_cursor, f, protocol=2)

def validate_input(helper, definition):
    cortex_host = definition.parameters.get('cortex_xdr_host', None)
    cortex_token_id = definition.parameters.get('cortex_xdr_token_id', None)
    cortex_token = definition.parameters.get('cortex_xdr_token', None)
    pass

def collect_events(helper, ew):
    helper.set_log_level(helper.get_log_level())
    
    sourcetype = helper.get_sourcetype()

    opt_cortex_host = helper.get_arg('cortex_xdr_host')
    opt_cortex_token_id = helper.get_arg('cortex_xdr_token_id')
    opt_cortex_token = helper.get_arg('cortex_xdr_token')
    
    if opt_cortex_host == None:
        opt_cortex_host = ""
    if opt_cortex_token_id == None:
        opt_cortex_token_id = ""
    if opt_cortex_token == None:
        opt_cortex_token = ""
        
    opt_cortex_host = opt_cortex_host.strip()
    opt_cortex_token_id = opt_cortex_token_id.strip()
    opt_cortex_token = opt_cortex_token.strip()
    
    
    incident_url="https://{0}/public_api/v1/incidents/get_incidents/".format(opt_cortex_host)
    details_url="https://{0}/public_api/v1/incidents/get_incident_extra_data/".format(opt_cortex_host)
    
    auth_headers = {
            "x-xdr-auth-id": str(opt_cortex_token_id),
            "Authorization": str(opt_cortex_token),
            "Content-Type": "application/json"
        }

    # get the current timestamp
    timestamp = get_state()

    # filter the request using timestamp and incident creation_time
    data = {
        "request_data": {
            "filters": [
                {
                    "field": "creation_time",
                    "operator": "gte",
                    "value": timestamp
                }
            ],
            "sort": {
                "field": "creation_time",
                "keyword": "desc"
            }
        }
    }
    

    helper.log_info("Requesting Incidents: {0}".format(incident_url))
    
    proxy_settings = helper.get_proxy()

    response = helper.send_http_request(incident_url, "POST", parameters=None, payload=data,
                                        headers=auth_headers, cookies=None, verify=False, cert=None,
                                        timeout=30, use_proxy=True)
    
    helper.log_debug(pprint(vars(response), indent=4))

    if response.status_code != 200:
        helper.log_error("Failed to get incident data: {0}".format(response.status_code))
        incidents = None
    else:
        helper.log_info("Incidents retrieved.")
        incidents = response.json()
        put_state((int(round(time.time() * 1000))))

    if(incidents != None and incidents['reply']['total_count'] > 0):
        helper.log_info("{0} Incidents Found.".format(incidents['reply']['total_count']))
        for incident in incidents['reply']['incidents']:
            helper.log_info("BLOOM")
            temp_data = {
                "request_data": {
                    "incident_id": incident['incident_id']
                }
            }
            helper.log_info("Requesting Incident Details: {0}".format(details_url))
            response = helper.send_http_request(details_url, "POST", parameters=None, payload=temp_data,
                                        headers=auth_headers, cookies=None, verify=False, cert=None,
                                        timeout=30, use_proxy=True)
            
            if response.status_code != 200:
                helper.log_error("Failed to get incident data: {0}".format(response.status_code))
                incident_details = None
            else:
                helper.log_info("Incidents extra details found.")
                
                incident_details = response.json()
                helper.log_debug(incident_details)
                
                try:
                    event = helper.new_event(time=round(incident_details['reply']['incident']['creation_time']/1000),source=helper.get_input_stanza_names(), index=helper.get_output_index(), sourcetype=sourcetype, data=json.dumps(incident_details))
                    
                    ew.write_event(event)
                except:
                    helper.log_error(sys.exc_info()[0])
                
    # uncomment to send test event
    # sample1 = {
    #     "reply":{
    #         "incident":{
    #             "incident_id":"<incient ID>",
    #             "incident_name":"test",
    #             "creation_time":int(round(time.time() * 1000)),
    #             "modification_time":int(round(time.time() * 1000)),
    #             "detection_time":None,
    #             "status":"new",
    #             "severity":"high",
    #             "description":"generated by PAN NGFW",
    #             "assigned_user_mail":None,
    #             "assigned_user_pretty_name":None,
    #             "alert_count":1,
    #             "low_severity_alert_count":0,
    #             "med_severity_alert_count":0,
    #             "high_severity_alert_count":1,
    #             "user_count":0,
    #             "host_count":0,
    #             "notes":None,
    #             "resolve_comment":None,
    #             "manual_severity":None,
    #             "manual_description":None,
    #             "xdr_url":"https://test.xdr.us.paloaltonetworks.com/incident-view/1",
    #             "starred":False,
    #             "hosts":None,
    #             "users":[
                    
    #             ],
    #             "incident_sources":[
    #                 "PAN NGFW"
    #             ]
    #         },
    #         "alerts":{
    #             "total_count":1,
    #             "data":[
    #                 {
    #                 "external_id":"<external ID>",
    #                 "severity":"high",
    #                 "matching_status":"UNMATCHABLE",
    #                 "end_match_attempt_ts":None,
    #                 "local_insert_ts":1603175431,
    #                 "bioc_indicator":None,
    #                 "matching_service_rule_id":None,
    #                 "attempt_counter":None,
    #                 "bioc_category_enum_key":None,
    #                 "case_id":1,
    #                 "is_whitelisted":False,
    #                 "starred":False,
    #                 "deduplicate_tokens":"<token value>",
    #                 "filter_rule_id":None,
    #                 "mitre_technique_id_and_name":None,
    #                 "mitre_tactic_id_and_name":None,
    #                 "agent_version":None,
    #                 "agent_device_domain":None,
    #                 "agent_fqdn":None,
    #                 "agent_os_type":"NO_HOST",
    #                 "agent_os_sub_type":None,
    #                 "agent_data_collection_status":None,
    #                 "mac":None,
    #                 "agent_is_vdi":None,
    #                 "agent_install_type":"NA",
    #                 "agent_host_boot_time":None,
    #                 "event_sub_type":None,
    #                 "module_id":None,
    #                 "association_strength":None,
    #                 "dst_association_strength":None,
    #                 "story_id":None,
    #                 "event_id":None,
    #                 "event_type":"Network Event",
    #                 "event_timestamp":None,
    #                 "actor_process_instance_id":None,
    #                 "actor_process_image_path":None,
    #                 "actor_process_image_name":None,
    #                 "actor_process_command_line":None,
    #                 "actor_process_signature_status":"N/A",
    #                 "actor_process_signature_vendor":None,
    #                 "actor_process_image_sha256":None,
    #                 "actor_process_image_md5":None,
    #                 "actor_process_causality_id":None,
    #                 "actor_causality_id":None,
    #                 "actor_process_os_pid":None,
    #                 "actor_thread_thread_id":None,
    #                 "causality_actor_process_image_name":None,
    #                 "causality_actor_process_command_line":None,
    #                 "causality_actor_process_image_path":None,
    #                 "causality_actor_process_signature_vendor":None,
    #                 "causality_actor_process_signature_status":"N/A",
    #                 "causality_actor_causality_id":None,
    #                 "causality_actor_process_execution_time":None,
    #                 "causality_actor_process_image_md5":None,
    #                 "causality_actor_process_image_sha256":None,
    #                 "action_file_path":None,
    #                 "action_file_name":None,
    #                 "action_file_md5":None,
    #                 "action_file_sha256":None,
    #                 "action_file_macro_sha256":None,
    #                 "action_registry_data":None,
    #                 "action_registry_key_name":None,
    #                 "action_registry_value_name":None,
    #                 "action_registry_full_key":None,
    #                 "action_local_ip":"<IP address>",
    #                 "action_local_port":"<port>",
    #                 "action_remote_ip":"<IP address>",
    #                 "action_remote_port":"<port>",
    #                 "action_external_hostname":"<hostname>",
    #                 "action_country":"UNKNOWN",
    #                 "action_process_instance_id":None,
    #                 "action_process_causality_id":None,
    #                 "action_process_image_name":None,
    #                 "action_process_image_sha256":None,
    #                 "action_process_image_command_line":None,
    #                 "action_process_signature_status":"N/A",
    #                 "action_process_signature_vendor":None,
    #                 "os_actor_effective_username":None,
    #                 "os_actor_process_instance_id":None,
    #                 "os_actor_process_image_path":None,
    #                 "os_actor_process_image_name":None,
    #                 "os_actor_process_command_line":None,
    #                 "os_actor_process_signature_status":"N/A",
    #                 "os_actor_process_signature_vendor":None,
    #                 "os_actor_process_image_sha256":None,
    #                 "os_actor_process_causality_id":None,
    #                 "os_actor_causality_id":None,
    #                 "os_actor_process_os_pid":None,
    #                 "os_actor_thread_thread_id":None,
    #                 "fw_app_id":None,
    #                 "fw_interface_from":None,
    #                 "fw_interface_to":None,
    #                 "fw_rule":None,
    #                 "fw_rule_id":None,
    #                 "fw_device_name":None,
    #                 "fw_serial_number":"<serial number>",
    #                 "fw_url_domain":None,
    #                 "fw_email_subject":"",
    #                 "fw_email_sender":None,
    #                 "fw_email_recipient":None,
    #                 "fw_app_subcategory":None,
    #                 "fw_app_category":None,
    #                 "fw_app_technology":None,
    #                 "fw_vsys":None,
    #                 "fw_xff":None,
    #                 "fw_misc":None,
    #                 "fw_is_phishing":"N/A",
    #                 "dst_agent_id":None,
    #                 "dst_causality_actor_process_execution_time":None,
    #                 "dns_query_name":None,
    #                 "dst_action_external_hostname":None,
    #                 "dst_action_country":None,
    #                 "dst_action_external_port":None,
    #                 "alert_id":"1",
    #                 "detection_timestamp":1603184109000,
    #                 "name":"sagcalun",
    #                 "category":"Spyware Detected via Anti-Spyware profile",
    #                 "endpoint_id":None,
    #                 "description":"Spyware Phone Home Detection",
    #                 "host_ip":"<IP address>",
    #                 "host_name":"<hostname>",
    #                 "source":"PAN NGFW",
    #                 "action":"DETECTED_4",
    #                 "action_pretty":"Detected (Raised An Alert)",
    #                 "user_name":None
    #                 }
    #             ]
    #         },
    #         "network_artifacts":{
    #             "total_count":2,
    #             "data":[
    #                 {
    #                 "type":"DOMAIN",
    #                 "alert_count":1,
    #                 "is_manual":False,
    #                 "network_domain":"<domain name>",
    #                 "network_remote_ip":"<IP address>",
    #                 "network_remote_port":"<port>",
    #                 "network_country":"UNKNOWN"
    #                 },
    #                 {
    #                 "type":"IP",
    #                 "alert_count":1,
    #                 "is_manual":False,
    #                 "network_domain":"<domain name>",
    #                 "network_remote_ip":"<IP address>",
    #                 "network_remote_port":"<port>",
    #                 "network_country":"UNKNOWN"
    #                 }
    #             ]
    #         },
    #         "file_artifacts":{
    #             "total_count":0,
    #             "data":[
                    
    #             ]
    #         }
    #     }
    # }
    
    # event1 = helper.new_event(time=round(sample1['reply']['incident']['creation_time']/1000),source=helper.get_input_stanza_names(), index=helper.get_output_index(), sourcetype=sourcetype, data=json.dumps(sample1))
    # ew.write_event(event1)