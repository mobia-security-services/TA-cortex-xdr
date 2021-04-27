
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
    cortex_url = definition.parameters.get('cortex_url', None)
    cortex_token_id = definition.parameters.get('cortex_token_id', None)
    cortex_token = definition.parameters.get('cortex_token', None)
    pass

def collect_events(helper, ew):
    """Implement your data collection logic here"""
    
    helper.set_log_level(helper.get_log_level())
    
    sourcetype = helper.get_sourcetype()

    opt_cortex_url = helper.get_arg('cortex_url')
    opt_cortex_token_id = helper.get_arg('cortex_token_id')
    opt_cortex_token = helper.get_arg('cortex_token')
    
    if opt_cortex_url == None:
        opt_cortex_url = ""
    if opt_cortex_token_id == None:
        opt_cortex_token_id = ""
    if opt_cortex_token == None:
        opt_cortex_token = ""
    
    opt_cortex_url = opt_cortex_url.strip()
    opt_cortex_token_id = opt_cortex_token_id.strip()
    opt_cortex_token = opt_cortex_token.strip()
    
    
    incident_url="{0}/public_api/v1/incidents/get_incidents/".format(opt_cortex_url)
    details_url="{0}/public_api/v1/incidents/get_incident_extra_data/".format(opt_cortex_url)
    update_url="{0}/public_api/v1/incidents/update_incident/".format(opt_cortex_url)
    
    auth_headers = {
            "x-xdr-auth-id": str(opt_cortex_token_id),
            "Authorization": str(opt_cortex_token),
            "Content-Type": "application/json"
        }

    # get the current timestamp
    timestamp = get_state()
    helper.log_info("Using timestamp: {0}".format(timestamp))

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
    
    # helper.log_debug(pprint(vars(response), indent=4))

    if response.status_code != 200:
        helper.log_error("Failed to get incident data: {0}".format(response.status_code))
        incidents = None
    else:
        helper.log_info("Incidents retrieved.")
        incidents = response.json()
        next_timestamp = (int(round(time.time() * 1000)))
        put_state(next_timestamp)
        helper.log_info("Updating timestamp: {0}".format(next_timestamp))
    
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
                #sourcetype = helper.get_sourcetype()
                # override sourcetype with _json - duplicate event issue workaround with non _json sourcetype
                event = helper.new_event(time=round(incident_details['reply']['incident']['creation_time']/1000),source=helper.get_input_type(), index=helper.get_output_index(), sourcetype="_json", data=json.dumps(incident_details))
                ew.write_event(event)

                helper.log_info("Resolving Cortex Ticket: {0}".format(incident['incident_id']))
                comment = "A Splunk event ticket has been created for investigation"
                temp_data = {
                    "request_data": {
                        "incident_id":incident['incident_id'],
                        "update_data": {
                            "status":"resolved_other",
                            "resolve_comment":comment
                        }
                    }
                }
                response = helper.send_http_request(update_url, "POST", parameters=None, payload=temp_data,
                                            headers=auth_headers, cookies=None, verify=False, cert=None,
                                            timeout=30, use_proxy=True)

                if response.status_code != 200:
                    helper.log_error("Failed to update Cortex incident: {0}".format(response.status_code))
                    incident_details = None
                else:
                    helper.log_info("Cortex incident resolved: {0}".format(incident['incident_id']))


