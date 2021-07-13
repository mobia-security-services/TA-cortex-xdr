
# encoding = utf-8

import os
import sys
import time
import datetime
import pickle
import json
from pprint import pprint

state_file_name = "cortex_xdrednpoint.last"
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
    
    endpoints_url="{0}/public_api/v1/endpoints/get_endpoints/".format(opt_cortex_url)
    
    auth_headers = {
            "x-xdr-auth-id": str(opt_cortex_token_id),
            "Authorization": str(opt_cortex_token),
            "Content-Type": "application/json"
        }

    # get the current timestamp
    timestamp = get_state()
    helper.log_info("Using timestamp: {0}".format(timestamp))
    
    helper.log_info("Requesting Endpoints: {0}".format(endpoints_url))
    
    proxy_settings = helper.get_proxy()

    response = helper.send_http_request(endpoints_url, "POST", parameters=None, payload={},
                                        headers=auth_headers, cookies=None, verify=False, cert=None,
                                        timeout=30, use_proxy=True)

    if response.status_code != 200:
        helper.log_error("Failed to get endpoints data: {0}".format(response.status_code))
        incidents = None
    else:
        helper.log_info("Endpoints retrieved.")
        endpoints = response.json()
        next_timestamp = (int(round(time.time() * 1000)))
        put_state(next_timestamp)
        helper.log_info("Updating timestamp: {0}".format(next_timestamp))
        import_time = "{:.3f}".format(time.time())
        #sourcetype = helper.get_sourcetype()
        sourcetype="_json"
        
        for endpoint in endpoints['reply']:
            event = helper.new_event(time=import_time, index=helper.get_output_index(), sourcetype=sourcetype, data=json.dumps(endpoint))
            ew.write_event(event)


