# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from alienvaultotxv2_consts import *
import requests
import json
from bs4 import BeautifulSoup
from datetime import datetime, timedelta


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class AlienvaultOtxv2Connector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(AlienvaultOtxv2Connector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._api_key = None

        # Ingest settings
        self._container_limit = None
        self._start_time = None
        self._artifact_limit = None

        # Required values can be accessed directly
        # Map OTX indicator types to CEF fields
        self._cef_mapping = dict()

    def _extract_otx_summary(self, response):

        # Generate the OTX summary
        summary = dict()
        summary['count'] = 0
        summary['found'] = 0
        summary['pulse_count'] = 0
        summary['pulse_0_name'] = 0

        if 'pulse_info' in response:
            if 'count' in response['pulse_info']:
                summary['count'] = response['pulse_info']['count']
                if summary['count'] > 0:
                    summary['found'] = True
            else:
                summary['count'] = 0
                summary['found'] = False

            pulse_count = len(response['pulse_info']['pulses'])
            summary['pulse_count'] = len(response['pulse_info']['pulses'])
            if pulse_count > 0:
                summary['pulse_0_name'] = response['pulse_info']['pulses'][0]['name']
                # message = "Domain was found inside in an OTX Pulse as:[" + str(summary['pulse_0_name']) + "]"

        if 'data' in response:
            if 'count' in response:
                summary['count'] = response['count']
                if summary['count'] > 0:
                    summary['found'] = True
            else:
                summary['count'] = 0
                summary['found'] = False

            if len(response['data']) > 0:
                if 'hash' in response['data'][0]:
                    summary['pulse_0_name'] = response['data'][0]['hash']

        return summary

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, u"Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = u'\n'.join(split_lines)
        except:
            error_text = u"Cannot parse error details"

        message = u"Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace(u'{', u'{{').replace(u'}', u'}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = u"Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace(u'{', u'{{').replace(u'}', u'}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = u"Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint
        otx_headers = {
            'X-OTX-API-KEY': self._api_key,
            'User-Agent': 'OTX Python 1/1.1',
            'Content-Type': 'application/json'
        }
        kwargs = {"headers": otx_headers}

        try:
            r = request_func(
                            url,
                            # auth=(username, password),  # basic authentication
                            verify=config.get('verify_server_cert', False),
                            **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, u"Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call('/api/v1/user/me', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_on_poll(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary
        if self.is_poll_now():
            domax_containers = param.get('container_count')
            domax_artifacts = param.get('artifact_count')
        else:
            domax_containers = self._container_limit
            domax_artifacts = self._artifact_limit

        # Required values can be accessed directly
        # required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # get and record state

        # self._start_time
        current_time = datetime.utcnow().isoformat()
        modified_since = self._state.get('modified_since', (datetime.utcnow() - timedelta(days=1)).isoformat())
        # temp holding Endpoint
        endpoint = "/api/v1/pulses/subscribed?modified_since:{0}&page=1".format(modified_since)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        self.save_progress("Handling Response")
        self.save_progress("Artifact limit {0}".format(domax_artifacts))
        self.save_progress("Container limit {0}".format(domax_containers))
        self.save_progress("Processing Pulses since {0}".format(modified_since))
        containers = []
        for pulse in response['results']:
            if len(containers) < domax_containers:
                self.save_progress("Processing Pulse {0}".format(pulse["id"]))
                container = {"description": "Container added by AlienVault OTX", "run_automation": False,
                             'name': pulse["name"], 'artifacts': [], "source_data_identifier": pulse["id"]}
                self.save_progress("Collecting Artifacts...")
                artifact_count = 0
                for indicator in pulse['indicators']:
                    if indicator['type'] in self._cef_mapping:
                        artifact = {"label": "otx",
                                    "type": self._cef_mapping.get(indicator['type'])['type'],
                                    "name": self._cef_mapping.get(indicator['type'])['name'],
                                    "description": "Artifact added by AlienVault OTX",
                                    "cef": {
                                        self._cef_mapping.get(indicator['type'])['name']: indicator['indicator']
                                    }
                                    }
                        # self.save_progress("Added {0} ".format(indicator))
                        if artifact_count < domax_artifacts:
                            artifact_count += 1
                            container['artifacts'].append(artifact)
                        else:
                            self.save_progress("Artifact current limit reached ")
                            break
                    else:
                        self.save_progress("Indicator type {0} not supported, ignoring".format(indicator['type']))
                self.save_progress("Added {0} indicators".format(artifact_count))
                containers.append(container)
            else:
                self.save_progress("Container limit reached {0}".format(len(containers)))
                break
        # Done with the collection
        self.save_progress("Saving all containers and adding artifacts...")
        self._state['modified_since'] = current_time
        status, message, container_responses = self.save_containers(containers)
        # self.save_progress("Container response {0} ".format(container_responses))
        # Add the response into the data section
        # action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(status)

    def _handle_domain_reputation(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        domain = param['domain']
        section = param['section']
        endpoint = "/api/v1/indicators/domain/" + domain + "/" + section

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Construct the summary dict

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary(self._extract_otx_summary(response))
        print (summary)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ip_reputation(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        ip = param['ip']
        endpoint = "/api/v1/indicators/IPv4/" + ip + "/general"

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Construct the summary dict

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary(self._extract_otx_summary(response))
        print (summary)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_file_reputation(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        hash = param['hash']
        endpoint = "/api/v1/indicators/file/" + hash + "/general"

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary(self._extract_otx_summary(response))
        print (summary)
        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def _handle_url_reputation(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        url = param['url']
        endpoint = "/api/v1/indicators/url/" + url + "/general"

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary(self._extract_otx_summary(response))
        print (summary)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        elif action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        elif action_id == 'domain_reputation':
            ret_val = self._handle_domain_reputation(param)

        elif action_id == 'ip_reputation':
            ret_val = self._handle_ip_reputation(param)

        elif action_id == 'file_reputation':
            ret_val = self._handle_file_reputation(param)

        elif action_id == 'url_reputation':
            ret_val = self._handle_url_reputation(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config['base_url']
        self._api_key = config['api_key']
        # Ingest settings
        self._start_time = config['start_time']
        self._container_limit = int(config['container_count'])
        self._artifact_limit = int(config['artifact_count'])

        self._cef_mapping = {
            'FileHash-MD5': {'name': 'fileHashMd5', 'type': 'hash'},
            'FileHash-SHA256': {'name': 'fileHashSha256', 'type': 'sha256'},
            'FileHash-SHA1': {'name': 'fileHashSha1', 'type': 'sha1'},
            'domain': {'name': 'destinationDnsDomain', 'type': 'host'},
            'IPv4': {'name': 'destinationAddress', 'type': 'ip'},
            'URL': {'name': 'requestURL', 'type': 'url'},
            'hostname': {'name': 'destinationDnsDomain', 'type': 'domain'},
            'email': {'name': 'destinationAddress', 'type': 'email'},
            'CIDR': {'name': 'destinationAddress', 'type': 'ip'}
        }

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = AlienvaultOtxv2Connector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)