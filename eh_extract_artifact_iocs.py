"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'extract_ioc_1' block
    extract_ioc_1(container=container)

    return

def extract_ioc_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('extract_ioc_1() called')

    id_value = container.get('id', None)

    # collect data for 'extract_ioc_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.bodyText', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'extract_ioc_1' call
    for container_item in container_data:
        parameters.append({
            'vault_id': "",
            'file_type': "txt",
            'text': container_item[0],
            'is_structured': "",
            'label': "",
            'max_artifacts': "",
            'container_id': id_value,
            'remap_cef_fields': "Do not apply CEF -> CIM remapping, only apply custom remap",
            'custom_remap_json': "{}",
            'run_automation': "true",
            'severity': "medium",
            'parse_domains': "true",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="extract ioc", parameters=parameters, assets=['email_parser'], callback=playbook_local_eh_investigate_email_iocs_1, name="extract_ioc_1")

    return

def playbook_local_eh_investigate_email_iocs_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_local_eh_investigate_email_iocs_1() called')
    
    # call playbook "local/eh_investigate_email_iocs", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="local/eh_investigate_email_iocs", container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return