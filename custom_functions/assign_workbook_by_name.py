def assign_workbook_by_name(container_id=None, workbook_name=None, **kwargs):
    """
    Assigns workbooks as actions to give granular control on the tasks responders have to do on a case by case basis.
    
    Args:
        container_id
        workbook_name
    
    Returns a JSON-serializable object that implements the configured data paths:
        success
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {"status":False}
    
    container = phantom.get_container(container_id) 
    
    workbook_list = phantom.build_phantom_rest_url('workbook_template')
    response = phantom.requests.get(
        "{}?page_size=0".format(workbook_list),
        verify=False,
    )
    
    try:
        response = json.loads(response.text)
        if "data" in response:
            for item in response['data']:
                if item['name'].lower().strip() == workbook_name.lower().strip():
                    phantom.add_workbook(container, item['id'])
                    break
            outputs['status'] = True
    
    except Exception as e:
        phantom.debug("error in assign_workbook_by_name: {}".format(e))
    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
