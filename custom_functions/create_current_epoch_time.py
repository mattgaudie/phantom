def create_current_epoch_time(**kwargs):
    """
    Create an epoch time to add to artifacts, containers, comments and more.
    
    Returns a JSON-serializable object that implements the configured data paths:
        epoch_time
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import calendar;
    import time;
    import datetime;
    
    outputs = {}
    
    ts = time.time()
    phantom.debug(ts)
    #outputs.append({"epoch_time": ts})
    outputs['epoch_time'] = ts
    phantom.debug(outputs)
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
    