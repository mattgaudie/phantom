def url_encode_string(input_string=None, **kwargs):
    """
    URL encode a string
    
    Args:
        input_string
    
    Returns a JSON-serializable object that implements the configured data paths:
        url_string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import urllib
    
    url_string = urllib.quote(input_string)
    
    outputs = {"url_string": url_string}

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
