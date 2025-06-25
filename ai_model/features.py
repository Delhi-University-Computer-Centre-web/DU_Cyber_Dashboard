# ai_model/features.py

def extract_features(entry):
    """
    Convert a LogEntry object into a numerical feature vector for ML model.
    Features used:
    1. Status code category (2=OK, 4=client error, 5=server error, etc.)
    2. Request length
    3. Keyword: is admin/restricted endpoint accessed?
    4. Is the method GET/POST or unknown?
    """
    status_group = entry.status // 100

    request_length = len(entry.request) if entry.request else 0

    sensitive_keywords = ['admin', 'login', 'root', 'config', 'wp', '.env']
    keyword_flag = int(any(keyword in entry.request.lower() for keyword in sensitive_keywords))

    method_flag = 0
    if entry.request.startswith("GET"):
        method_flag = 1
    elif entry.request.startswith("POST"):
        method_flag = 2

    return [status_group, request_length, keyword_flag, method_flag]
