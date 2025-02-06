# call_api.py

import requests

url = 'http://127.0.0.1:8000/api/my-endpoint/'  # Adjust the URL as per your Django server configuration

try:
    response = requests.get(url)
    print(response.json())  # Assuming the response is JSON; adjust as needed
except requests.exceptions.RequestException as e:
    print(f"Failed to retrieve data: {e}")
