import requests

proxie = {
     'https': 'https://103.148.57.103:30005'
    # 'http': 'https://192.46.233.69:8090',
    # 'https': 'https://41.204.63.118:80'
    # 'https': 'https://185.139.56.133:6961'    hostinger.co.id
    # 'https': 'https://72.10.164.178:10801' https://free-proxy-list.net
}
response = requests.get("https://hostinger.co.id", proxies= proxie) 
print(response.text)

