import requests

proxie = {
    # 'https': 'https://52.183.8.192:3128'
    'https': 'https://20.27.86.185:80'
    # 'https': 'https://41.204.63.118:80'
    # 'https': 'https://185.139.56.133:6961'
    # 'https': 'https://72.10.164.178:10801'
}
response = requests.get("https://ipinfo.io/json", proxies= proxie)
print(response.text)