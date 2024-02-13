# ------------Ts misy ilavaina azy ty-------------------
import requests

proxie = {
    'https': 'https://147.182.180.242:80'
    # 'https': 'https://20.27.86.185:80'
    # 'https': 'https://185.139.56.133:6961'
    # 'https': 'https://72.10.164.178:10801'
}
response = requests.get("https://ipinfo.io/json", proxies= proxie)
print(response.text)
#------Test each free IP address --------
# response = requests.get("https://free-proxy-list.net")

# import requests
# from bs4 import BeautifulSoup

# # Send a GET request to the website
# url = "https://free-proxy-list.net/"
# response = requests.get(url)

# # Parse the HTML content of the website
# soup = BeautifulSoup(response.content, "html.parser")

# # Extract the IP addresses and ports
# proxies = {}
# table = soup.find("table", {"class": "table table-striped table-bordered"})
# for row in table.find_all("tr")[1:]:
#     cells = row.find_all("td")
#     ip_address = cells[0].text
#     port = cells[1].text
#     protocol = "https"
#     proxy = f"'{protocol}':'https://{ip_address}:{port}'"
#     proxies[proxy] = None

# # Print the extracted IP addresses
# print("Proxies extracted:")
# for proxy in proxies:
#     try:
#         print("1111111111111111111")
#         response = requests.get("https://ipinfo.io/json")
#         print(response.text)
#         print("222222222222222222222222")
#         break
#     except requests.exceptions.ProxyError:
#         print("disoooooooo")
#         break
#     except ProxyError:
