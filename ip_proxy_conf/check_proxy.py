'https://www.youtube.com/watch?v=FbtCl9jJyyc'
import queue
import requests
import threading

q = queue.Queue()
valid_proxies = []

with open('ip_address_conf/proxy_list.txt', 'r') as list:
    proxies = list.read().split("\n")
    for p in proxies:
        q.put(p)

def check_proxies():
    global q 
    while not q.empty():
        proxy = q.get()
        try:
            res = requests.get('http://ipinfo.io/json', proxies= {"https": proxy, "http": proxy})
            
        except:
            continue
        if res.status_code == 200:
            with open('ip_address_conf/valid_IP.txt', 'a') as valid:
                valid.write(proxy + '\n')
            print(proxy)

for x in range(10):
    threading.Thread(target=check_proxies).start()