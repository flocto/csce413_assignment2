import requests

url = 'http://172.20.0.21:8888'
api_token = 'FLAG{n3tw0rk_tr4ff1c_1s_n0t_s3cur3}'

s = requests.Session()
s.headers.update({'Authorization': f'Bearer {api_token}'})

r = s.get(f'{url}/flag')
print(r.json())
