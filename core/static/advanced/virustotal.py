import requests
import json
from html2image import Html2Image 
import sys

sys.path.append('../../../')

from core.static.basic.filetype import GLOBAL

class virustotal:
	def __init__(self):
		self.hash = "84882c9d43e23d63b82004fae74ebb61"
		self.apikey = GLOBAL["static"]["advanced"]["vt_apikey"]

	def search(self):
		token_url = "https://www.virustotal.com/api/v3/widget/url?query=" + str(self.hash)
		
		print(self.apikey)
		header = {
			"accept": "application/json",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36",
			"x-apikey": self.apikey
		}

		response = requests.get(token_url, headers=header)
		json_response = json.loads(response.text)
		token = json_response["data"]["url"].split("html/")[1]
		
		widget_url = "https://www.virustotal.com/ui/widget/html/" + str(token)
		response = requests.get(widget_url, headers=header)

		hti = Html2Image()
		hti.screenshot(html_str=response.text, save_as='virustotal.png')


obj = virustotal()
obj.search()
