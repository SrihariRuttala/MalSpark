import requests
import json
from html2image import Html2Image 
import sys
import socket
from core.static.basic.filetype import GLOBAL

class virustotal:
	def __init__(self):
		self.hash = "625ac05fd47adc3c63700c3b30de79ab"
		# self.hash = "28338b5d4883ceca83b28b5a9ebad94041d03167dd82283fe0ae6632ba02a2fd"
		self.apikey = GLOBAL["static"]["advanced"]["vt_apikey"]

	def search(self):
		token_url = "https://www.virustotal.com/api/v3/widget/url?query=" + str(self.hash)
		url = "https://www.virustotal.com/api/v3/files/" + str(self.hash)

		header = {
			"accept": "application/json",
			"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.5359.125 Safari/537.36",
			"x-apikey": self.apikey
		}

		response = requests.get(token_url, headers=header)
		json_response = json.loads(response.text)
		detections = json_response['data']['detection_ratio']['detections']
		total = json_response['data']['detection_ratio']['total']

		lable_response = requests.get(url, headers=header)
		json_response = json.loads(lable_response.text)
		try:
			threat_label = json_response['data']['attributes']['popular_threat_classification']['suggested_threat_label']
		except KeyError:
			threat_label = "None"
		return detections, total, threat_label

		# token = json_response["data"]["url"].split("html/")[1]

		# widget_url = "https://www.virustotal.com/ui/widget/html/" + str(token)
		# response = requests.get(widget_url, headers=header)

		# hti = Html2Image()
		# hti.screenshot(html_str=response.text, save_as='virustotal.png')

	def check_connection(self):
		try:
			host = socket.gethostbyname("one.one.one.one")
			s = socket.create_connection((host, 80), 2)
			s.close()
			return True
		except:
			pass
		return False


