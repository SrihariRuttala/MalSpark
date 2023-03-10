import string
from core.static.basic.filetype import GLOBAL
import json
import os
from concurrent.futures import ThreadPoolExecutor
import re
from core.static.basic.modules import modules


class strings:
	
	def __init__(self):
		self.mal_strings = json.load(open(os.getcwd() + '/json/strings.json','r'))
		self.file = "/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-04.exe"
		self.printable = set(string.printable)
		self.data = open(self.file, 'rb').read()
		self.collected = []
		self.executor = ThreadPoolExecutor(10)
		self.min_length = GLOBAL["static"]["basic"]["minimum_string_length"]

	def advanced_strings(self):
		strings = []
		url_pattern = re.compile(r'(http[s]?://)?(www\.)[a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)+(:[0-9]+)?(/.*)*')
		
		ipv4_pattern = re.compile(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
		
		ipv6_regex = '''(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|
        ([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:)
        {1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1
        ,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}
        :){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{
        1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA
        -F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a
        -fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0
        -9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,
        4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}
        :){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9
        ])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0
        -9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]
        |1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]
        |1{0,1}[0-9]){0,1}[0-9]))'''

		email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
		
		for i in self.collected:
			match = url_pattern.search(i)
			ipv4_match = ipv4_pattern.search(i)
			ipv6_match = re.search(ipv6_regex, i)
			email_match = email_pattern.search(i)
			if match:
				self.collected.remove(i)
				strings.append(match.group())
			if ipv4_match:
				self.collected.remove(i)
				strings.append(ipv4_match.group())
			if ipv6_match:
				self.collected.remove(i)
				strings.append(ipv6_match.group())
			if email_match:
				self.collected.remove(i)
				strings.append(email_match.group())

		return strings

	def extract_strings(self):
		# print(self.data)
		flag = 0
		extracted_string = ""
		self.printable.remove("\n")
		self.printable.remove('\x0c')
		self.printable.remove("\x0b")
		for char in self.data:
			char = chr(char)
			if char in self.printable:
				if flag ==0 and char == " ":
					pass
				else:
					extracted_string += char
					flag =1
			elif len(extracted_string) >= self.min_length:
				self.collected.append(extracted_string)
				extracted_string = ""
				flag = 0
			else:
				flag = 0
				extracted_string = ""
		self.collectable = self.collected
		return self.collected

	def pattern_category(self,type, words):
		category_string = []

		category_string.append(type)
		if type == 'files':
			for i in words:
				for j in self.collected:
					if (i == ("." + j.split('.')[-1].strip().lower())) and (j.split(".")[0].lower() not in list(map(str.lower, self.mal_strings['utilities']['util']))):
						category_string.append(j)
						self.collected.remove(j)
		elif type== 'utilities':
			for i in words:
				for j in self.collected:
					if (i.lower() == j.strip().lower()) or (j.split(".")[0].lower() == i.lower()):
						category_string.append(j)
						self.collected.remove(j)
		else:
			for i in words:
				for j in self.collected:
					if i.lower() == j.strip().lower():
						category_string.append(j)
						self.collected.remove(j)

		return category_string

	

	def pattern_evalution(self):
		mal_types = list(self.mal_strings.keys())
		sub_type = []
		patterns = []
		for i in range(len(mal_types)):
			ele = list(self.mal_strings[mal_types[i]].keys())[0]
			sub_type.append(ele)


		for i in range(len(mal_types)):
			pattern_list = self.pattern_category(mal_types[i], self.mal_strings[mal_types[i]][sub_type[i]])
			if len(pattern_list) != 1:
				patterns.append(pattern_list)

		return patterns

	def get_modules(self):
		obj = modules(self.file)
		imports = obj.get_imports()
		exports = obj.get_exports()

		imports_keys = list(imports.keys())
		imports_values = list(imports.values())
		extracted_imports = []
		extracted_exports = []
		for i in self.collectable:
			flag = 0
			for j in exports:
				if i.strip().lower() == j.lower():
					exported_exports.append(i)
					flag = 1
					
			if flag==0:
				for j in imports_keys:
					if i.strip().lower() == j.lower():
						extracted_imports.append(i)
						flag = 1
				if flag == 0:
					for j in imports_values:
						for k in j:
							if i.strip().lower() == k.strip().lower():
								extracted_imports.append(i)

		self.collected = [ele for ele in self.collected if ele not in extracted_imports]
		self.collected = [ele for ele in self.collected if ele not in extracted_exports]

		return extracted_imports, extracted_exports, self.collected

# obj = strings()
# obj.extract_strings()  
# obj.advanced_strings()
# obj.pattern_evalution()
