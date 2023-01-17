import string
from filetype import GLOBAL
import json
import os
from concurrent.futures import ThreadPoolExecutor


class strings:
	
	def __init__(self):
		self.mal_strings = json.load(open(os.getcwd() + '/../../../json/strings.json','r'))
		self.file = "/home/srihari/Documents/projects/malspark/samples/Chapter_3L/Lab03-04.exe"
		self.printable = set(string.printable)
		self.data = open(self.file, 'rb').read()
		self.collected = []
		self.executor = ThreadPoolExecutor(10)

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
			elif len(extracted_string) >=4:
				self.collected.append(extracted_string)
				extracted_string = ""
				flag = 0
			else:
				flag = 0
				extracted_string = ""

	def pattern_category(self,type, words):
		category_string = []

		category_string.append(type)
		if type == 'files':
			for i in words:
				for j in self.collected:
					if (i in j.strip().lower()) and (j.split(".")[0].lower() not in list(map(str.lower, self.mal_strings['utilities']['util']))):
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
			patterns.append(pattern_list)

		for i in mal_types:
			print(i)
		# print(patterns)
		

obj = strings()
obj.extract_strings()  
obj.pattern_evalution()
