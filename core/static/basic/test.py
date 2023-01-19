# Python program to find the type of Ip address

# re module provides support
# for regular expressions
import re

# Make a regular expression
# for validating an Ipv4
ipv4 = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''

# Make a regular expression
# for validating an Ipv6
ipv6 = '''(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|
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

# Define a function for finding
# the type of Ip address
def find(Ip):

	# pass the regular expression
	# and the string in search() method
	match = re.search(ipv4, Ip)
	if match:
		print(match.group())
	elif re.search(ipv6, Ip):
		print("IPv6")
	else:
		print("Neither")

# Driver Code
if __name__ == '__main__' :
	
	# Enter the Ip address
	Ip = "192.0.2.126"
	
	# calling run function
	find(Ip)

	Ip = "3001:0da8:75a3:0000:0000:8a2e:0370:7334"
	find(Ip)

	Ip = "36.12.08.20.52"
	find(Ip)
