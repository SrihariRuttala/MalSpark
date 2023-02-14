# Python program to find the type of Ip address

# re module provides support
# for regular expressions
import re
import math
import pefile
import os
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

def entropy(filepath):
    # Open the file and read its contents
    with open(filepath, "rb") as f:
        contents = f.read()

    # Create a frequency dictionary for each byte value
    frequency = {}
    for b in contents:
        if b in frequency:
            frequency[b] += 1
        else:
            frequency[b] = 1

    # Compute the entropy
    entropy = 0
    for b in frequency.values():
        p = b / len(contents)
        entropy -= p * math.log(p, 256)

    return entropy

def entropy1(filepath):

	for file in self.files:
		filepath = self.path + file
		byte = [0 for i in range(256)]
		with open(filepath, 'rb') as f:
			data = f.read()
			entropy = 0
			for i in range(len(data)):
				byte[data[i]] += 1

			for i in range(256):
				temp = byte[i]/len(data)
				if temp:
					entropy += (-math.log(temp)/math.log(2))* byte[i]

			entropy = entropy/len(data)

		print(entropy)

		return entropy

def get_stack_strings(file_path):
    pe = pefile.PE(file_path)

    # Get the address of the .rdata section
    rdata_section = [section for section in pe.sections if section.Name.decode().strip() == '.rdata'][0]
    rdata_offset = rdata_section.VirtualAddress
    rdata_size = rdata_section.Misc_VirtualSize

    # Read the .rdata section into memory
    rdata = pe.get_memory_mapped_image()[rdata_offset:rdata_offset + rdata_size]

    # Search for stack strings in the .rdata section
    stack_strings = re.findall(b'[\x20-\x7E]+', rdata)

    return stack_strings

file_path = "path/to/your/pe_file.exe"
stack_strings = get_stack_strings(file_path)
print(stack_strings)

		


# Driver Code
if __name__ == '__main__' :
	
	# # Enter the Ip address
	# Ip = "192.0.2.126"
	
	# # calling run function
	# find(Ip)

	# Ip = "3001:0da8:75a3:0000:0000:8a2e:0370:7334"
	# find(Ip)

	# Ip = "36.12.08.20.52"
	# find(Ip)
	filepath = '/home/srihari/Documents/projects/malware_stats/not-packed/crop-auto.exe'
	entropy_value = entropy1(filepath)
	print("Entropy of {}: {} bits per byte".format(filepath, round(entropy_value, 5))
