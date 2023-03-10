import pefile
import lief


class resources:
	def __init__(self, filepath):
		self.filepath = filepath
		self.pe = pefile.PE(self.filepath)

	def get_resource_names(self):
		# try:
		if not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
			return None
		else:
			resource_names = []
			for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
				if resource_type.name is not None:
					size=resource_type.struct.sizeof()
					rva= hex(resource_type.struct.OffsetToData)
					data = self.pe.get_data(16480, size)
					resource_names.append(resource_type.name.decode())
				else:
					resource_names.append(pefile.RESOURCE_TYPE.get(resource_type.struct.Id))
				if resource_type.directory is not None:
					for resource_id in resource_type.directory.entries:
						if resource_id.name is not None:
							resource_names.append(resource_id.name.decode())
						else:
							resource_names.append(pefile.RESOURCE_TYPE.get(resource_id.struct.Id))
						if resource_id.directory is not None:
							for resource_lang in resource_id.directory.entries:
								resource_names.append(pefile.LANG.get(resource_lang.data.lang))
		return resource_names
		# except Exception as e:
		# 	print("Exception : " + str(e))
		# 	return None	

	def extract_resource(self):
		resource_directory = self.pe.DIRECTORY_ENTRY_RESOURCE
		
		for resource_type in resource_directory.entries:
			# print(dir(resource_type))
			if resource_type.name is None:
				resource_type_name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
			else:
				resource_type_name = resource_type.name.decode()

			for resource_id in resource_type.directory.entries:
				data_rva = resource_id.struct.OffsetToData
				size = resource_id.struct.sizeof()

				print(data_rva)
				print(size)
				