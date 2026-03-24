import pefile
import traceback

def get_resource_names(filepath):
    # try:
    pe = pefile.PE(filepath)
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return None
    else:
        resource_names = []
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
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
    #     print(e)
    #     return None


filepath = "/home/srihari/Documents/projects/malware_stats/Practical Malware Analysis Labs/BinaryCollection/Chapter_1L/Lab01-01.exe"
# filepath = "/home/srihari/Documents/projects/malspark/samples/Lab01-04.exe"
resources_names = get_resource_names(filepath)
if resources_names is None:
    print("The PE file does not have resources.")
else:
    print("The PE file has the following resources:")
    for resource_name in resources_names:
        print(resource_name)

