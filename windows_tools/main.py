# Import necessary modules from windows_tools
import windows_tools.antivirus
import windows_tools.bitlocker
from windows_tools import file_utils
import windows_tools.installed_software
import windows_tools.office
import windows_tools.updates
import windows_tools.users
import windows_tools.virtualization
import windows_tools.server

# Antivirus
# antivirus_result = windows_tools.antivirus.get_installed_antivirus_software()
# print("Antivirus Software:", antivirus_result)

# Bitlocker
# bitlocker_result = windows_tools.bitlocker.get_bitlocker_full_status()
# print("Bitlocker Status:", bitlocker_result)

# File Utilities

# path = "C:\python\windowstools"

# try:
#     file_utils_result = file_utils.get_paths_recursive_and_fix_permissions(path)
#     # Iterate through the results and print them
#     for path in file_utils_result:
#         print(path)
# except Exception as e:
#     print(f"An error occurred: {e}")


# Installed Software
# installed_software_result = windows_tools.installed_software.get_installed_software()
# print("Installed Software:", installed_software_result)

# Office
# office_version = windows_tools.office.get_office_version()
# print("Office:", office_version)

# Windows Updates

# updates_result = windows_tools.updates.get_windows_updates(filter_duplicates=True, include_all_states=False)
# print("Windows Updates:", updates_result)

# Users

# users_result = windows_tools.users.get_users()
# print("Users:", users_result)

# Virtualization
# virtualization_result = windows_tools.virtualization.get_relevant_platform_info()
# print("Virtualization Platform:", virtualization_result)

# Server

# server_result = windows_tools.server.is_windows_server()
# server_result1 = windows_tools.server.is_rds_server()
# print("Server:", server_result)
# print("Server:", server_result1)