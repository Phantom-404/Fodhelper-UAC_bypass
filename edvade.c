// modules / includes used in this code
#include <windows.h>
#include <psapi.h>
#include <intrin.h>
#include <stdio.h>
#define MAX_PROCESSES 1024
int detection_counter = 0;  // if this hits 3 the code thinks its in a sandbox and killes him self (this is not perfect as this was my attempt on removing false positive but i am kinda lazy so yes)
void check_cpu_for_virtualization() { // check for virtual cpu (if a vm is downloaded on the pc its (75% changes on a false positive))
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x1);
    if (cpuInfo[2] & (1 << 31)) {
        printf("[!] Hypervisor detected! Likely running inside a VM.\n");
        detection_counter++;
    } else {
        printf("[+] No hypervisor detected.\n");
    }
}
void check_system_memory() { // check how muchs ram the pc has if its is less then 4 gb it just killes him self
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    unsigned long long totalMemoryMB = memStatus.ullTotalPhys / (1024 * 1024);
    if (memStatus.ullTotalPhys / (1024 * 1024) < 4096) {
        printf("[!] Low RAM detected. Potential sandbox.\n");
        exit(0);
    } else {
        printf("[+] Sufficient RAM available.\n");
    }
}
void detect_sleep_bypass() { // trys to detect if the sleep get shorten if it dose get shorten it kills him self as its 99% sure its in a vm or sandbox
    DWORD start = GetTickCount();
    Sleep(20000);
    DWORD end = GetTickCount();

    if ((end - start) < 20000) {
        printf("[-] Sleep was skipped or shortened. Potential sandbox.\n");
        exit(0);
    } else {
        printf("[+] Sleep timing is normal.\n");
    }
}
void check_vm_files() { // check for drivers installed to check if there is a vm driver installed if there is a vm driver installed it will put in the detection counter cause it could be a false positive
    WIN32_FIND_DATA fileData;
    HANDLE hFind = FindFirstFile("C:\\Windows\\System32\\drivers\\VBox*.sys", &fileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        printf("[!] VirtualBox driver detected: %s\n", fileData.cFileName);
        FindClose(hFind);
        detection_counter++;
    } else {
        printf("[+] No VirtualBox drivers detected.\n");
    }
}
void check_registry() { // check for sertan registry keys
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("[!] VirtualBox registry key detected.\n");
        RegCloseKey(hKey);
        detection_counter++;
    } else {
        printf("[+] No VirtualBox registry key found.\n");
    }
}
void detect_user_interaction() {    // detects if the last 30 seconds there was a key or mouse interaction if there was none he kills him self as its 100% changes its a sandbox / vm
    LASTINPUTINFO lastInput = {0};
    lastInput.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lastInput)) {
        DWORD idleTime = GetTickCount() - lastInput.dwTime;
        if (idleTime > 30000) {
            printf("[!] No user interaction detected. Potential sandbox.\n");
            exit(0);
        } else {
            printf("[+] User activity detected.\n");
        }
    } else {
        printf("[-] Failed to get last input info.\n");
    }
}
void check_virtual_hardware() { // check for more virtual hardware
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    if (sysInfo.dwProcessorType == PROCESSOR_INTEL_386 ||
        sysInfo.dwProcessorType == PROCESSOR_INTEL_486) {
        printf("[+] Unusual CPU detected. Potential sandbox.\n");
        detection_counter++;
    }
    char buffer[128];
    DWORD size = sizeof(buffer);
    if (GetEnvironmentVariable("VBOX_ENV", buffer, size)) {
        printf("[!] VirtualBox environment variable detected.\n");
        detection_counter++;
    } else {
        printf("[+] No virtualization-related environment variables found.\n");
    }
}
void check_exit_condition() {   // this is actual a function that check if there is 3 detecion but i kinda use it as junk code.
    if (detection_counter > 3) {
        printf("[!] More than 3 detections triggered. Exiting program.\n");
        exit(1);
    }
}
void checkRunningProcesses(const wchar_t* processList[], int processCount) {    // check for sertan process running if there is a malicous process running it will kill him self for anti debugging
    DWORD processIds[MAX_PROCESSES];
    DWORD bytesReturned;
    if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        printf("[-] Failed to enumerate processes.\n");
        return;
    }
    int numProcesses = bytesReturned / sizeof(DWORD);
    for (int i = 0; i < numProcesses; i++) {
        DWORD processId = processIds[i];

        if (processId == 0) continue;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess) {
            wchar_t processName[MAX_PATH] = {0};
            if (GetModuleBaseNameW(hProcess, NULL, processName, sizeof(processName) / sizeof(wchar_t))) {
                for (int j = 0; j < processCount; j++) {
                    if (wcscmp(processName, processList[j]) == 0) {
                        printf("[!] Process found: %ls (PID: %lu)\n", processName, processId);
                        Sleep(5000);
                        exit(0);
                    }
                }
            }
            CloseHandle(hProcess);
        }
    }
}
int detect_processes(){ // calls the check running process function and gives the list of the process (i only got 150 process now there are muchs more)
    const wchar_t* processList[] = {
        L"x64dbg.exe", L"ida.exe", L"ida64.exe", L"VsDebugConsole.exe", L"msvsmon.exe", L"ollydbg.exe", L"windbg.exe", L"dbghelp.dll", L"dbgw32.dll", L"gdb.exe", L"apimonitor.exe", L"procmon.exe", L"autoruns.exe",
        L"VMwareTray.exe", L"vboxservice.exe", L"VBoxTray.exe", L"qemu-system-x86_64.exe", L"hyperv.exe", L"pestudio.exe", L"peid.exe", L"Wireshark.exe", L"tshark.exe", L"fiddler.exe", L"burpsuite.exe", 
        L"mitmproxy.exe", L"tcpdump.exe", L"wireshark.exe", L"mimikatz.exe", L"sysmon.exe", L"frida.exe", L"radare2.exe", L"ImmunityDebugger.exe", L"DbgView.exe", L"procmon64.exe", L"hexrays.dll", L"windbgx.exe",
        L"reptile.exe", L"shellcode.exe", L"windbg.exe", L"dbgview64.exe", L"eterlogic.exe", L"jdb.exe", L"tds.exe", L"ted.exe", L"mspdb100.dll", L"gdbserver.exe", L"strace.exe", L"ldd.exe", L"cl.exe", 
        L"valgrind.exe", L"ghidra.exe", L"binaryninja.exe", L"octave.exe", L"sqlmap.exe", L"sqlninja.exe", L"aircrack-ng.exe", L"reaver.exe", L"htop.exe", L"nmap.exe", L"nikto.exe", L"masscan.exe", L"seclists.exe", 
        L"dsniff.exe", L"ettercap.exe", L"tcpdump.exe", L"ettercap.exe", L"burp.exe", L"toxiproxy.exe", L"telerik.exe", L"procexp.exe", L"regshot.exe", L"binwalk.exe", L"ncat.exe", L"shellter.exe", L"cain.exe", 
        L"msfconsole.exe", L"msfvenom.exe", L"z3x.exe", L"MobSF.exe", L"FlexiSPY.exe", L"symantec.exe", L"avast.exe", L"malwarebytes.exe", L"trendmicro.exe", L"hitmanpro.exe", L"mcafee.exe", L"bitdefender.exe", 
        L"nod32.exe", L"webroot.exe", L"windowsdefender.exe", L"forticlient.exe", L"shavlik.exe", L"cisco.exe", L"openvpn.exe", L"mariadb.exe", L"mysql.exe", L"postgres.exe", L"nginx.exe", L"apache.exe", 
        L"tomcat.exe", L"uwsgi.exe", L"redis.exe", L"docker.exe", L"vagrant.exe", L"virtualbox.exe", L"vmware.exe", L"wslhost.exe", L"terraform.exe", L"ansible.exe", L"puppet.exe", L"chef.exe" L"minikube.exe", 
        L"kubectl.exe", L"helm.exe", L"terraform.exe", L"docker-compose.exe", L"artifactory.exe", L"jenkins.exe", L"ci_tool.exe", L"buildbot.exe"
    };
    int processCount = sizeof(processList) / sizeof(processList[0]);
    checkRunningProcesses(processList, processCount);
    check_exit_condition();
    printf("[+] No Blacklisted Process found.\n");
    return 0;
}
int check_detections(){ // main check detection function
    if (detection_counter == 3){
        printf("[-] Sandbox detected! exisiting....\n");
        exit(0);
    }
    return 0;
}
int detect() {  // function to stages all above functions yes ik i can make it smaller and cleaner but i am a lazy programer : D (at least i am transparent)
    Sleep(5000);
    printf("[!] Running sandbox detection...\n");
    detect_processes();
    Sleep(5000);
    detect_user_interaction();
    check_cpu_for_virtualization();
    Sleep(5000);
    check_detections();
    if (detection_counter > 3) {
        check_exit_condition();
        return -1;
    }
    check_detections();
    detect_sleep_bypass();
    check_detections();
    check_system_memory();
    check_detections();
    check_exit_condition();
    check_detections();
    check_exit_condition();
    check_detections();
    check_exit_condition();
    check_detections();
    check_vm_files();
    check_detections();
    check_exit_condition();
    check_detections();
    check_registry();
    check_detections();
    check_exit_condition();
    check_detections();
    check_exit_condition();
    printf("[!] Sandbox detection complete.\n");
    printf("[!] %i out of 3.\n", detection_counter);
    return 0;
}