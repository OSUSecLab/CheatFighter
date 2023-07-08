#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

int memfd;

void _pmparser_split_line(
        char*buf,char*addr1,char*addr2,
        char*perm,char* offset,char* device,char*inode,
        char* pathname){
    //
    int orig=0;
    int i=0;
    //addr1
    while(buf[i]!='-'){
        addr1[i-orig]=buf[i];
        i++;
    }
    addr1[i]='\0';
    i++;
    //addr2
    orig=i;
    while(buf[i]!='\t' && buf[i]!=' '){
        addr2[i-orig]=buf[i];
        i++;
    }
    addr2[i-orig]='\0';

    //perm
    while(buf[i]=='\t' || buf[i]==' ')
        i++;
    orig=i;
    while(buf[i]!='\t' && buf[i]!=' '){
        perm[i-orig]=buf[i];
        i++;
    }
    perm[i-orig]='\0';
    //offset
    while(buf[i]=='\t' || buf[i]==' ')
        i++;
    orig=i;
    while(buf[i]!='\t' && buf[i]!=' '){
        offset[i-orig]=buf[i];
        i++;
    }
    offset[i-orig]='\0';
    //dev
    while(buf[i]=='\t' || buf[i]==' ')
        i++;
    orig=i;
    while(buf[i]!='\t' && buf[i]!=' '){
        device[i-orig]=buf[i];
        i++;
    }
    device[i-orig]='\0';
    //inode
    while(buf[i]=='\t' || buf[i]==' ')
        i++;
    orig=i;
    while(buf[i]!='\t' && buf[i]!=' '){
        inode[i-orig]=buf[i];
        i++;
    }
    inode[i-orig]='\0';
    //pathname
    pathname[0]='\0';
    while(buf[i]=='\t' || buf[i]==' ')
        i++;
    orig=i;
    while(buf[i]!='\t' && buf[i]!=' ' && buf[i]!='\n'){
        pathname[i-orig]=buf[i];
        i++;
    }
    pathname[i-orig]='\0';

}


long get_module_base(int pid, char *memory_range_name) {
    char *pcVar1;
    char acStack1096 [1024];
    char acStack72 [32];
    char *local_28;
    char *local_20;
    char *local_18;
    FILE *local_10;
    long local_8;

    local_8 = 0;
    snprintf(acStack72,0x20,"/proc/%d/maps",pid);
    local_10 = fopen(acStack72,"r");
    char addr1[20],addr2[20], perm[8], offset[20], dev[10],inode[30],pathname[50];
    if (local_10 != (FILE *)0x0) {
        do {
            pcVar1 = fgets(acStack1096,0x400,local_10);
            if (pcVar1 == (char *)0x0) goto LAB_0010171c;
            local_20 = acStack1096;
            local_28 = memory_range_name;
            _pmparser_split_line(pcVar1,addr1,addr2,perm,offset, dev,inode,pathname);
            pcVar1 = strstr(local_20, memory_range_name);
        } while (pcVar1 == (char *)0x0 || perm[1] != 'w');
        local_18 = strtok(acStack1096,"-");
        local_8 = strtoul(local_18,(char **)0x0,0x10);
        if (local_8 == 0x8000) {
            local_8 = 0;
        }
        LAB_0010171c:
        fclose(local_10);
    }
    return local_8;
}


long find_pid_of(char *package_name)
{
    int iVar1;
    char acStack1096 [1024];
    char acStack72 [32];
    FILE *local_28;
    long local_1c;
    dirent *local_18;
    DIR *local_10;
    long local_4;

    local_4 = 0xffffffff;
    if (package_name == (char *)0x0) {
        local_4 = 0xffffffff;
    }
    else {
        local_10 = opendir("/proc");
        if (local_10 == (DIR *)0x0) {
            local_4 = 0xffffffff;
        }
        else {
            do {
                do {
                    do {
                        local_18 = readdir(local_10);
                        if (local_18 == (dirent *)0x0) goto LAB_001015ec;
                        local_1c = atoi(local_18->d_name);
                    } while (local_1c == 0);
                    sprintf(acStack72,"/proc/%ld/cmdline",(long)local_1c);
                    local_28 = fopen(acStack72,"r");
                } while (local_28 == (FILE *)0x0);
                fgets(acStack1096,0x400,local_28);
                fclose(local_28);
                iVar1 = strcmp(package_name, acStack1096);
            } while (iVar1 != 0);
            local_4 = local_1c;
            LAB_001015ec:
            closedir(local_10);
        }
    }
    return local_4;
}
// libil2cpp.so [0x71BFBBF000] + [0x151C48] -> 0x71BFD10C48 + [0xB8] -> 0x71BFD10C48 + [0x0] -> 0x71B99FC938 + [0xB0] -> 0x71D0B99CC0 + [0x48] -> 0x71D0BCF4A0 + [0x58] -> 0x71D0BD0DC8 + [0x5C] -> 0x71D0B4A878 -> 22


//Pistol: libil2cpp.so [0x71BFBB7000] + [0x150B68] -> 0x71BFD07B68 + [0xB8] -> 0x71BFD07B68 + [0x20] -> 0x71BDD8FF38 + [0x18] -> 0x71D0A6FD40 + [0x78] -> 0x71B92914F8 + [0x50] -> 0x70B7F25AF8 + [0x20] -> 0x70BD194C20 + [0x5C] -> 0x71B3B0ECE0 -> 17
//AR: libil2cpp.so [0x71BFBB7000] + [0x150B68] -> 0x71BFD07B68 + [0xB8] -> 0x71BFD07B68 + [0x20] -> 0x71BDD8FF38 + [0x18] -> 0x71D0A6FD40 + [0xC0] -> 0x71B92914F8 + [0x50] -> 0x70B7F25B40 + [0x20] -> 0x70BD251440 + [0x5C] -> 0x71B23AA050 -> 50
///data/app/com.SAUnity.SAUnity-fbWKLzoE9_TVvOWi0HisPw==/lib/arm64/libil2cpp.so [0x7EFC72F000] + [0x6A68A0] -> 0x7EFCDD58A0 + [0xB8] -> 0x7EFCDD58A0 + [0x8] -> 0x7EF3F4E838 + [0x18] -> 0x7EF6C31F38 + [0xC0] -> 0x7EF6FED738 + [0x50] -> 0x7E00C7CB40 + [0x20] -> 0x7E07F055F0 + [0x5C] -> 0x7E0BFA3E30 -> 30
/**[0xDF728] 
 * -> 0x76E4EAB728 + [0x80] 
 * -> 0x76E4EAB728 + [0xB8] 
 * -> 0x76E4F1C210 + [0x60] 
 * -> 0x76E1373CB8 + [0xB0] 
 * -> 0x76E2FBCCC0 + [0x48] 
 * -> 0x76E2FE74A0 + [0x58] 
 * -> 0x76E2FF3DC8 + [0x5C] 
 * -> 0x76E29F47A8 -> 50
 **/
long readValue(long address, long offset)
{
  long local_8 = 0;
  long final_address = address + offset;
  pread64(memfd, &local_8, 8, final_address);
  printf("read address: %lx,\t [%lx + %lx] found: %lx\n", final_address, address, offset, local_8);
  return local_8;
}

int readValueI(long address)
{
  int local_8 = 0;
  pread64(memfd, &local_8, 4, address);
  printf("read address: %lx,\t found: %d\n", address, local_8);
  return local_8;
}

void writeValueI(long address, int value)
{
    pwrite64(memfd, &value, 4, address);
}

int main(int argc, char** argv)
{
    // int option = 0;
    int updated_ammo = 7523;
    if (argc > 1)
    {
        updated_ammo = atoi(argv[1]);
    }
    // if (argc > 2)
    // {
    //     updated_ammo = atoi(argv[2]);
    // }
    long pid = find_pid_of("com.SAUnity.SAUnity");
    printf("PID: %d\n", pid);
    char *local_28 = (char *)calloc(1,0x3c);
    sprintf(local_28,"/proc/%d/mem",pid);
    memfd = open(local_28,2);
    long libil2cpp_base = get_module_base(pid, "libil2cpp.so");
    long pistol_ammo_address = readValue(readValue(readValue(readValue(readValue(readValue(readValue(libil2cpp_base, 0x150B68), 0xB8) , 0x20), 0x18), 0x78), 0x50) , 0x20)  + 0x5C;
    int pistol_ammo = readValueI(pistol_ammo_address);

    long ar_ammo_address = readValue(readValue(readValue(readValue(readValue(readValue(readValue(libil2cpp_base, 0xDF728), 0x80) , 0xB8), 0x60), 0xB0), 0x48) , 0x58)  + 0x5C;
    int ar_ammo = readValueI(pistol_ammo_address);

    printf("libil2cpp base: %lx\n", libil2cpp_base);
    printf("Pistol Ammo Address: %lx\n", pistol_ammo_address);
    printf("Pistol Ammo: %d\n", pistol_ammo);

    printf("AR Ammo Address: %lx\n", ar_ammo_address);
    printf("AR Ammo: %d\n", ar_ammo);

    // if (option) {
        writeValueI(pistol_ammo_address, updated_ammo);
    // } else {
        writeValueI(ar_ammo_address, updated_ammo);
    // }
    printf("New Pistol Ammo: %d\n", readValueI(pistol_ammo_address));
    printf("New AR Ammo: %d\n", readValueI(ar_ammo_address));
    return 0;
}


