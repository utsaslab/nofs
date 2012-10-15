The No-Order File System
========================

*The No-Order File System (NoFS) is a simple, lightweight file system that employs a novel technique called backpointer-based consistency to provide crash consistency without ordering writes as they go to disk. NoFS is robust to crashes, and delivers excellent performance across a range of workloads.*

The NoFS [project page](http://pages.cs.wisc.edu/~vijayc/nofs.htm) provides a high level overview. For technical details, please read the [FAST 2012](http://static.usenix.org/events/fast12/) paper [Consistency Without Ordering](http://www.cs.wisc.edu/adsl/Publications/nofs-fast12.pdf). Please [cite this publication](http://research.cs.wisc.edu/adsl/Publications/nofs-fast12.bib) if you use this work.

This project contains the linux kernel and file system code that we used in the paper. Another name for NoFS is ext2bp (reflecting that the code is the result of adding backpointers (bp) to ext2). The term ext2bp is used extensively in the code.  

Please feel free to <a href="http://cs.wisc.edu/~vijayc">contact me</a> with any questions.

#### Description

The code has three main parts. 

**e2fsprogs-1.41.12**
This is a modified version of e2fsprogs. It allows the user to create a nofs file system (mke2bpfs) and debug it (debugfs).

**ext2bp** 
This is the core NoFS file system. It is written as an independent kernel module. It has some dependencies in the kernel which are provided by the kernel patch. 

**nofs_kernel.patch**
This includes changes to the Linux 2.6.27.55 kernel to support NoFS. This patch has to be applied to the kernel before NoFS can be run in it.   

#### Usage
* Make the e2fsprogs
<pre>cd e2fsprogs-1.41.12/; make;</pre>

* Make the new NoFS file system
<pre>cd misc; ./mke2bfs /dev/sdb</pre>

* Patch the kernel.
<pre>cd linux-2.6.27.55/; patch -p1 &lt; nofs_kernel.patch; </pre>

* Compile and install the kernel.
<pre>make; make modules; make modules_install; make install</pre>

* Reboot the machine into the new kernel.

* Extract the ext2bp folder and move into the kernel tree
<pre>mv ext2bp linux-2.6.27.55/fs/</pre>

* Compile the kernel module
<pre>cd linux-2.6.27.55/fs/ext2bp; make</pre>

* Load the kernel module
<pre>insmod ext2bp.ko</pre>

* Mount the file system 
<pre>mount -t ext2bp /dev/sdb /mnt/test</pre>

#### Caveats 

This version of the code does not contain block offsets. Backpointers only contain inode numbers. We intend to clean up and upload the version that includes block offsets soon. The code is a bit more verbose than strictly required as many functions were introduced purely for debugging purposes.  
