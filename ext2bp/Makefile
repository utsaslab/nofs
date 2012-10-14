#
# Makefile for the linux ext2-filesystem routines.
#

obj-m += ext2bp.o

ext2bp-objs := balloc.o dir.o file.o fsync.o ialloc.o inode.o \
	  ioctl.o namei.o super.o symlink.o

#ext2-$(CONFIG_EXT2_FS_XATTR) += xattr.o xattr_user.o xattr_trusted.o
#ext2-$(CONFIG_EXT2_FS_POSIX_ACL) += acl.o
#ext2-$(CONFIG_EXT2_FS_XIP)	 += xip.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
