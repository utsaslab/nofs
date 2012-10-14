#include <linux/fs.h>
#include <linux/list.h>
#include <linux/ext2bp_fs.h>

/*
 * ext2 mount options
 */
struct ext2_mount_options {
	unsigned long s_mount_opt;
	uid_t s_resuid;
	gid_t s_resgid;
};

/* Ext2bp: Struct for the data scan item */
struct struct_data_scan_item {
	struct super_block *i_sb;
	unsigned long inode_num;
	umode_t is_dir;
	unsigned long data_num;	
	struct list_head list;
};
typedef struct struct_data_scan_item data_scan_item;

/*
 * second extended file system inode data in memory
 */
struct ext2_inode_info {
	__le32	i_data[15];
	__le32	i_backlinks[32];
	__u32	i_flags;
	__u32	i_faddr;
	__u8	i_frag_no;
	__u8	i_frag_size;
	__u16	i_state;
	__u32	i_file_acl;
	__u32	i_dir_acl;
	__u32	i_dtime;

	/*
	 * i_block_group is the number of the block group which contains
	 * this file's inode.  Constant across the lifetime of the inode,
	 * it is ued for making block allocation decisions - we try to
	 * place a file's data blocks near its inode block, and new inodes
	 * near to their parent directory's inode.
	 */
	__u32	i_block_group;

	/* block reservation info */
	struct ext2_block_alloc_info *i_block_alloc_info;

	__u32	i_dir_start_lookup;
#ifdef CONFIG_EXT2_FS_XATTR
	/*
	 * Extended attributes can be read independently of the main file
	 * data. Taking i_mutex even when reading would cause contention
	 * between readers of EAs and writers of regular file data, so
	 * instead we synchronize on xattr_sem when reading or changing
	 * EAs.
	 */
	struct rw_semaphore xattr_sem;
#endif
#ifdef CONFIG_EXT2_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif
	rwlock_t i_meta_lock;

	/*
	 * truncate_mutex is for serialising ext2_truncate() against
	 * ext2_getblock().  It also protects the internals of the inode's
	 * reservation data structures: ext2_reserve_window and
	 * ext2_reserve_window_node.
	 */
	struct mutex truncate_mutex;
	struct inode	vfs_inode;
	struct list_head i_orphan;	/* unlinked but open inodes */
};

/*
 * Inode dynamic state flags
 */
#define EXT2_STATE_NEW			0x00000001 /* inode is newly created */


/*
 * Function prototypes
 */

/*
 * Ok, these declarations are also in <linux/kernel.h> but none of the
 * ext2 source programs needs to include it so they are duplicated here.
 */

static inline struct ext2_inode_info *EXT2_I(struct inode *inode)
{
	return container_of(inode, struct ext2_inode_info, vfs_inode);
}

/* balloc.c */
extern int ext2_bg_has_super(struct super_block *sb, int group);
extern unsigned long ext2_bg_num_gdb(struct super_block *sb, int group);
extern ext2_fsblk_t ext2_new_block(struct inode *, unsigned long, int *);
extern ext2_fsblk_t ext2_new_blocks(struct inode *, unsigned long,
				unsigned long *, int *);
extern void ext2_free_blocks (struct inode *, unsigned long,
			      unsigned long);
extern unsigned long ext2_count_free_blocks (struct super_block *);
extern unsigned long ext2_count_dirs (struct super_block *);
extern void ext2_check_blocks_bitmap (struct super_block *);
extern struct ext2_group_desc * ext2_get_group_desc(struct super_block * sb,
						    unsigned int block_group,
						    struct buffer_head ** bh);
extern void ext2_discard_reservation (struct inode *);
extern int ext2_should_retry_alloc(struct super_block *sb, int *retries);
extern void ext2_init_block_alloc_info(struct inode *);
extern void ext2_rsv_window_add(struct super_block *sb, struct ext2_reserve_window_node *rsv);
extern unsigned ext2bp_mark_block_valid(struct super_block *sb, int block);
extern unsigned ext2bp_mark_block_used(struct super_block *sb, int block);
extern unsigned ext2bp_mark_block_free(struct super_block *sb, int block);
extern unsigned ext2bp_test_block_valid(struct super_block *sb, int block);
extern unsigned ext2bp_test_block_in_use(struct super_block *sb, int block);
extern void ext2bp_check_inmem_bitmap(struct super_block *sb);

/* dir.c */
extern int ext2_add_link (struct dentry *, struct inode *);
extern ino_t ext2_inode_by_name(struct inode *, struct dentry *);
extern int ext2_make_empty(struct inode *, struct inode *);
extern struct ext2_dir_entry_2 * ext2_find_entry (struct inode *,struct dentry *, struct page **);
extern int ext2_delete_entry (struct ext2_dir_entry_2 *, struct page *);
extern int ext2_empty_dir (struct inode *);
extern struct ext2_dir_entry_2 * ext2_dotdot (struct inode *, struct page **);
extern void ext2_set_link(struct inode *, struct ext2_dir_entry_2 *, struct page *, struct inode *);

extern int ext2bp_find_inode_in_dir(struct inode* dir, ino_t ino);
extern int dir_page_contains_backpointer(unsigned long inum, void* pageaddr);

/* fsync.c */
extern int ext2_sync_file (struct file *, struct dentry *, int);

/* ialloc.c */
extern struct inode * ext2_new_inode (struct inode *, int);
extern void ext2_free_inode (struct inode *);
extern unsigned long ext2_count_free_inodes (struct super_block *);
extern void ext2_check_inodes_bitmap (struct super_block *);
extern unsigned long ext2_count_free (struct buffer_head *, unsigned);
extern unsigned ext2bp_mark_inode_valid(struct super_block *sb, int ino);
extern unsigned ext2bp_mark_inode_used(struct super_block *sb, int ino);
extern unsigned ext2bp_mark_inode_free(struct super_block *sb, int ino);
extern unsigned ext2bp_test_inode_valid(struct super_block *sb, int ino);
extern unsigned long get_free_inodes_count(struct super_block *sb, int group);
extern unsigned long get_free_blocks_count(struct super_block *sb, int group);
extern unsigned long get_used_dirs_count(struct super_block *sb, int group);
extern unsigned long inc_free_inodes_count(struct super_block *sb, int group);
extern unsigned long inc_free_blocks_count(struct super_block *sb, int group);
extern unsigned long inc_used_dirs_count(struct super_block *sb, int group);
extern unsigned long dec_free_inodes_count(struct super_block *sb, int group);
extern unsigned long dec_free_blocks_count(struct super_block *sb, int group);
extern unsigned long dec_used_dirs_count(struct super_block *sb, int group);

/* inode.c */
extern struct inode *ext2_iget (struct super_block *, unsigned long);
extern struct inode *ext2bp_iget_without_check (struct super_block *, unsigned long);

extern int ext2_write_inode (struct inode *, int);
extern void ext2_delete_inode (struct inode *);
extern int ext2_sync_inode (struct inode *);
extern int ext2_get_block(struct inode *, sector_t, struct buffer_head *, int);
extern void ext2_truncate (struct inode *);
extern int ext2_setattr (struct dentry *, struct iattr *);
extern void ext2_set_inode_flags(struct inode *inode);
extern void ext2_get_inode_flags(struct ext2_inode_info *);
extern int __ext2_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata);
extern int __ext2bp_write_begin(struct file *file, struct address_space *mapping,
		loff_t pos, unsigned len, unsigned flags,
		struct page **pagep, void **fsdata);
extern void verify_inode_data(struct inode* inode);
extern void verify_each_item(data_scan_item* ditem);
extern void verify_each_data_block(struct super_block* sb, unsigned long block_num);
extern void verify_data_blocks(struct super_block *sb, unsigned long block_num);

/* Vijay: Modified functions for ext2bp */
extern void ext2bp_delete_inode (struct inode *);
extern void ext2bp_truncate (struct inode *);
extern void ext2bp_check_inode(struct super_block *sb, struct ext2_inode* inode, ino_t ino);
extern void ext2bp_get_and_check_inode(struct super_block *sb,  ino_t ino);
extern struct ext2_inode* ext2bp_get_raw_inode(struct super_block *sb,  ino_t ino);
extern bool ext2bp_refer_check(struct super_block *sb, ino_t ino1, ino_t ino2);
/* ioctl.c */
extern long ext2_ioctl(struct file *, unsigned int, unsigned long);
extern long ext2_compat_ioctl(struct file *, unsigned int, unsigned long);

/* namei.c */
struct dentry *ext2_get_parent(struct dentry *child);

/* super.c */
extern void ext2_error (struct super_block *, const char *, const char *, ...)
	__attribute__ ((format (printf, 3, 4)));
extern void ext2_warning (struct super_block *, const char *, const char *, ...)
	__attribute__ ((format (printf, 3, 4)));
extern void ext2_update_dynamic_rev (struct super_block *sb);
extern void ext2_write_super (struct super_block *);
extern void ext2_destroy_inode(struct inode *inode);
/*
 * Inodes and files operations
 */

/* dir.c */
extern const struct file_operations ext2_dir_operations;

/* file.c */
extern const struct inode_operations ext2_file_inode_operations;
extern const struct file_operations ext2_file_operations;
extern const struct file_operations ext2_xip_file_operations;

/* inode.c */
extern const struct address_space_operations ext2_aops;
extern const struct address_space_operations ext2_aops_xip;
extern const struct address_space_operations ext2_nobh_aops;

/* namei.c */
extern const struct inode_operations ext2_dir_inode_operations;
extern const struct inode_operations ext2_special_inode_operations;

/* symlink.c */
extern const struct inode_operations ext2_fast_symlink_inode_operations;
extern const struct inode_operations ext2_symlink_inode_operations;

/* super.c */
extern unsigned int data_scan_done;
extern unsigned int inode_scan_done;
extern spinlock_t data_list_lock;
extern spinlock_t ext2bp_sb_lock;
extern struct struct_data_scan_item* data_scan_list;

static inline ext2_fsblk_t
ext2_group_first_block_no(struct super_block *sb, unsigned long group_no)
{
	return group_no * (ext2_fsblk_t)EXT2_BLOCKS_PER_GROUP(sb) +
		le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
}
