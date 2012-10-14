/*
 *  linux/fs/ext2/ialloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  BSD ufs-inspired inode and directory allocation by 
 *  Stephen Tweedie (sct@dcs.ed.ac.uk), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 * Author: Vijay Chidambaram (vijayc@cs.wisc.edu)
 */

#include <linux/quotaops.h>
#include <linux/sched.h>
#include <linux/backing-dev.h>
#include <linux/buffer_head.h>
#include <linux/random.h>
#include "ext2.h"
#include "xattr.h"
#include "acl.h"

/*
 * ialloc.c contains the inodes allocation and deallocation routines
 */

/*
 * The free inodes are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.
 */


/*
 * Read the inode allocation bitmap for a given block_group, reading
 * into the specified slot in the superblock's bitmap cache.
 *
 * Return buffer_head of bitmap on success or NULL.
 */
static struct buffer_head *
read_inode_bitmap(struct super_block * sb, unsigned long block_group)
{
	struct ext2_group_desc *desc;
	struct buffer_head *bh = NULL;

	desc = ext2_get_group_desc(sb, block_group, NULL);
	if (!desc)
		goto error_out;

	bh = sb_bread(sb, le32_to_cpu(desc->bg_inode_bitmap));
	if (!bh)
		ext2_error(sb, "read_inode_bitmap",
			    "Cannot read inode bitmap - "
			    "block_group = %lu, inode_bitmap = %u",
			    block_group, le32_to_cpu(desc->bg_inode_bitmap));
error_out:
	return bh;
}

/* Vijay: Modifying function to update in-mem group desc for ext2bp */
static void ext2_release_inode(struct super_block *sb, int group, int dir)
{
	struct ext2_group_desc * desc;
	struct buffer_head *bh;

	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	// Modifying in-mem group desc. Lock protected.
	EXT2_SB(sb)->bg_free_inodes_counts[group]+= 1;

	if (dir) {
		EXT2_SB(sb)->bg_used_dirs_counts[group] -= 1;
		BUG_ON(EXT2_SB(sb)->bg_used_dirs_counts[group] < 0);
	}
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	
	spin_lock(&ext2bp_sb_lock);
	if (dir)
		percpu_counter_dec(&EXT2_SB(sb)->s_dirs_counter);
	spin_unlock(&ext2bp_sb_lock);

	sb->s_dirt = 1;
}

/* Vijay: Setting the validity bit for the inode in ext2bp */
unsigned ext2bp_mark_inode_valid(struct super_block *sb, int ino) {
	if (!((EXT2_SB(sb))->s_inode_validity_bitmap)) {
		printk("Inside ext2bp_mark_inode_valid: Validity bitmap is NULL");
		return -1;
	}
	ext2bp_debug("Setting validity bitmap for inode %lu\n", ino);
	unsigned long block_group = (ino - 1) / EXT2_INODES_PER_GROUP(sb);
	unsigned prev = ext2_set_bit_atomic(sb_bgl_lock(EXT2_SB(sb), block_group),
			ino - 1, (void *) (EXT2_SB(sb))->s_inode_validity_bitmap);
	return prev;
}

/* Vijay: Setting the availability bit for the inode in ext2bp */
unsigned ext2bp_mark_inode_used(struct super_block *sb, int ino) {
	if (!((EXT2_SB(sb))->s_inode_availability_bitmap)) {
		printk("Inside ext2bp_mark_inode_used: Availability bitmap is NULL");
		return -1;
	}

	ext2bp_debug("Setting avail bitmap for inode %lu\n", ino);
	unsigned long block_group = (ino - 1) / EXT2_INODES_PER_GROUP(sb);
	unsigned prev = ext2_set_bit_atomic(sb_bgl_lock(EXT2_SB(sb), block_group),
			ino - 1, (void *) (EXT2_SB(sb))->s_inode_availability_bitmap);
	if (prev) {
		ext2_error (sb, "ext2bp_mark_inode_used",
				"Inode %lu has been marked in use", ino);
	}
	
	return prev;
}

/* Vijay: Clearing the availability bit for the inode in ext2bp */
unsigned ext2bp_mark_inode_free(struct super_block *sb, int ino) {
	if (!((EXT2_SB(sb))->s_inode_availability_bitmap)) {
		printk("Inside ext2bp_mark_inode_free: Availability bitmap is NULL");
		return -1;
	}
	ext2bp_debug("Clearing avail bitmap for inode %lu\n", ino);
	
	unsigned long block_group = (ino - 1) / EXT2_INODES_PER_GROUP(sb);
	unsigned prev = ext2_clear_bit_atomic(sb_bgl_lock(EXT2_SB(sb), block_group),
			ino - 1, (void *) (EXT2_SB(sb))->s_inode_availability_bitmap);
	return prev;
}

/* Vijay: Test if an inode is valid. It is ok not to use locks here since 
 * it is used for debugging purposes.
 */
unsigned ext2bp_test_inode_valid(struct super_block *sb, int ino) {
	if (!((EXT2_SB(sb))->s_inode_validity_bitmap)) {
		printk("Inside ext2bp_mark_inode_used: Availability bitmap is NULL");
		return 0;
	}
	return ext2_test_bit(ino - 1, (unsigned long *)EXT2_SB(sb)->s_inode_validity_bitmap); 
}

/* Ext2bp: Getter functions for the in memory statistics. These are protected
 * by the induvidual group locks.
 */
unsigned long get_free_inodes_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_free_inodes_counts)) {
		printk("get_free_inodes_count: bg_free_inodes_counts is NULL");
		return 0;
	}
	unsigned long ans = 0;
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	ans = EXT2_SB(sb)->bg_free_inodes_counts[group]; 
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return ans;
}

unsigned long get_free_blocks_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_free_blocks_counts)) {
		printk("get_free_blocks_count: bg_free_blocks_counts is NULL");
		return 0;
	}
	unsigned long ans = 0;
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	ans = EXT2_SB(sb)->bg_free_blocks_counts[group]; 
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return ans;
}

unsigned long get_used_dirs_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_used_dirs_counts)) {
		printk("get_used_dirs_count: bg_used_dirs_counts is NULL");
		return 0;
	}
	unsigned long ans = 0;
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	ans = EXT2_SB(sb)->bg_used_dirs_counts[group]; 
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return ans;
}

/* Ext2bp: Increment and decrement functions for the in mem stats.
 */
unsigned long inc_free_inodes_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_free_inodes_counts)) {
		printk("inc_free_inodes_count: bg_free_inodes_counts is NULL");
		return 0;
	}
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	EXT2_SB(sb)->bg_free_inodes_counts[group]++;
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return 1;
}

unsigned long inc_free_blocks_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_free_blocks_counts)) {
		printk("inc_free_blocks_count: bg_free_blocks_counts is NULL");
		return 0;
	}
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	EXT2_SB(sb)->bg_free_blocks_counts[group]++; 
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return 1;
}

unsigned long inc_used_dirs_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_used_dirs_counts)) {
		printk("inc_used_dirs_count: bg_used_dirs_counts is NULL");
		return 0;
	}
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	EXT2_SB(sb)->bg_used_dirs_counts[group]++;
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return 1;
}

unsigned long dec_free_inodes_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_free_inodes_counts)) {
		printk("dec_free_inodes_count: bg_free_inodes_counts is NULL");
		return 0;
	}
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	EXT2_SB(sb)->bg_free_inodes_counts[group]--;
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return 1;
}

unsigned long dec_free_blocks_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_free_blocks_counts)) {
		printk("dec_free_blocks_count: bg_free_blocks_counts is NULL");
		return 0;
	}
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	EXT2_SB(sb)->bg_free_blocks_counts[group]--; 
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return 1;
}

unsigned long dec_used_dirs_count(struct super_block *sb, int group) {
	if (!((EXT2_SB(sb))->bg_used_dirs_counts)) {
		printk("dec_used_dirs_count: bg_used_dirs_counts is NULL");
		return 0;
	}
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	EXT2_SB(sb)->bg_used_dirs_counts[group]--;
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
	return 1;
}

/*
 * NOTE! When we get the inode, we're the only people
 * that have access to it, and as such there are no
 * race conditions we have to worry about. The inode
 * is not on the hash-lists, and it cannot be reached
 * through the filesystem because the directory entry
 * has been deleted earlier.
 *
 * HOWEVER: we must make sure that we get no aliases,
 * which means that we have to call "clear_inode()"
 * _before_ we mark the inode not in use in the inode
 * bitmaps. Otherwise a newly created file might use
 * the same inode number (not actually the same pointer
 * though), and then we'd have two inodes sharing the
 * same inode number and space on the harddisk.
 */
void ext2_free_inode (struct inode * inode)
{
	ext2bp_debug("ext2_free_inode called for %lu\n", inode->i_ino);
	struct super_block * sb = inode->i_sb;
	int is_directory;
	unsigned long ino;
	struct buffer_head *bitmap_bh = NULL;
	unsigned long block_group;
	unsigned long bit;
	struct ext2_super_block * es;

	ino = inode->i_ino;
	ext2_debug ("freeing inode %lu\n", ino);

	/*
	 * Note: we must free any quota before locking the superblock,
	 * as writing the quota to disk may need the lock as well.
	 */
	if (!is_bad_inode(inode)) {
		/* Quota is already initialized in iput() */
		ext2_xattr_delete_inode(inode);
	    	DQUOT_FREE_INODE(inode);
		DQUOT_DROP(inode);
	}

	es = EXT2_SB(sb)->s_es;
	is_directory = S_ISDIR(inode->i_mode);

	/* Do this BEFORE marking the inode not in use or returning an error */
	clear_inode (inode);

	if (ino < EXT2_FIRST_INO(sb) ||
	    ino > le32_to_cpu(es->s_inodes_count)) {
		ext2_error (sb, "ext2_free_inode",
			    "reserved or nonexistent inode %lu", ino);
	}
	block_group = (ino - 1) / EXT2_INODES_PER_GROUP(sb);
	bit = (ino - 1) % EXT2_INODES_PER_GROUP(sb);

	/* Ok, now we can actually update the inode bitmaps.. */
	if (!ext2bp_mark_inode_free(sb, ino)) { 

		/*
		 * This is no longer always an error, since this can be called as part of the scan
		 * process where the inode has not yet been updated - We will be deleting a dead
   		 * inode at that point.
		 */
		if (inode_scan_done) {
			ext2_error (sb, "ext2_free_inode",
					"bit already cleared for inode %lu", ino);
		}
	}  else {
		ext2bp_debug("Calling release inode\n");
		ext2_release_inode(sb, block_group, is_directory);
	}
}

/*
 * We perform asynchronous prereading of the new inode's inode block when
 * we create the inode, in the expectation that the inode will be written
 * back soon.  There are two reasons:
 *
 * - When creating a large number of files, the async prereads will be
 *   nicely merged into large reads
 * - When writing out a large number of inodes, we don't need to keep on
 *   stalling the writes while we read the inode block.
 *
 * FIXME: ext2_get_group_desc() needs to be simplified.
 */
static void ext2_preread_inode(struct inode *inode)
{
	unsigned long block_group;
	unsigned long offset;
	unsigned long block;
	struct ext2_group_desc * gdp;
	struct backing_dev_info *bdi;
	struct super_block *sb = inode->i_sb;

	bdi = inode->i_mapping->backing_dev_info;
	if (bdi_read_congested(bdi))
		return;
	if (bdi_write_congested(bdi))
		return;

	block_group = (inode->i_ino - 1) / EXT2_INODES_PER_GROUP(inode->i_sb);

	/*
	 * Figure out the offset within the block group inode table
	 */
	offset = ((inode->i_ino - 1) % EXT2_INODES_PER_GROUP(inode->i_sb)) *
				EXT2_INODE_SIZE(inode->i_sb);

	block = EXT2_SB(sb)->bg_inode_tables[block_group] +
				(offset >> EXT2_BLOCK_SIZE_BITS(inode->i_sb));

	sb_breadahead(inode->i_sb, block);
}

/*
 * There are two policies for allocating an inode.  If the new inode is
 * a directory, then a forward search is made for a block group with both
 * free space and a low directory-to-inode ratio; if that fails, then of
 * the groups with above-average free space, that group with the fewest
 * directories already is chosen.
 *
 * For other inodes, search forward from the parent directory\'s block
 * group to find a free inode.
 */
static int find_group_dir(struct super_block *sb, struct inode *parent)
{
	int ngroups = EXT2_SB(sb)->s_groups_count;
	int avefreei = ext2_count_free_inodes(sb) / ngroups;
	struct ext2_group_desc *desc, *best_desc = NULL;
	int group, best_group = -1;

	for (group = 0; group < ngroups; group++) {
		desc = ext2_get_group_desc (sb, group, NULL);
		if (!desc || !desc->bg_free_inodes_count)
			continue;
		if (le16_to_cpu(desc->bg_free_inodes_count) < avefreei)
			continue;
		if (!best_desc || 
		    (le16_to_cpu(desc->bg_free_blocks_count) >
		     le16_to_cpu(best_desc->bg_free_blocks_count))) {
			best_group = group;
			best_desc = desc;
		}
	}
	if (!best_desc)
		return -1;

	return best_group;
}

/* Vijay: Modifying the vanilla inode allocator for ext2bp. We need to be
   using the in-memory descriptors, not the disk ones */
static int ext2bp_find_group_dir(struct super_block *sb, struct inode *parent)
{
	int ngroups = EXT2_SB(sb)->s_groups_count;
	int avefreei = ext2_count_free_inodes(sb) / ngroups;
	struct ext2_group_desc *desc, *best_desc = NULL;
	int group, best_group = -1;
	unsigned long long mx_free_block_counts = -1;
	struct ext2_sb_info *sbi = EXT2_SB(sb);

	for (group = 0; group < ngroups; group++) {
	    unsigned long freei_group = get_free_inodes_count(sb, group);
		unsigned long freeb_group = get_free_blocks_count(sb, group);

		if (freei_group < avefreei)
			continue;
		if (freeb_group > mx_free_block_counts) {
			best_group = group;
			mx_free_block_counts = freeb_group;
		}
	}
	if (mx_free_block_counts == -1) return -1;
	
	return best_group;
}

/* 
 * Orlov's allocator for directories. 
 * 
 * We always try to spread first-level directories.
 *
 * If there are blockgroups with both free inodes and free blocks counts 
 * not worse than average we return one with smallest directory count. 
 * Otherwise we simply return a random group. 
 * 
 * For the rest rules look so: 
 * 
 * It's OK to put directory into a group unless 
 * it has too many directories already (max_dirs) or 
 * it has too few free inodes left (min_inodes) or 
 * it has too few free blocks left (min_blocks) or 
 * it's already running too large debt (max_debt). 
 * Parent's group is preferred, if it doesn't satisfy these 
 * conditions we search cyclically through the rest. If none 
 * of the groups look good we just look for a group with more 
 * free inodes than average (starting at parent's group). 
 * 
 * Debt is incremented each time we allocate a directory and decremented 
 * when we allocate an inode, within 0--255. 
 */ 

#define INODE_COST 64
#define BLOCK_COST 256

static int find_group_orlov(struct super_block *sb, struct inode *parent)
{
	int parent_group = EXT2_I(parent)->i_block_group;
	struct ext2_sb_info *sbi = EXT2_SB(sb);
	struct ext2_super_block *es = sbi->s_es;
	int ngroups = sbi->s_groups_count;
	int inodes_per_group = EXT2_INODES_PER_GROUP(sb);
	int freei;
	int avefreei;
	int free_blocks;
	int avefreeb;
	int blocks_per_dir;
	int ndirs;
	int max_debt, max_dirs, min_blocks, min_inodes;
	int group = -1, i;
	struct ext2_group_desc *desc;

	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	avefreei = freei / ngroups;
	free_blocks = percpu_counter_read_positive(&sbi->s_freeblocks_counter);
	avefreeb = free_blocks / ngroups;
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);

	if ((parent == sb->s_root->d_inode) ||
	    (EXT2_I(parent)->i_flags & EXT2_TOPDIR_FL)) {
		struct ext2_group_desc *best_desc = NULL;
		int best_ndir = inodes_per_group;
		int best_group = -1;

		get_random_bytes(&group, sizeof(group));
		parent_group = (unsigned)group % ngroups;
		for (i = 0; i < ngroups; i++) {
			group = (parent_group + i) % ngroups;
			desc = ext2_get_group_desc (sb, group, NULL);
			if (!desc || !desc->bg_free_inodes_count)
				continue;
			if (le16_to_cpu(desc->bg_used_dirs_count) >= best_ndir)
				continue;
			if (le16_to_cpu(desc->bg_free_inodes_count) < avefreei)
				continue;
			if (le16_to_cpu(desc->bg_free_blocks_count) < avefreeb)
				continue;
			best_group = group;
			best_ndir = le16_to_cpu(desc->bg_used_dirs_count);
			best_desc = desc;
		}
		if (best_group >= 0) {
			desc = best_desc;
			group = best_group;
			goto found;
		}
		goto fallback;
	}

	if (ndirs == 0)
		ndirs = 1;	/* percpu_counters are approximate... */

	blocks_per_dir = (le32_to_cpu(es->s_blocks_count)-free_blocks) / ndirs;

	max_dirs = ndirs / ngroups + inodes_per_group / 16;
	min_inodes = avefreei - inodes_per_group / 4;
	min_blocks = avefreeb - EXT2_BLOCKS_PER_GROUP(sb) / 4;

	max_debt = EXT2_BLOCKS_PER_GROUP(sb) / max(blocks_per_dir, BLOCK_COST);
	if (max_debt * INODE_COST > inodes_per_group)
		max_debt = inodes_per_group / INODE_COST;
	if (max_debt > 255)
		max_debt = 255;
	if (max_debt == 0)
		max_debt = 1;

	for (i = 0; i < ngroups; i++) {
		group = (parent_group + i) % ngroups;
		desc = ext2_get_group_desc (sb, group, NULL);
		if (!desc || !desc->bg_free_inodes_count)
			continue;
		if (sbi->s_debts[group] >= max_debt)
			continue;
		if (le16_to_cpu(desc->bg_used_dirs_count) >= max_dirs)
			continue;
		if (le16_to_cpu(desc->bg_free_inodes_count) < min_inodes)
			continue;
		if (le16_to_cpu(desc->bg_free_blocks_count) < min_blocks)
			continue;
		goto found;
	}

fallback:
	for (i = 0; i < ngroups; i++) {
		group = (parent_group + i) % ngroups;
		desc = ext2_get_group_desc (sb, group, NULL);
		if (!desc || !desc->bg_free_inodes_count)
			continue;
		if (le16_to_cpu(desc->bg_free_inodes_count) >= avefreei)
			goto found;
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback;
	}

	return -1;

found:
	return group;
}

/* Vijay: Modifying the orlov allocator for ext2bp. We need to be using the
   in-memory descriptors, not the disk ones */
static int ext2bp_find_group_orlov(struct super_block *sb, struct inode *parent)
{
	int parent_group = EXT2_I(parent)->i_block_group;
	struct ext2_sb_info *sbi = EXT2_SB(sb);
	struct ext2_super_block *es = sbi->s_es;
	int ngroups = sbi->s_groups_count;
	int inodes_per_group = EXT2_INODES_PER_GROUP(sb);
	int freei;
	int avefreei;
	int free_blocks;
	int avefreeb;
	int blocks_per_dir;
	int ndirs;
	int max_debt, max_dirs, min_blocks, min_inodes;
	int group = -1, i;
	struct ext2_group_desc *desc;

	spin_lock(&ext2bp_sb_lock);
	freei = percpu_counter_read_positive(&sbi->s_freeinodes_counter);
	free_blocks = percpu_counter_read_positive(&sbi->s_freeblocks_counter);
	ndirs = percpu_counter_read_positive(&sbi->s_dirs_counter);
	spin_unlock(&ext2bp_sb_lock);

	avefreeb = free_blocks / ngroups;
	avefreei = freei / ngroups;

	if ((parent == sb->s_root->d_inode) ||
	    (EXT2_I(parent)->i_flags & EXT2_TOPDIR_FL)) {
		struct ext2_group_desc *best_desc = NULL;
		int best_ndir = inodes_per_group;
		int best_group = -1;

		get_random_bytes(&group, sizeof(group));
		parent_group = (unsigned)group % ngroups;
		for (i = 0; i < ngroups; i++) {
			group = (parent_group + i) % ngroups;
			unsigned long freei_group = get_free_inodes_count(sb, group);
			unsigned long freeb_group = get_free_blocks_count(sb, group);
			unsigned long useddir_group = get_used_dirs_count(sb, group);

			if (useddir_group >= best_ndir)
				continue;
			if (freei_group < avefreei)
				continue;
			if (freeb_group < avefreeb)
				continue;
			best_group = group;
			best_ndir = useddir_group;
		}
		if (best_group >= 0) {
			group = best_group;
			goto found;
		}
		goto fallback;
	}

	if (ndirs == 0)
		ndirs = 1;	/* percpu_counters are approximate... */

	blocks_per_dir = (le32_to_cpu(es->s_blocks_count)-free_blocks) / ndirs;

	max_dirs = ndirs / ngroups + inodes_per_group / 16;
	min_inodes = avefreei - inodes_per_group / 4;
	min_blocks = avefreeb - EXT2_BLOCKS_PER_GROUP(sb) / 4;

	max_debt = EXT2_BLOCKS_PER_GROUP(sb) / max(blocks_per_dir, BLOCK_COST);
	if (max_debt * INODE_COST > inodes_per_group)
		max_debt = inodes_per_group / INODE_COST;
	if (max_debt > 255)
		max_debt = 255;
	if (max_debt == 0)
		max_debt = 1;

	for (i = 0; i < ngroups; i++) {
		group = (parent_group + i) % ngroups;
		unsigned long freei_group = get_free_inodes_count(sb, group);
		unsigned long freeb_group = get_free_blocks_count(sb, group);
		unsigned long useddir_group = get_used_dirs_count(sb, group);

		if (sbi->s_debts[group] >= max_debt)
			continue;
		if (useddir_group >= max_dirs)
			continue;
		if (freei_group < min_inodes)
			continue;
		if (freeb_group < min_blocks)
			continue;
		goto found;
	}

fallback:
	for (i = 0; i < ngroups; i++) {
		group = (parent_group + i) % ngroups;
		unsigned long freei_group = get_free_inodes_count(sb, group);
		if (freei_group >= avefreei)
			goto found;
	}

	if (avefreei) {
		/*
		 * The free-inodes counter is approximate, and for really small
		 * filesystems the above test can fail to find any blockgroups
		 */
		avefreei = 0;
		goto fallback;
	}

	return -1;

found:
	return group;
}

static int find_group_other(struct super_block *sb, struct inode *parent)
{
	int parent_group = EXT2_I(parent)->i_block_group;
	int ngroups = EXT2_SB(sb)->s_groups_count;
	struct ext2_group_desc *desc;
	int group, i;

	/*
	 * Try to place the inode in its parent directory
	 */
	group = parent_group;
	desc = ext2_get_group_desc (sb, group, NULL);
	if (desc && le16_to_cpu(desc->bg_free_inodes_count) &&
			le16_to_cpu(desc->bg_free_blocks_count))
		goto found;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	group = (group + parent->i_ino) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some
	 * free blocks.
	 */
	for (i = 1; i < ngroups; i <<= 1) {
		group += i;
		if (group >= ngroups)
			group -= ngroups;
		desc = ext2_get_group_desc (sb, group, NULL);
		if (desc && le16_to_cpu(desc->bg_free_inodes_count) &&
				le16_to_cpu(desc->bg_free_blocks_count))
			goto found;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */
	group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++group >= ngroups)
			group = 0;
		desc = ext2_get_group_desc (sb, group, NULL);
		if (desc && le16_to_cpu(desc->bg_free_inodes_count))
			goto found;
	}

	return -1;

found:
	return group;
}

/* Vijay: Modifying for ext2bp, using in-mem group descriptors instead of
   on disk ones */
static int ext2bp_find_group_other(struct super_block *sb, struct inode *parent)
{
	int parent_group = EXT2_I(parent)->i_block_group;
	int ngroups = EXT2_SB(sb)->s_groups_count;
	struct ext2_group_desc *desc;
	int group, i;
	struct ext2_sb_info *sbi = EXT2_SB(sb);

	/*
	 * Try to place the inode in its parent directory
	 */
	group = parent_group;
	unsigned long freei_group = get_free_inodes_count(sb, group);
	unsigned long freeb_group = get_free_blocks_count(sb, group);

	if (freei_group && freeb_group)
		goto found;

	/*
	 * We're going to place this inode in a different blockgroup from its
	 * parent.  We want to cause files in a common directory to all land in
	 * the same blockgroup.  But we want files which are in a different
	 * directory which shares a blockgroup with our parent to land in a
	 * different blockgroup.
	 *
	 * So add our directory's i_ino into the starting point for the hash.
	 */
	group = (group + parent->i_ino) % ngroups;

	/*
	 * Use a quadratic hash to find a group with a free inode and some
	 * free blocks.
	 */
	for (i = 1; i < ngroups; i <<= 1) {
		group += i;
		if (group >= ngroups)
			group -= ngroups;
		freei_group = get_free_inodes_count(sb, group);
		freeb_group = get_free_blocks_count(sb, group);
		if (freei_group && freeb_group)
			goto found;
	}

	/*
	 * That failed: try linear search for a free inode, even if that group
	 * has no free blocks.
	 */
	group = parent_group;
	for (i = 0; i < ngroups; i++) {
		if (++group >= ngroups)
			group = 0;
		freei_group = get_free_inodes_count(sb, group);
		if (freei_group)
			goto found;
	}

	return -1;

found:
	return group;
}

/*
 * Ext2bp - The allocation strategy is group by group, which is changed to
 * reading off the in-memory bitmaps.
*/
struct inode *ext2_new_inode(struct inode *dir, int mode)
{
	struct super_block *sb;
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *bh2;
	int group, i;
	ino_t ino = 0;
	struct inode * inode;
	struct ext2_group_desc *gdp;
	struct ext2_super_block *es;
	struct ext2_inode_info *ei;
	struct ext2_sb_info *sbi;
	int err;

	sb = dir->i_sb;
	inode = new_inode(sb);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	ei = EXT2_I(inode);
	sbi = EXT2_SB(sb);
	es = sbi->s_es;

	if (S_ISDIR(mode)) {
		if (test_opt(sb, OLDALLOC)) {
			ext2bp_debug("Calling ext2bp_find_group_dir\n");
			group = ext2bp_find_group_dir(sb, dir);

		} else {
			ext2bp_debug("Calling the new orlov func\n");
			group = ext2bp_find_group_orlov(sb, dir);
		}

	} else { 
		ext2bp_debug("Calling ext2bp_find_group_other\n");
		group = ext2bp_find_group_other(sb, dir);
	}

	if (group == -1) {
		err = -ENOSPC;
		goto fail;
	}

	unsigned long ori_ino = 0, ext2bp_ino = 0;

find_via_ext2bp:
	ext2bp_debug("Finding inode via ext2bp bitmap\n");	
	for (i = 0; i < sbi->s_groups_count; i++) {
		ino = 0;
		if (!group) ino = EXT2_FIRST_INO(sb);
		else ino = group * EXT2_SB(sb)->s_inodes_per_group;

repeat_in_this_group_for_ext2bp:

		spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
		ino = ext2_find_next_zero_bit((unsigned long *)EXT2_SB(sb)->s_inode_availability_bitmap, EXT2_SB(sb)->s_groups_count * EXT2_INODES_PER_GROUP(sb), ino);

		unsigned int validity_status = 	ext2_test_bit(ino, (unsigned long *)EXT2_SB(sb)->s_inode_validity_bitmap);
		spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));

		if (!validity_status) {
			// This inode hasnt been read from disk yet, can't trust its bitmap status
			// Search for next free bit in this group
			ino++;
			ext2bp_debug("Inode not valid, going to repeat again\n");
			goto repeat_in_this_group_for_ext2bp;
		}
	
		ext2bp_ino = ino;	
		goto got;
	}

	/*
	 * Scanned all blockgroups.
	 */
	err = -ENOSPC;
	goto fail;
got:

	ino = ext2bp_ino;
	ino++;
	if (ino < EXT2_FIRST_INO(sb) || ino > le32_to_cpu(es->s_inodes_count)) {
		ext2_error (sb, "ext2_new_inode",
			    "reserved inode or inode > inodes count - "
			    "block_group = %d,inode=%lu", group,
			    (unsigned long) ino);
		err = -EIO;
		goto fail;
	}
	/* Vijay: The inode number calculated before the got label is local to the group, 
	   and starts with 0. For example, in the 100th group 3rd inode, the inode number 
           will be 3 - The global inode number is calculated only here */ 

	/* Why are we not adding in the group information here? Because ino is global
	 * inode number, not local one. Ignore previous comment. 
	 */
	ext2bp_mark_inode_used(sb, ino);
	
	spin_lock(&ext2bp_sb_lock);
	percpu_counter_add(&sbi->s_freeinodes_counter, -1);
	if (S_ISDIR(mode))
			percpu_counter_inc(&sbi->s_dirs_counter);
	spin_unlock(&ext2bp_sb_lock);

	spin_lock(sb_bgl_lock(sbi, group));
	/* 
	 * Ext2bp: Direct dec instead of calling dec_free_inodes_count. 
	 * This is alright since it's protected by a lock. 
	 */
	sbi->bg_free_inodes_counts[group]--;
	if (S_ISDIR(mode)) {
		sbi->bg_used_dirs_counts[group]++;
		if (sbi->s_debts[group] < 255)
			sbi->s_debts[group]++;
	} else {
		if (sbi->s_debts[group])
			sbi->s_debts[group]--;
	}
	spin_unlock(sb_bgl_lock(sbi, group));

	sb->s_dirt = 1;
	inode->i_uid = current->fsuid;
	if (test_opt (sb, GRPID))
		inode->i_gid = dir->i_gid;
	else if (dir->i_mode & S_ISGID) {
		inode->i_gid = dir->i_gid;
		if (S_ISDIR(mode))
			mode |= S_ISGID;
	} else
		inode->i_gid = current->fsgid;
	inode->i_mode = mode;

	inode->i_ino = ino;
	ext2bp_debug("Inode %d now part of dir inode %d\n", inode->i_ino, dir->i_ino);
	// Adding backlink to the inode - Modifying position 0 since this is a
	// new inode - It will not have any other links pointing to it.	
	// First, we need to reset all the backlinks
	for(i=0; i < EXT2_N_LINKS; i++)
		ei->i_backlinks[i] = 0;
	ei->i_backlinks[0] = dir->i_ino;

	inode->i_blocks = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = CURRENT_TIME_SEC;
	memset(ei->i_data, 0, sizeof(ei->i_data));
	ei->i_flags = EXT2_I(dir)->i_flags & ~EXT2_BTREE_FL;
	if (S_ISLNK(mode))
		ei->i_flags &= ~(EXT2_IMMUTABLE_FL|EXT2_APPEND_FL);
	/* dirsync is only applied to directories */
	if (!S_ISDIR(mode))
		ei->i_flags &= ~EXT2_DIRSYNC_FL;
	ei->i_faddr = 0;
	ei->i_frag_no = 0;
	ei->i_frag_size = 0;
	ei->i_file_acl = 0;
	ei->i_dir_acl = 0;
	ei->i_dtime = 0;
	ei->i_block_alloc_info = NULL;
	ei->i_block_group = group;
	ei->i_dir_start_lookup = 0;
	ei->i_state = EXT2_STATE_NEW;
	ext2_set_inode_flags(inode);
	spin_lock(&sbi->s_next_gen_lock);
	inode->i_generation = sbi->s_next_generation++;
	spin_unlock(&sbi->s_next_gen_lock);
	insert_inode_hash(inode);

	if (DQUOT_ALLOC_INODE(inode)) {
		err = -EDQUOT;
		goto fail_drop;
	}

	err = ext2_init_acl(inode, dir);
	if (err)
		goto fail_free_drop;

	err = ext2_init_security(inode,dir);
	if (err)
		goto fail_free_drop;

	mark_inode_dirty(inode);
	ext2_preread_inode(inode);
	return inode;

fail_free_drop:
	DQUOT_FREE_INODE(inode);

fail_drop:
	DQUOT_DROP(inode);
	inode->i_flags |= S_NOQUOTA;
	inode->i_nlink = 0;
	iput(inode);
	return ERR_PTR(err);

fail:
	make_bad_inode(inode);
	iput(inode);
	return ERR_PTR(err);
}

unsigned long ext2_count_free_inodes (struct super_block * sb)
{
	struct ext2_group_desc *desc;
	unsigned long desc_count = 0;
	int i;	

#ifdef EXT2FS_DEBUG
	struct ext2_super_block *es;
	unsigned long bitmap_count = 0;
	struct buffer_head *bitmap_bh = NULL;

	es = EXT2_SB(sb)->s_es;
	for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
		desc_count += EXT2_SB(sb)->bg_free_inodes_count[i]; 	
	}
	return desc_count;
#else
	for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
		desc_count += EXT2_SB(sb)->bg_free_inodes_counts[i]; 	
	}
	return desc_count;
#endif
}

/* Called at mount-time, super-block is locked */
unsigned long ext2_count_dirs (struct super_block * sb)
{
	unsigned long count = 0;
	int i;

	for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
		count += EXT2_SB(sb)->bg_used_dirs_counts[i];
	}
	return count;
}
