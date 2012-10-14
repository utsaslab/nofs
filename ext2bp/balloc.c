/*
 *  linux/fs/ext2/balloc.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  Enhanced block allocation by Stephen Tweedie (sct@redhat.com), 1993
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 */

#include "ext2.h"
#include <linux/quotaops.h>
#include <linux/sched.h>
#include <linux/buffer_head.h>
#include <linux/capability.h>

/*
 * balloc.c contains the blocks allocation and deallocation routines
 */

/*
 * The free blocks are managed by bitmaps.  A file system contains several
 * blocks groups.  Each group contains 1 bitmap block for blocks, 1 bitmap
 * block for inodes, N blocks for the inode table and data blocks.
 *
 * The file system contains group descriptors which are located after the
 * super block.  Each descriptor contains the number of the bitmap block and
 * the free blocks count in the block.  The descriptors are loaded in memory
 * when a file system is mounted (see ext2_fill_super).
 */


#define in_range(b, first, len)	((b) >= (first) && (b) <= (first) + (len) - 1)

struct ext2_group_desc * ext2_get_group_desc(struct super_block * sb,
					     unsigned int block_group,
					     struct buffer_head ** bh)
{
	if(!sb) return NULL;
	unsigned long group_desc;
	unsigned long offset;
	struct ext2_group_desc * desc;
	struct ext2_sb_info *sbi = EXT2_SB(sb);
	if(!sbi) {
		printk("Error accessing sbi\n");
		return NULL;
	}

	if (block_group >= sbi->s_groups_count) {
		ext2_error (sb, "ext2_get_group_desc",
			    "block_group >= groups_count - "
			    "block_group = %d, groups_count = %lu",
			    block_group, sbi->s_groups_count);

		return NULL;
	}

	group_desc = block_group >> EXT2_DESC_PER_BLOCK_BITS(sb);

	if(!EXT2_SB(sb) || !(EXT2_SB(sb)->s_desc_per_block)) {
		printk("Error in accessing sbi members\n");
		return NULL;
	}
	
	offset = block_group & (EXT2_DESC_PER_BLOCK(sb) - 1);
	if(group_desc > sbi->s_groups_count) {
		printk("Group desc is wrong\n");
		return NULL;
	}

	if(!sbi || !sbi->s_group_desc) {
		printk("sbi or sbi group desc NULL\n");
		return NULL;
	}

	if (!sbi->s_group_desc[group_desc]) {
		ext2_error (sb, "ext2_get_group_desc",
			    "Group descriptor not loaded - "
			    "block_group = %d, group_desc = %lu, desc = %lu",
			     block_group, group_desc, offset);
		return NULL;
	}

	desc = (struct ext2_group_desc *) sbi->s_group_desc[group_desc]->b_data;
	if (bh)
		*bh = sbi->s_group_desc[group_desc];
	return desc + offset;
}

/* Ext2bp functions for operating on the in-mem block bitmaps */

/* Vijay: Setting the validity bit for a block in ext2bp */
unsigned ext2bp_mark_block_valid(struct super_block *sb, int block) {
	if (!((EXT2_SB(sb))->s_block_validity_bitmap)) {
		printk("Inside ext2bp_mark_block_valid: Validity bitmap is NULL");
		return -1;
	}
	unsigned long block_bitno = block - le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
	if (block_bitno < 0 ) {
		printk("Error: Invalid block num\n");
		return -1;
	}
	unsigned long block_group = block_bitno / EXT2_BLOCKS_PER_GROUP(sb);
	int prev = ext2_set_bit_atomic(
			sb_bgl_lock(EXT2_SB(sb), block_group),
			block_bitno, (void *) (EXT2_SB(sb))->s_block_validity_bitmap);
	return prev;
}

/* Vijay: Setting the availability bit for a block in ext2bp */
unsigned ext2bp_mark_block_used(struct super_block *sb, int block) {
	if (!((EXT2_SB(sb))->s_block_availability_bitmap)) {
		printk("Inside ext2bp_mark_block_used: Availability bitmap is NULL");
		return -1;
	}
	unsigned long block_bitno = block - le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
	if (block_bitno < 0 ) {
		printk("Error: Invalid block num\n");
		return -1;
	}
	unsigned long block_group = block_bitno / EXT2_BLOCKS_PER_GROUP(sb);
	int prev = ext2_set_bit_atomic(
			sb_bgl_lock(EXT2_SB(sb), block_group),
			block_bitno, (void *) (EXT2_SB(sb))->s_block_availability_bitmap);
	if (prev) {
		printk("Ext2bp ext2bp_mark_block_used ERROR: Block %lu has been marked in use", block);
	}
	return prev;
}

/* Vijay: Clearing the availability bit for a block in ext2bp */
unsigned ext2bp_mark_block_free(struct super_block *sb, int block) {
	if (!((EXT2_SB(sb))->s_block_availability_bitmap)) {
		printk("Inside ext2bp_mark_block_used: Availability bitmap is NULL");
		return -1;
	}
	unsigned long block_bitno = block - le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
	if (block_bitno < 0 ) {
		printk("Error: Invalid block num\n");
		return -1;
	}
	unsigned long block_group = block_bitno / EXT2_BLOCKS_PER_GROUP(sb);
	int prev = ext2_clear_bit_atomic(
			sb_bgl_lock(EXT2_SB(sb), block_group),
			block_bitno, (void *) (EXT2_SB(sb))->s_block_availability_bitmap);
	if (!prev) {
		ext2bp_debug("Clearing avail bitmap for block %lu\n", block);
		ext2bp_debug("Setting block %lu as free, bit %lu\n", block, block_bitno);
		ext2bp_debug("Was the bit prev set? %u\n", prev);
	}
	if (data_scan_done) BUG_ON(!prev);
	return prev;
}

/* Vijay: Test if a block is valid. It is ok to use this without a lock
 * since it is only for debugging purposes.
 */
unsigned ext2bp_test_block_valid(struct super_block *sb, int block) {
	if (!((EXT2_SB(sb))->s_block_validity_bitmap)) {
		printk("Inside ext2bp_mark_block_used: validity bitmap is NULL");
		return 0;
	}
	unsigned long block_bitno = block - le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
	if (block_bitno < 0 ) {
		printk("Error: Invalid block num\n");
		return 0;
	}
	return ext2_test_bit(block_bitno, (unsigned long *)EXT2_SB(sb)->s_block_validity_bitmap); 
}

/* Vijay: Test if a block is in use. It is ok to use this without a lock
 * since it is only for debugging purposes.
 */
unsigned ext2bp_test_block_in_use(struct super_block *sb, int block) {
	if (!((EXT2_SB(sb))->s_block_availability_bitmap)) {
		printk("Inside ext2bp_mark_block_used: Availability bitmap is NULL");
		return 0;
	}
	unsigned long block_bitno = block - le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
	if (block_bitno < 0 ) {
		printk("Error: Invalid block num\n");
		return 0;
	}
	return ext2_test_bit(block_bitno, (unsigned long *)EXT2_SB(sb)->s_block_availability_bitmap); 
}

/* Ext2bp: Routines to convert between absolute and relative versions of block numbers.
 * The relative version is valid inside a block group. The absolute version is valid 
 * across block groups 
 */
unsigned long rel_block_num(struct super_block *sb, unsigned long group, unsigned long block) {
	return block - ext2_group_first_block_no(sb, group);
}

unsigned long abs_block_num(struct super_block *sb, unsigned long group, unsigned long block) {
	return block + ext2_group_first_block_no(sb, group);
}

unsigned long block_bit_num(struct super_block *sb, unsigned long block) {
	return block - le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
}

unsigned long rel_bit_to_abs_block(struct super_block *sb, unsigned long group, unsigned long rel_bitno) {
	unsigned long abs_bitno = rel_bitno + group * EXT2_BLOCKS_PER_GROUP(sb);
	return abs_bitno + le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
}

unsigned long abs_bit_to_abs_block(struct super_block *sb, unsigned long abs_bitno) {
	return abs_bitno + le32_to_cpu(EXT2_SB(sb)->s_es->s_first_data_block);
}

/* End of ext2bp functions */

static int ext2_valid_block_bitmap(struct super_block *sb,
					struct ext2_group_desc *desc,
					unsigned int block_group,
					struct buffer_head *bh)
{
	ext2_grpblk_t offset;
	ext2_grpblk_t next_zero_bit;
	ext2_fsblk_t bitmap_blk;
	ext2_fsblk_t group_first_block;

	group_first_block = ext2_group_first_block_no(sb, block_group);

	/* check whether block bitmap block number is set */
	bitmap_blk = le32_to_cpu(desc->bg_block_bitmap);
	offset = bitmap_blk - group_first_block;
	if (!ext2_test_bit(offset, bh->b_data))
		/* bad block bitmap */
		goto err_out;

	/* check whether the inode bitmap block number is set */
	bitmap_blk = le32_to_cpu(desc->bg_inode_bitmap);
	offset = bitmap_blk - group_first_block;
	if (!ext2_test_bit(offset, bh->b_data))
		/* bad block bitmap */
		goto err_out;

	/* check whether the inode table block number is set */
	bitmap_blk = le32_to_cpu(desc->bg_inode_table);
	offset = bitmap_blk - group_first_block;
	next_zero_bit = ext2_find_next_zero_bit(bh->b_data,
				offset + EXT2_SB(sb)->s_itb_per_group,
				offset);
	if (next_zero_bit >= offset + EXT2_SB(sb)->s_itb_per_group)
		/* good bitmap for inode tables */
		return 1;

err_out:
	ext2_error(sb, __func__,
			"Invalid block bitmap - "
			"block_group = %d, block = %lu",
			block_group, bitmap_blk);
	return 0;
}

/* Ext2bp: Function to check the in-mem blocks bitmaps for validity
 * regarding marking inode tables and bitmap blocks as used.
 */
void ext2bp_check_inmem_bitmap(struct super_block *sb) {
	struct ext2_group_desc *desc;
	unsigned long desc_count = 0;
	int i, j;
	for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
		desc = ext2_get_group_desc (sb, i, NULL);
		if (!desc)
			continue;

		ext2_grpblk_t offset;
		ext2_grpblk_t next_zero_bit;
		ext2_fsblk_t bitmap_blk;
		ext2_fsblk_t group_first_block;

		group_first_block = ext2_group_first_block_no(sb, i);

		/* check whether block bitmap block number is set */
		bitmap_blk = le32_to_cpu(desc->bg_block_bitmap);
		BUG_ON(!ext2bp_test_block_in_use(sb, bitmap_blk));

		/* check whether the inode bitmap block number is set */
		bitmap_blk = le32_to_cpu(desc->bg_inode_bitmap);
		BUG_ON(!ext2bp_test_block_in_use(sb, bitmap_blk));

		/* check whether the inode table block number is set */
		bitmap_blk = le32_to_cpu(desc->bg_inode_table);
		for (j = 0; j < EXT2_SB(sb)->s_itb_per_group; j++)
			BUG_ON(!ext2bp_test_block_in_use(sb, bitmap_blk + j));
	}
}

/*
 * Read the bitmap for a given block_group,and validate the
 * bits for block/inode/inode tables are set in the bitmaps
 *
 * Return buffer_head on success or NULL in case of failure.
 */
static struct buffer_head *
read_block_bitmap(struct super_block *sb, unsigned int block_group)
{
	struct ext2_group_desc * desc;
	struct buffer_head * bh = NULL;
	ext2_fsblk_t bitmap_blk;

	desc = ext2_get_group_desc(sb, block_group, NULL);
	if (!desc)
		return NULL;
	bitmap_blk = le32_to_cpu(desc->bg_block_bitmap);
	bh = sb_getblk(sb, bitmap_blk);
	if (unlikely(!bh)) {
		ext2_error(sb, __func__,
			    "Cannot read block bitmap - "
			    "block_group = %d, block_bitmap = %u",
			    block_group, le32_to_cpu(desc->bg_block_bitmap));
		return NULL;
	}
	if (likely(bh_uptodate_or_lock(bh)))
		return bh;

	if (bh_submit_read(bh) < 0) {
		brelse(bh);
		ext2_error(sb, __func__,
			    "Cannot read block bitmap - "
			    "block_group = %d, block_bitmap = %u",
			    block_group, le32_to_cpu(desc->bg_block_bitmap));
		return NULL;
	}

	ext2_valid_block_bitmap(sb, desc, block_group, bh);
	/*
	 * file system mounted not to panic on error, continue with corrupt
	 * bitmap
	 */
	return bh;
}

static void release_blocks(struct super_block *sb, int count)
{
	if (count) {
		struct ext2_sb_info *sbi = EXT2_SB(sb);
		
		spin_lock(&ext2bp_sb_lock);	
		percpu_counter_add(&sbi->s_freeblocks_counter, count);
		spin_unlock(&ext2bp_sb_lock);	
		sb->s_dirt = 1;
	}
}

/* Vijay: Modifying this a bit to reflect the change in the in-mem 
   group desciptor for ext2bp */
static void group_adjust_blocks(struct super_block *sb, int group_no,
	struct ext2_group_desc *desc, struct buffer_head *bh, int count)
{
	if (count) {
		struct ext2_sb_info *sbi = EXT2_SB(sb);
		unsigned free_blocks;

		spin_lock(sb_bgl_lock(sbi, group_no));
		
		/* Change the in-mem desc for ext2bp. Doing it directly
		 * instead of calling inc function as it is protected
		 * by the group lock.
		 */
		sbi->bg_free_blocks_counts[group_no]+= count;
		spin_unlock(sb_bgl_lock(sbi, group_no));
		sb->s_dirt = 1;
	}
}

/*
 * The reservation window structure operations
 * --------------------------------------------
 * Operations include:
 * dump, find, add, remove, is_empty, find_next_reservable_window, etc.
 *
 * We use a red-black tree to represent per-filesystem reservation
 * windows.
 *
 */

/**
 * __rsv_window_dump() -- Dump the filesystem block allocation reservation map
 * @rb_root:		root of per-filesystem reservation rb tree
 * @verbose:		verbose mode
 * @fn:			function which wishes to dump the reservation map
 *
 * If verbose is turned on, it will print the whole block reservation
 * windows(start, end). Otherwise, it will only print out the "bad" windows,
 * those windows that overlap with their immediate neighbors.
 */
#if 1
static void __rsv_window_dump(struct rb_root *root, int verbose,
			      const char *fn)
{
	struct rb_node *n;
	struct ext2_reserve_window_node *rsv, *prev;
	int bad;

restart:
	n = rb_first(root);
	bad = 0;
	prev = NULL;

	printk("Block Allocation Reservation Windows Map (%s):\n", fn);
	while (n) {
		rsv = rb_entry(n, struct ext2_reserve_window_node, rsv_node);
		if (verbose)
			printk("reservation window 0x%p "
				"start: %lu, end: %lu\n",
				rsv, rsv->rsv_start, rsv->rsv_end);
		if (rsv->rsv_start && rsv->rsv_start >= rsv->rsv_end) {
			printk("Bad reservation %p (start >= end)\n",
			       rsv);
			bad = 1;
		}
		if (prev && prev->rsv_end >= rsv->rsv_start) {
			printk("Bad reservation %p (prev->end >= start)\n",
			       rsv);
			bad = 1;
		}
		if (bad) {
			if (!verbose) {
				printk("Restarting reservation walk in verbose mode\n");
				verbose = 1;
				goto restart;
			}
		}
		n = rb_next(n);
		prev = rsv;
	}
	printk("Window map complete.\n");
	BUG_ON(bad);
}
#define rsv_window_dump(root, verbose) \
	__rsv_window_dump((root), (verbose), __func__)
#else
#define rsv_window_dump(root, verbose) do {} while (0)
#endif

/**
 * goal_in_my_reservation()
 * @rsv:		inode's reservation window
 * @grp_goal:		given goal block relative to the allocation block group
 * @group:		the current allocation block group
 * @sb:			filesystem super block
 *
 * Test if the given goal block (group relative) is within the file's
 * own block reservation window range.
 *
 * If the reservation window is outside the goal allocation group, return 0;
 * grp_goal (given goal block) could be -1, which means no specific
 * goal block. In this case, always return 1.
 * If the goal block is within the reservation window, return 1;
 * otherwise, return 0;
 */
static int
goal_in_my_reservation(struct ext2_reserve_window *rsv, ext2_grpblk_t grp_goal,
			unsigned int group, struct super_block * sb)
{
	ext2_fsblk_t group_first_block, group_last_block;

	group_first_block = ext2_group_first_block_no(sb, group);
	group_last_block = group_first_block + EXT2_BLOCKS_PER_GROUP(sb) - 1;

	if ((rsv->_rsv_start > group_last_block) ||
	    (rsv->_rsv_end < group_first_block))
		return 0;
	if ((grp_goal >= 0) && ((grp_goal + group_first_block < rsv->_rsv_start)
		|| (grp_goal + group_first_block > rsv->_rsv_end)))
		return 0;
	return 1;
}

/**
 * search_reserve_window()
 * @rb_root:		root of reservation tree
 * @goal:		target allocation block
 *
 * Find the reserved window which includes the goal, or the previous one
 * if the goal is not in any window.
 * Returns NULL if there are no windows or if all windows start after the goal.
 */
static struct ext2_reserve_window_node *
search_reserve_window(struct rb_root *root, ext2_fsblk_t goal)
{
	struct rb_node *n = root->rb_node;
	struct ext2_reserve_window_node *rsv;

	if (!n)
		return NULL;

	do {
		rsv = rb_entry(n, struct ext2_reserve_window_node, rsv_node);

		if (goal < rsv->rsv_start)
			n = n->rb_left;
		else if (goal > rsv->rsv_end)
			n = n->rb_right;
		else
			return rsv;
	} while (n);
	/*
	 * We've fallen off the end of the tree: the goal wasn't inside
	 * any particular node.  OK, the previous node must be to one
	 * side of the interval containing the goal.  If it's the RHS,
	 * we need to back up one.
	 */
	if (rsv->rsv_start > goal) {
		n = rb_prev(&rsv->rsv_node);
		rsv = rb_entry(n, struct ext2_reserve_window_node, rsv_node);
	}
	return rsv;
}

/*
 * ext2_rsv_window_add() -- Insert a window to the block reservation rb tree.
 * @sb:			super block
 * @rsv:		reservation window to add
 *
 * Must be called with rsv_lock held.
 */
void ext2_rsv_window_add(struct super_block *sb,
		    struct ext2_reserve_window_node *rsv)
{
	struct rb_root *root = &EXT2_SB(sb)->s_rsv_window_root;
	struct rb_node *node = &rsv->rsv_node;
	ext2_fsblk_t start = rsv->rsv_start;

	struct rb_node ** p = &root->rb_node;
	struct rb_node * parent = NULL;
	struct ext2_reserve_window_node *this;

	while (*p)
	{
		parent = *p;
		this = rb_entry(parent, struct ext2_reserve_window_node, rsv_node);

		if (start < this->rsv_start)
			p = &(*p)->rb_left;
		else if (start > this->rsv_end)
			p = &(*p)->rb_right;
		else {
			rsv_window_dump(root, 1);
			BUG();
		}
	}

	rb_link_node(node, parent, p);
	rb_insert_color(node, root);
}

/**
 * rsv_window_remove() -- unlink a window from the reservation rb tree
 * @sb:			super block
 * @rsv:		reservation window to remove
 *
 * Mark the block reservation window as not allocated, and unlink it
 * from the filesystem reservation window rb tree. Must be called with
 * rsv_lock held.
 */
static void rsv_window_remove(struct super_block *sb,
			      struct ext2_reserve_window_node *rsv)
{
	rsv->rsv_start = EXT2_RESERVE_WINDOW_NOT_ALLOCATED;
	rsv->rsv_end = EXT2_RESERVE_WINDOW_NOT_ALLOCATED;
	rsv->rsv_alloc_hit = 0;
	rb_erase(&rsv->rsv_node, &EXT2_SB(sb)->s_rsv_window_root);
}

/*
 * rsv_is_empty() -- Check if the reservation window is allocated.
 * @rsv:		given reservation window to check
 *
 * returns 1 if the end block is EXT2_RESERVE_WINDOW_NOT_ALLOCATED.
 */
static inline int rsv_is_empty(struct ext2_reserve_window *rsv)
{
	/* a valid reservation end block could not be 0 */
	return (rsv->_rsv_end == EXT2_RESERVE_WINDOW_NOT_ALLOCATED);
}

/**
 * ext2_init_block_alloc_info()
 * @inode:		file inode structure
 *
 * Allocate and initialize the  reservation window structure, and
 * link the window to the ext2 inode structure at last
 *
 * The reservation window structure is only dynamically allocated
 * and linked to ext2 inode the first time the open file
 * needs a new block. So, before every ext2_new_block(s) call, for
 * regular files, we should check whether the reservation window
 * structure exists or not. In the latter case, this function is called.
 * Fail to do so will result in block reservation being turned off for that
 * open file.
 *
 * This function is called from ext2_get_blocks_handle(), also called
 * when setting the reservation window size through ioctl before the file
 * is open for write (needs block allocation).
 *
 * Needs truncate_mutex protection prior to calling this function.
 */
void ext2_init_block_alloc_info(struct inode *inode)
{
	struct ext2_inode_info *ei = EXT2_I(inode);
	struct ext2_block_alloc_info *block_i = ei->i_block_alloc_info;
	struct super_block *sb = inode->i_sb;

	block_i = kmalloc(sizeof(*block_i), GFP_NOFS);
	if (block_i) {
		struct ext2_reserve_window_node *rsv = &block_i->rsv_window_node;

		rsv->rsv_start = EXT2_RESERVE_WINDOW_NOT_ALLOCATED;
		rsv->rsv_end = EXT2_RESERVE_WINDOW_NOT_ALLOCATED;

	 	/*
		 * if filesystem is mounted with NORESERVATION, the goal
		 * reservation window size is set to zero to indicate
		 * block reservation is off
		 */
		if (!test_opt(sb, RESERVATION))
			rsv->rsv_goal_size = 0;
		else
			rsv->rsv_goal_size = EXT2_DEFAULT_RESERVE_BLOCKS;
		rsv->rsv_alloc_hit = 0;
		block_i->last_alloc_logical_block = 0;
		block_i->last_alloc_physical_block = 0;
	}
	ei->i_block_alloc_info = block_i;
}

/**
 * ext2_discard_reservation()
 * @inode:		inode
 *
 * Discard(free) block reservation window on last file close, or truncate
 * or at last iput().
 *
 * It is being called in three cases:
 * 	ext2_release_file(): last writer closes the file
 * 	ext2_clear_inode(): last iput(), when nobody links to this file.
 * 	ext2_truncate(): when the block indirect map is about to change.
 */
void ext2_discard_reservation(struct inode *inode)
{
	struct ext2_inode_info *ei = EXT2_I(inode);
	struct ext2_block_alloc_info *block_i = ei->i_block_alloc_info;
	struct ext2_reserve_window_node *rsv;
	spinlock_t *rsv_lock = &EXT2_SB(inode->i_sb)->s_rsv_window_lock;

	if (!block_i)
		return;

	rsv = &block_i->rsv_window_node;
	if (!rsv_is_empty(&rsv->rsv_window)) {
		spin_lock(rsv_lock);
		if (!rsv_is_empty(&rsv->rsv_window))
			rsv_window_remove(inode->i_sb, rsv);
		spin_unlock(rsv_lock);
	}
}

/**
 * ext2_free_blocks_sb() -- Free given blocks and update quota and i_blocks
 * @inode:		inode
 * @block:		start physcial block to free
 * @count:		number of blocks to free
 */
void ext2_free_blocks (struct inode * inode, unsigned long block,
		       unsigned long count)
{
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head * bh2;
	unsigned long block_group;
	unsigned long bit;
	unsigned long i;
	unsigned long overflow;
	struct super_block * sb = inode->i_sb;
	struct ext2_sb_info * sbi = EXT2_SB(sb);
	struct ext2_group_desc * desc;
	struct ext2_super_block * es = sbi->s_es;
	unsigned freed = 0, group_freed;

	if (block < le32_to_cpu(es->s_first_data_block) ||
	    block + count < block ||
	    block + count > le32_to_cpu(es->s_blocks_count)) {
		ext2_error (sb, "ext2_free_blocks",
			    "Freeing blocks not in datazone - "
			    "block = %lu, count = %lu", block, count);
		goto error_return;
	}

	ext2_debug ("freeing block(s) %lu-%lu\n", block, block + count - 1);

do_more:
	overflow = 0;
	block_group = (block - le32_to_cpu(es->s_first_data_block)) /
		      EXT2_BLOCKS_PER_GROUP(sb);
	bit = (block - le32_to_cpu(es->s_first_data_block)) %
		      EXT2_BLOCKS_PER_GROUP(sb);

	/*
	 * Check to see if we are freeing blocks across a group
	 * boundary.
	 */
	if (bit + count > EXT2_BLOCKS_PER_GROUP(sb)) {
		overflow = bit + count - EXT2_BLOCKS_PER_GROUP(sb);
		count -= overflow;
	}

    /* Vijay: This is where the in-mem bitmap should be used for ext2bp
	 * instead of the one read from disk */
    for (i = 0, group_freed = 0; i < count; i++) {
        // Ext2bp: Updating the in-mem bitmaps
        if (!ext2bp_mark_block_free(sb, block + i)) {
            ext2_error(sb, __func__,
					"ext2bp bit already cleared for block %lu", block + i);
		} else {
			group_freed++;
		}
	}

	/* This func has been change for ext2bp - desc is not 
	 * actively accessed there. I am just lazy to change the
     * API to leave out the desc.
	 */
	group_adjust_blocks(sb, block_group, desc, bh2, group_freed);
	freed += group_freed;

	if (overflow) {
		block += count;
		count = overflow;
		goto do_more;
	}
error_return:
	release_blocks(sb, freed);
	DQUOT_FREE_BLOCK(inode, freed);
}

/**
 * bitmap_search_next_usable_block()
 * @start:		the starting block (group relative) of the search
 * @bh:			bufferhead contains the block group bitmap
 * @maxblocks:		the ending block (group relative) of the reservation
 *
 * The bitmap search --- search forward through the actual bitmap on disk until
 * we find a bit free.
 */
static ext2_grpblk_t
bitmap_search_next_usable_block(ext2_grpblk_t start, struct buffer_head *bh,
					ext2_grpblk_t maxblocks)
{
	ext2_grpblk_t next;

	next = ext2_find_next_zero_bit(bh->b_data, maxblocks, start);
	if (next >= maxblocks)
		return -1;
	return next;
}

/**
 * ext2bp_bitmap_search_next_usable_block()
 * Ext2bp version of the above function. Works on in-mem bitmaps instead of
 * on disk ones. Requires the superblock and the group number as extra
 * paramaters. Tested. Returns a bit position.
 * NOTE: Input start and maxblocks are global bit positions.
 */
static ext2_grpblk_t
ext2bp_bitmap_search_next_usable_block(struct super_block *sb, ext2_grpblk_t bit_start, unsigned int group,
		ext2_grpblk_t bit_maxblocks)
{
	BUG_ON(bit_start < 0);
	BUG_ON(bit_maxblocks < bit_start);

	ext2_grpblk_t bno = bit_start; 
	int validity_status = 0;

repeat_for_ext2bp:
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	bno = ext2_find_next_zero_bit((unsigned long *)EXT2_SB(sb)->s_block_availability_bitmap,
			EXT2_SB(sb)->s_groups_count * EXT2_BLOCKS_PER_GROUP(sb), bno);
	BUG_ON(bno < 0);
	BUG_ON(bno < bit_start);
	validity_status = ext2_test_bit(bno,
			(unsigned long *)EXT2_SB(sb)->s_block_validity_bitmap);
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));

	if (bno >= bit_maxblocks) return -1;

	if (!validity_status) {
		/*
		 * We found a free block - but validity bit says its
		 * false. If the data scan has not completed yet, we 
		 * investigate this block ( along with a certain number
		 * of blocks behind it, since we will pay for the seek
		 * anyway).
		 */
		if (!data_scan_done) {
			verify_data_blocks(sb, abs_bit_to_abs_block(sb, bno));
			// Check for validity and availability again
			goto repeat_for_ext2bp; 	
		}

		bno++;
		goto repeat_for_ext2bp;
	}

	ext2_grpblk_t rel_bit_num = bno - group * EXT2_BLOCKS_PER_GROUP(sb);
	return rel_bit_num;
}

/**
 * find_next_usable_block()
 * @start:		the starting block (group relative) to find next
 * 			allocatable block in bitmap.
 * @bh:			bufferhead contains the block group bitmap
 * @maxblocks:		the ending block (group relative) for the search
 *
 * Find an allocatable block in a bitmap.  We perform the "most
 * appropriate allocation" algorithm of looking for a free block near
 * the initial goal; then for a free byte somewhere in the bitmap;
 * then for any free bit in the bitmap.
 */
static ext2_grpblk_t
find_next_usable_block(int start, struct buffer_head *bh, int maxblocks)
{
	ext2_grpblk_t here, next;
	char *p, *r;

	if (start > 0) {
		/*
		 * The goal was occupied; search forward for a free 
		 * block within the next XX blocks.
		 *
		 * end_goal is more or less random, but it has to be
		 * less than EXT2_BLOCKS_PER_GROUP. Aligning up to the
		 * next 64-bit boundary is simple..
		 */
		ext2_grpblk_t end_goal = (start + 63) & ~63;
		if (end_goal > maxblocks)
			end_goal = maxblocks;
		here = ext2_find_next_zero_bit(bh->b_data, end_goal, start);
		if (here < end_goal)
			return here;
		ext2_debug("Bit not found near goal\n");
	}

	here = start;
	if (here < 0)
		here = 0;

	p = ((char *)bh->b_data) + (here >> 3);
	r = memscan(p, 0, ((maxblocks + 7) >> 3) - (here >> 3));
	next = (r - ((char *)bh->b_data)) << 3;

	if (next < maxblocks && next >= here)
		return next;

	here = bitmap_search_next_usable_block(here, bh, maxblocks);
	return here;
}

/* Ext2bp: The ext2bp version of find_next_usable_block. Uses the in-mem bitmap 
 * instead of the block bitmap. Also, takes the group number as a parameter since
 * we need it to access the in-mem bitmap of that group. THis returns a rel bit position.
 * Input parameters are relative bit positions.
 */
static ext2_grpblk_t
ext2bp_find_next_usable_block(struct super_block *sb, int rel_bit_start, int group, int rel_bit_maxblocks)
{
	BUG_ON(rel_bit_start < 0);
	BUG_ON(rel_bit_start > rel_bit_maxblocks);
	BUG_ON(rel_bit_maxblocks < 0);
	ext2_grpblk_t rel_bit_here, abs_bit_next, rel_bit_next;
	char *p, *r;

	if (rel_bit_start > 0) {
		/*
		 * The goal was occupied; search forward for a free 
		 * block within the next XX blocks.
		 *
		 * end_goal is more or less random, but it has to be
		 * less than EXT2_BLOCKS_PER_GROUP. Aligning up to the
		 * next 64-bit boundary is simple..
		 */
		ext2_grpblk_t rel_bit_end_goal = (rel_bit_start + 63) & ~63;
		if (rel_bit_end_goal > rel_bit_maxblocks)
			rel_bit_end_goal = rel_bit_maxblocks;
	
		int abs_bit_end_goal = rel_bit_end_goal + group * EXT2_BLOCKS_PER_GROUP(sb);
		int abs_bit_start = rel_bit_start + group * EXT2_BLOCKS_PER_GROUP(sb);
		int bno = abs_bit_start;
		int bendgoal = abs_bit_end_goal;
		int validity_status = 0;

	repeat:	

		BUG_ON(bno < 0);
		spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
		bno = ext2_find_next_zero_bit((unsigned long *)EXT2_SB(sb)->s_block_availability_bitmap, bendgoal, bno);
		validity_status = ext2_test_bit(bno, (unsigned long *)EXT2_SB(sb)->s_block_validity_bitmap);
		spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
		BUG_ON(bno < 0);
		BUG_ON(bendgoal < 0);

		if (!validity_status) {
			bno++;
			if (bno < bendgoal)
				goto repeat;
		}

		if (bno < bendgoal) {
			/* Ino is bit number, convert it back into group relative
			 * and return. 
			 */
			int rel_bit_num = bno - group * EXT2_BLOCKS_PER_GROUP(sb);
			return rel_bit_num;
		}
		ext2_debug("Bit not found near goal\n");
	}
	
	rel_bit_here = rel_bit_start;
	if (rel_bit_here < 0)
		rel_bit_here = 0;
	int abs_bit_here = rel_bit_here + group * EXT2_BLOCKS_PER_GROUP(sb);
	int abs_bit_maxblocks = rel_bit_maxblocks + group * EXT2_BLOCKS_PER_GROUP(sb);

repeat_for_byte:
	BUG_ON(abs_bit_here < 0);
	BUG_ON(abs_bit_maxblocks < 0);
	BUG_ON(abs_bit_here > abs_bit_maxblocks);
	p = ((char *)EXT2_SB(sb)->s_block_availability_bitmap) + (abs_bit_here >> 3);

	spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
	r = memscan(p, 0, ((rel_bit_maxblocks + 7) >> 3) - (rel_bit_here >> 3));
	// Check if this byte is 1 in the validity bitmap
	int offset = r - (char*)EXT2_SB(sb)->s_block_availability_bitmap;
	char validity_value = *((char*)EXT2_SB(sb)->s_block_validity_bitmap + offset);
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));

	BUG_ON(offset < 0);
	abs_bit_next = offset << 3;
	if (validity_value ^ -1) {
		if ((abs_bit_here + 1) < abs_bit_maxblocks) {
			abs_bit_here++;
			goto repeat_for_byte;
		}
	}

	// Converting next back to relative
	if (abs_bit_next < abs_bit_maxblocks && abs_bit_next >= abs_bit_here) {
		rel_bit_next = abs_bit_next - group * EXT2_BLOCKS_PER_GROUP(sb);
		return rel_bit_next;
	}

	rel_bit_here = ext2bp_bitmap_search_next_usable_block(sb, abs_bit_here, group, abs_bit_maxblocks);
	return rel_bit_here;
}

/*
 * ext2_try_to_allocate()
 * @sb:			superblock
 * @handle:		handle to this transaction
 * @group:		given allocation block group
 * @bitmap_bh:		bufferhead holds the block bitmap
 * @grp_goal:		given target block within the group
 * @count:		target number of blocks to allocate
 * @my_rsv:		reservation window
 *
 * Attempt to allocate blocks within a give range. Set the range of allocation
 * first, then find the first free bit(s) from the bitmap (within the range),
 * and at last, allocate the blocks by claiming the found free bit as allocated.
 *
 * To set the range of this allocation:
 * 	if there is a reservation window, only try to allocate block(s)
 * 	from the file's own reservation window;
 * 	Otherwise, the allocation range starts from the give goal block,
 * 	ends at the block group's last block.
 *
 * If we failed to allocate the desired block then we may end up crossing to a
 * new bitmap.
 */
static int
ext2_try_to_allocate(struct super_block *sb, int group,
			struct buffer_head *bitmap_bh, ext2_grpblk_t grp_goal,
			unsigned long *count,
			struct ext2_reserve_window *my_rsv)
{
	ext2_fsblk_t group_first_block;
       	ext2_grpblk_t start, end;
	unsigned long num = 0;

	/* we do allocation within the reservation window if we have a window */
	if (my_rsv) {
		group_first_block = ext2_group_first_block_no(sb, group);
		if (my_rsv->_rsv_start >= group_first_block)
			start = my_rsv->_rsv_start - group_first_block;
		else
			/* reservation window cross group boundary */
			start = 0;
		end = my_rsv->_rsv_end - group_first_block + 1;
		if (end > EXT2_BLOCKS_PER_GROUP(sb))
			/* reservation window crosses group boundary */
			end = EXT2_BLOCKS_PER_GROUP(sb);
		if ((start <= grp_goal) && (grp_goal < end))
			start = grp_goal;
		else
			grp_goal = -1;
	} else {
		if (grp_goal > 0)
			start = grp_goal;
		else
			start = 0;
		end = EXT2_BLOCKS_PER_GROUP(sb);
	}

	BUG_ON(start > EXT2_BLOCKS_PER_GROUP(sb));

repeat:
	if (grp_goal < 0) {
		grp_goal = ext2bp_find_next_usable_block(sb, start, group, end);

		if (grp_goal < 0)
			goto fail_access;

		if (!my_rsv) {
			int i;
			
			spin_lock(sb_bgl_lock(EXT2_SB(sb), group));
			
            /* grp_goal is a relative bit num. In order to pass it on
			 * ext2bp functions, we need to convert it into an absolute
			 * block number */
			for (i = 0; i < 7 && grp_goal > start &&
					!ext2bp_test_block_in_use(sb, 
							rel_bit_to_abs_block(sb, group, grp_goal - 1))
					 && ext2bp_test_block_valid(sb, 
						rel_bit_to_abs_block(sb, group, grp_goal - 1));
					i++, grp_goal--)
				;
			spin_unlock(sb_bgl_lock(EXT2_SB(sb), group));
		}
	}
	start = grp_goal;

	BUG_ON(start < 0);

	unsigned long abs_grp_goal = rel_bit_to_abs_block(sb, group, grp_goal);
	if (ext2bp_mark_block_used(sb, abs_grp_goal) || !ext2bp_test_block_valid(sb, abs_grp_goal)) {
		
		// Block was either not valid, or already used. 
		start++;
		grp_goal++;
		if (start >= end)
			goto fail_access;
		goto repeat;
	
	}

	/* Update block count statistics */	
	
	spin_lock(&ext2bp_sb_lock);
	percpu_counter_dec(&EXT2_SB(sb)->s_freeblocks_counter);
	EXT2_SB(sb)->bg_free_blocks_counts[group]-= 1;
	spin_unlock(&ext2bp_sb_lock);

	num++;
	grp_goal++;

	BUG_ON(grp_goal < 0);
	while (num < *count && grp_goal < end) {
		abs_grp_goal = rel_bit_to_abs_block(sb, group, grp_goal);
		if (ext2bp_mark_block_used(sb, abs_grp_goal) ||
				!ext2bp_test_block_valid(sb, abs_grp_goal)) {
			break;
		}
		/* Update block count statistics */	

		spin_lock(&ext2bp_sb_lock);
		percpu_counter_dec(&EXT2_SB(sb)->s_freeblocks_counter);
		EXT2_SB(sb)->bg_free_blocks_counts[group]-= 1;
		spin_unlock(&ext2bp_sb_lock);

		num++;
		grp_goal++;
	}

	*count = num;
	return grp_goal - num;
fail_access:
	*count = num;
	return -1;
}

/**
 * 	find_next_reservable_window():
 *		find a reservable space within the given range.
 *		It does not allocate the reservation window for now:
 *		alloc_new_reservation() will do the work later.
 *
 * 	@search_head: the head of the searching list;
 *		This is not necessarily the list head of the whole filesystem
 *
 *		We have both head and start_block to assist the search
 *		for the reservable space. The list starts from head,
 *		but we will shift to the place where start_block is,
 *		then start from there, when looking for a reservable space.
 *
 * 	@size: the target new reservation window size
 *
 * 	@group_first_block: the first block we consider to start
 *			the real search from
 *
 * 	@last_block:
 *		the maximum block number that our goal reservable space
 *		could start from. This is normally the last block in this
 *		group. The search will end when we found the start of next
 *		possible reservable space is out of this boundary.
 *		This could handle the cross boundary reservation window
 *		request.
 *
 * 	basically we search from the given range, rather than the whole
 * 	reservation double linked list, (start_block, last_block)
 * 	to find a free region that is of my size and has not
 * 	been reserved.
 *
 */
static int find_next_reservable_window(
				struct ext2_reserve_window_node *search_head,
				struct ext2_reserve_window_node *my_rsv,
				struct super_block * sb,
				ext2_fsblk_t start_block,
				ext2_fsblk_t last_block)
{
	struct rb_node *next;
	struct ext2_reserve_window_node *rsv, *prev;
	ext2_fsblk_t cur;
	int size = my_rsv->rsv_goal_size;

	/* TODO: make the start of the reservation window byte-aligned */
	/* cur = *start_block & ~7;*/
	cur = start_block;
	rsv = search_head;
	if (!rsv)
		return -1;

	while (1) {
		if (cur <= rsv->rsv_end)
			cur = rsv->rsv_end + 1;

		/* TODO?
		 * in the case we could not find a reservable space
		 * that is what is expected, during the re-search, we could
		 * remember what's the largest reservable space we could have
		 * and return that one.
		 *
		 * For now it will fail if we could not find the reservable
		 * space with expected-size (or more)...
		 */
		if (cur > last_block)
			return -1;		/* fail */

		prev = rsv;
		next = rb_next(&rsv->rsv_node);
		rsv = rb_entry(next,struct ext2_reserve_window_node,rsv_node);

		/*
		 * Reached the last reservation, we can just append to the
		 * previous one.
		 */
		if (!next)
			break;

		if (cur + size <= rsv->rsv_start) {
			/*
			 * Found a reserveable space big enough.  We could
			 * have a reservation across the group boundary here
		 	 */
			break;
		}
	}
	/*
	 * we come here either :
	 * when we reach the end of the whole list,
	 * and there is empty reservable space after last entry in the list.
	 * append it to the end of the list.
	 *
	 * or we found one reservable space in the middle of the list,
	 * return the reservation window that we could append to.
	 * succeed.
	 */

	if ((prev != my_rsv) && (!rsv_is_empty(&my_rsv->rsv_window)))
		rsv_window_remove(sb, my_rsv);

	/*
	 * Let's book the whole avaliable window for now.  We will check the
	 * disk bitmap later and then, if there are free blocks then we adjust
	 * the window size if it's larger than requested.
	 * Otherwise, we will remove this node from the tree next time
	 * call find_next_reservable_window.
	 */
	my_rsv->rsv_start = cur;
	my_rsv->rsv_end = cur + size - 1;
	my_rsv->rsv_alloc_hit = 0;

	if (prev != my_rsv)
		ext2_rsv_window_add(sb, my_rsv);

	return 0;
}

/**
 * 	alloc_new_reservation()--allocate a new reservation window
 *
 *		To make a new reservation, we search part of the filesystem
 *		reservation list (the list that inside the group). We try to
 *		allocate a new reservation window near the allocation goal,
 *		or the beginning of the group, if there is no goal.
 *
 *		We first find a reservable space after the goal, then from
 *		there, we check the bitmap for the first free block after
 *		it. If there is no free block until the end of group, then the
 *		whole group is full, we failed. Otherwise, check if the free
 *		block is inside the expected reservable space, if so, we
 *		succeed.
 *		If the first free block is outside the reservable space, then
 *		start from the first free block, we search for next available
 *		space, and go on.
 *
 *	on succeed, a new reservation will be found and inserted into the list
 *	It contains at least one free block, and it does not overlap with other
 *	reservation windows.
 *
 *	failed: we failed to find a reservation window in this group
 *
 *	@rsv: the reservation
 *
 *	@grp_goal: The goal (group-relative).  It is where the search for a
 *		free reservable space should start from.
 *		if we have a goal(goal >0 ), then start from there,
 *		no goal(goal = -1), we start from the first block
 *		of the group.
 *
 *	@sb: the super block
 *	@group: the group we are trying to allocate in
 *	@bitmap_bh: the block group block bitmap
 *
 */
static int alloc_new_reservation(struct ext2_reserve_window_node *my_rsv,
		ext2_grpblk_t grp_goal, struct super_block *sb,
		unsigned int group, struct buffer_head *bitmap_bh)
{
	struct ext2_reserve_window_node *search_head;
	ext2_fsblk_t group_first_block, group_end_block, start_block;
	ext2_grpblk_t first_free_block;
	struct rb_root *fs_rsv_root = &EXT2_SB(sb)->s_rsv_window_root;
	unsigned long size;
	int ret;
	spinlock_t *rsv_lock = &EXT2_SB(sb)->s_rsv_window_lock;

	group_first_block = ext2_group_first_block_no(sb, group);
	group_end_block = group_first_block + (EXT2_BLOCKS_PER_GROUP(sb) - 1);

	if (grp_goal < 0)
		start_block = group_first_block;
	else
		start_block = grp_goal + group_first_block;

	size = my_rsv->rsv_goal_size;

	if (!rsv_is_empty(&my_rsv->rsv_window)) {
		/*
		 * if the old reservation is cross group boundary
		 * and if the goal is inside the old reservation window,
		 * we will come here when we just failed to allocate from
		 * the first part of the window. We still have another part
		 * that belongs to the next group. In this case, there is no
		 * point to discard our window and try to allocate a new one
		 * in this group(which will fail). we should
		 * keep the reservation window, just simply move on.
		 *
		 * Maybe we could shift the start block of the reservation
		 * window to the first block of next group.
		 */

		if ((my_rsv->rsv_start <= group_end_block) &&
				(my_rsv->rsv_end > group_end_block) &&
				(start_block >= my_rsv->rsv_start))
			return -1;

		if ((my_rsv->rsv_alloc_hit >
		     (my_rsv->rsv_end - my_rsv->rsv_start + 1) / 2)) {
			/*
			 * if the previously allocation hit ratio is
			 * greater than 1/2, then we double the size of
			 * the reservation window the next time,
			 * otherwise we keep the same size window
			 */
			size = size * 2;
			if (size > EXT2_MAX_RESERVE_BLOCKS)
				size = EXT2_MAX_RESERVE_BLOCKS;
			my_rsv->rsv_goal_size= size;
		}
	}

	spin_lock(rsv_lock);
	/*
	 * shift the search start to the window near the goal block
	 */
	search_head = search_reserve_window(fs_rsv_root, start_block);

	/*
	 * find_next_reservable_window() simply finds a reservable window
	 * inside the given range(start_block, group_end_block).
	 *
	 * To make sure the reservation window has a free bit inside it, we
	 * need to check the bitmap after we found a reservable window.
	 */
retry:
	ret = find_next_reservable_window(search_head, my_rsv, sb,
						start_block, group_end_block);

	if (ret == -1) {
		if (!rsv_is_empty(&my_rsv->rsv_window))
			rsv_window_remove(sb, my_rsv);
		spin_unlock(rsv_lock);
		return -1;
	}

	/*
	 * On success, find_next_reservable_window() returns the
	 * reservation window where there is a reservable space after it.
	 * Before we reserve this reservable space, we need
	 * to make sure there is at least a free block inside this region.
	 *
	 * Search the first free bit on the block bitmap.  Search starts from
	 * the start block of the reservable space we just found.
	 */
	spin_unlock(rsv_lock);
		
	first_free_block = ext2bp_bitmap_search_next_usable_block(sb, 
			my_rsv->rsv_start - group_first_block + group * EXT2_BLOCKS_PER_GROUP(sb),
			group,
			group_end_block - group_first_block + 1 + group * EXT2_BLOCKS_PER_GROUP(sb)); 
	
	if (first_free_block < 0) {
		/*
		 * no free block left on the bitmap, no point
		 * to reserve the space. return failed.
		 */
		spin_lock(rsv_lock);
		if (!rsv_is_empty(&my_rsv->rsv_window))
			rsv_window_remove(sb, my_rsv);
		spin_unlock(rsv_lock);
		return -1;		/* failed */
	}

	/* Here they convert the bit back into a block*/
	start_block = first_free_block + group_first_block;
	/*
	 * check if the first free block is within the
	 * free space we just reserved
	 */
	if (start_block >= my_rsv->rsv_start && start_block <= my_rsv->rsv_end)
		return 0;		/* success */
	/*
	 * if the first free bit we found is out of the reservable space
	 * continue search for next reservable space,
	 * start from where the free block is,
	 * we also shift the list head to where we stopped last time
	 */
	search_head = my_rsv;
	spin_lock(rsv_lock);
	goto retry;
}

/**
 * try_to_extend_reservation()
 * @my_rsv:		given reservation window
 * @sb:			super block
 * @size:		the delta to extend
 *
 * Attempt to expand the reservation window large enough to have
 * required number of free blocks
 *
 * Since ext2_try_to_allocate() will always allocate blocks within
 * the reservation window range, if the window size is too small,
 * multiple blocks allocation has to stop at the end of the reservation
 * window. To make this more efficient, given the total number of
 * blocks needed and the current size of the window, we try to
 * expand the reservation window size if necessary on a best-effort
 * basis before ext2_new_blocks() tries to allocate blocks.
 */
static void try_to_extend_reservation(struct ext2_reserve_window_node *my_rsv,
			struct super_block *sb, int size)
{
	struct ext2_reserve_window_node *next_rsv;
	struct rb_node *next;
	spinlock_t *rsv_lock = &EXT2_SB(sb)->s_rsv_window_lock;

	if (!spin_trylock(rsv_lock))
		return;

	next = rb_next(&my_rsv->rsv_node);

	if (!next)
		my_rsv->rsv_end += size;
	else {
		next_rsv = rb_entry(next, struct ext2_reserve_window_node, rsv_node);

		if ((next_rsv->rsv_start - my_rsv->rsv_end - 1) >= size)
			my_rsv->rsv_end += size;
		else
			my_rsv->rsv_end = next_rsv->rsv_start - 1;
	}
	spin_unlock(rsv_lock);
}

/**
 * ext2_try_to_allocate_with_rsv()
 * @sb:			superblock
 * @group:		given allocation block group
 * @bitmap_bh:		bufferhead holds the block bitmap
 * @grp_goal:		given target block within the group
 * @count:		target number of blocks to allocate
 * @my_rsv:		reservation window
 *
 * This is the main function used to allocate a new block and its reservation
 * window.
 *
 * Each time when a new block allocation is need, first try to allocate from
 * its own reservation.  If it does not have a reservation window, instead of
 * looking for a free bit on bitmap first, then look up the reservation list to
 * see if it is inside somebody else's reservation window, we try to allocate a
 * reservation window for it starting from the goal first. Then do the block
 * allocation within the reservation window.
 *
 * This will avoid keeping on searching the reservation list again and
 * again when somebody is looking for a free block (without
 * reservation), and there are lots of free blocks, but they are all
 * being reserved.
 *
 * We use a red-black tree for the per-filesystem reservation list.
 */
static ext2_grpblk_t
ext2_try_to_allocate_with_rsv(struct super_block *sb, unsigned int group,
			struct buffer_head *bitmap_bh, ext2_grpblk_t grp_goal,
			struct ext2_reserve_window_node * my_rsv,
			unsigned long *count)
{
	ext2_fsblk_t group_first_block, group_last_block;
	ext2_grpblk_t ret = 0;
	unsigned long num = *count;

	/*
	 * we don't deal with reservation when
	 * filesystem is mounted without reservation
	 * or the file is not a regular file
	 * or last attempt to allocate a block with reservation turned on failed
	 */
	if (my_rsv == NULL) {
		return ext2_try_to_allocate(sb, group, bitmap_bh,
						grp_goal, count, NULL);
	}
	/*
	 * grp_goal is a group relative block number (if there is a goal)
	 * 0 <= grp_goal < EXT2_BLOCKS_PER_GROUP(sb)
	 * first block is a filesystem wide block number
	 * first block is the block number of the first block in this group
	 */
	group_first_block = ext2_group_first_block_no(sb, group);
	group_last_block = group_first_block + (EXT2_BLOCKS_PER_GROUP(sb) - 1);

	/*
	 * Basically we will allocate a new block from inode's reservation
	 * window.
	 *
	 * We need to allocate a new reservation window, if:
	 * a) inode does not have a reservation window; or
	 * b) last attempt to allocate a block from existing reservation
	 *    failed; or
	 * c) we come here with a goal and with a reservation window
	 *
	 * We do not need to allocate a new reservation window if we come here
	 * at the beginning with a goal and the goal is inside the window, or
	 * we don't have a goal but already have a reservation window.
	 * then we could go to allocate from the reservation window directly.
	 */
	while (1) {
		if (rsv_is_empty(&my_rsv->rsv_window) || (ret < 0) ||
			!goal_in_my_reservation(&my_rsv->rsv_window,
						grp_goal, group, sb)) {
			if (my_rsv->rsv_goal_size < *count)
				my_rsv->rsv_goal_size = *count;
			ret = alloc_new_reservation(my_rsv, grp_goal, sb,
							group, bitmap_bh);
			if (ret < 0)
				break;			/* failed */

			if (!goal_in_my_reservation(&my_rsv->rsv_window,
							grp_goal, group, sb))
				grp_goal = -1;
		} else if (grp_goal >= 0) {
			int curr = my_rsv->rsv_end -
					(grp_goal + group_first_block) + 1;

			if (curr < *count) {
				try_to_extend_reservation(my_rsv, sb,
							*count - curr);
			}
		}

		if ((my_rsv->rsv_start > group_last_block) ||
				(my_rsv->rsv_end < group_first_block)) {
			rsv_window_dump(&EXT2_SB(sb)->s_rsv_window_root, 1);
			BUG();
		}
		ret = ext2_try_to_allocate(sb, group, bitmap_bh, grp_goal,
					   &num, &my_rsv->rsv_window);
		if (ret >= 0) {
			my_rsv->rsv_alloc_hit += num;
			*count = num;
			break;				/* succeed */
		}
		num = *count;
	}
	return ret;
}

/**
 * ext2_has_free_blocks()
 * @sbi:		in-core super block structure.
 *
 * Check if filesystem has at least 1 free block available for allocation.
 */
static int ext2_has_free_blocks(struct ext2_sb_info *sbi)
{
	ext2_fsblk_t free_blocks, root_blocks;
	
	spin_lock(&ext2bp_sb_lock);
	free_blocks = percpu_counter_read_positive(&sbi->s_freeblocks_counter);
	root_blocks = le32_to_cpu(sbi->s_es->s_r_blocks_count);
	spin_unlock(&ext2bp_sb_lock);

	if (free_blocks < root_blocks + 1 && !capable(CAP_SYS_RESOURCE) &&
		sbi->s_resuid != current->fsuid &&
		(sbi->s_resgid == 0 || !in_group_p (sbi->s_resgid))) {
		return 0;
	}
	return 1;
}

/*
 * ext2_new_blocks() -- core block(s) allocation function
 * @inode:		file inode
 * @goal:		given target block(filesystem wide)
 * @count:		target number of blocks to allocate
 * @errp:		error code
 *
 * ext2_new_blocks uses a goal block to assist allocation.  If the goal is
 * free, or there is a free block within 32 blocks of the goal, that block
 * is allocated.  Otherwise a forward search is made for a free block; within 
 * each block group the search first looks for an entire free byte in the block
 * bitmap, and then for any free bit if that fails.
 * This function also updates quota and i_blocks field.
 */
ext2_fsblk_t ext2_new_blocks(struct inode *inode, ext2_fsblk_t goal,
		    unsigned long *count, int *errp)
{
	struct buffer_head *bitmap_bh = NULL;
	struct buffer_head *gdp_bh;
	int group_no;
	int goal_group;
	ext2_grpblk_t grp_target_blk;	/* blockgroup relative goal block */
	ext2_grpblk_t grp_alloc_blk;	/* blockgroup-relative allocated block*/
	ext2_fsblk_t ret_block;		/* filesyetem-wide allocated block */
	int bgi;			/* blockgroup iteration index */
	int performed_allocation = 0;
	ext2_grpblk_t free_blocks;	/* number of free blocks in a group */
	struct super_block *sb;
	struct ext2_group_desc *gdp;
	struct ext2_super_block *es;
	struct ext2_sb_info *sbi;
	struct ext2_reserve_window_node *my_rsv = NULL;
	struct ext2_block_alloc_info *block_i;
	unsigned short windowsz = 0;
	unsigned long ngroups;
	unsigned long num = *count;

	*errp = -ENOSPC;
	sb = inode->i_sb;
	if (!sb) {
		printk("ext2_new_blocks: nonexistent device");
		return 0;
	}

	/*
	 * Check quota for allocation of this block.
	 */
	if (DQUOT_ALLOC_BLOCK(inode, num)) {
		*errp = -EDQUOT;
		return 0;
	}

	sbi = EXT2_SB(sb);
	es = EXT2_SB(sb)->s_es;
	ext2_debug("goal=%lu.\n", goal);
	/*
	 * Allocate a block from reservation only when
	 * filesystem is mounted with reservation(default,-o reservation), and
	 * it's a regular file, and
	 * the desired window size is greater than 0 (One could use ioctl
	 * command EXT2_IOC_SETRSVSZ to set the window size to 0 to turn off
	 * reservation on that particular file)
	 */
	block_i = EXT2_I(inode)->i_block_alloc_info;
	if (block_i) {
		windowsz = block_i->rsv_window_node.rsv_goal_size;
		if (windowsz > 0)
			my_rsv = &block_i->rsv_window_node;
	}

	if (!ext2_has_free_blocks(sbi)) {
		*errp = -ENOSPC;
		goto out;
	}

	/*
	 * First, test whether the goal block is free.
	 */
	if (goal < le32_to_cpu(es->s_first_data_block) ||
	    goal >= le32_to_cpu(es->s_blocks_count))
		goal = le32_to_cpu(es->s_first_data_block);
	group_no = (goal - le32_to_cpu(es->s_first_data_block)) /
			EXT2_BLOCKS_PER_GROUP(sb);
	goal_group = group_no;
retry_alloc:
	free_blocks = get_free_blocks_count(sb, group_no);
	
	/*
	 * if there is not enough free blocks to make a new resevation
	 * turn off reservation for this allocation
	 */
	if (my_rsv && (free_blocks < windowsz)
		&& (free_blocks > 0)
		&& (rsv_is_empty(&my_rsv->rsv_window)))
		my_rsv = NULL;

	if (free_blocks > 0) {
		grp_target_blk = ((goal - le32_to_cpu(es->s_first_data_block)) %
				EXT2_BLOCKS_PER_GROUP(sb));
		grp_alloc_blk = ext2_try_to_allocate_with_rsv(sb, group_no,
					bitmap_bh, grp_target_blk,
					my_rsv, &num);
		if (grp_alloc_blk >= 0)
			goto allocated;
	}

	ngroups = EXT2_SB(sb)->s_groups_count;
	smp_rmb();

	/*
	 * Now search the rest of the groups.  We assume that
	 * group_no and gdp correctly point to the last group visited.
	 */
	for (bgi = 0; bgi < ngroups; bgi++) {
		group_no++;
		if (group_no >= ngroups)
			group_no = 0;
		free_blocks = get_free_blocks_count(sb, group_no);
		/*
		 * skip this group if the number of
		 * free blocks is less than half of the reservation
		 * window size.
		 */
		if (my_rsv && (free_blocks <= (windowsz/2)))
			continue;

		/*
		 * try to allocate block(s) from this group, without a goal(-1).
		 */
		grp_alloc_blk = ext2_try_to_allocate_with_rsv(sb, group_no,
					bitmap_bh, -1, my_rsv, &num);
		if (grp_alloc_blk >= 0)
			goto allocated;
	}
	/*
	 * We may end up a bogus ealier ENOSPC error due to
	 * filesystem is "full" of reservations, but
	 * there maybe indeed free blocks avaliable on disk
	 * In this case, we just forget about the reservations
	 * just do block allocation as without reservations.
	 */
	if (my_rsv) {
		my_rsv = NULL;
		windowsz = 0;
		group_no = goal_group;
		goto retry_alloc;
	}
	/* No space left on the device */
	*errp = -ENOSPC;
	goto out;

allocated:

	ret_block = grp_alloc_blk + ext2_group_first_block_no(sb, group_no);

	performed_allocation = 1;

	if (ret_block + num - 1 >= le32_to_cpu(es->s_blocks_count)) {
		ext2_error(sb, "ext2_new_blocks",
			    "block("E2FSBLK") >= blocks count(%d) - "
			    "block_group = %d, es == %p ", ret_block,
			le32_to_cpu(es->s_blocks_count), group_no, es);
		goto out;
	}

	group_adjust_blocks(sb, group_no, gdp, gdp_bh, -num);
	
	spin_lock(sb_bgl_lock(EXT2_SB(sb), group_no));
	percpu_counter_sub(&sbi->s_freeblocks_counter, num);
	spin_unlock(sb_bgl_lock(EXT2_SB(sb), group_no));

	*errp = 0;
	DQUOT_FREE_BLOCK(inode, *count-num);
	*count = num;
	return ret_block;

io_error:
	*errp = -EIO;
out:
	/*
	 * Undo the block allocation
	 */
	if (!performed_allocation)
		DQUOT_FREE_BLOCK(inode, *count);
	//brelse(bitmap_bh);
	return 0;
}

ext2_fsblk_t ext2_new_block(struct inode *inode, unsigned long goal, int *errp)
{
	unsigned long count = 1;

	return ext2_new_blocks(inode, goal, &count, errp);
}

#ifdef EXT2FS_DEBUG

static const int nibblemap[] = {4, 3, 3, 2, 3, 2, 2, 1, 3, 2, 2, 1, 2, 1, 1, 0};

unsigned long ext2_count_free (struct buffer_head * map, unsigned int numchars)
{
	unsigned int i;
	unsigned long sum = 0;

	if (!map)
		return (0);
	for (i = 0; i < numchars; i++)
		sum += nibblemap[map->b_data[i] & 0xf] +
			nibblemap[(map->b_data[i] >> 4) & 0xf];
	return (sum);
}

#endif  /*  EXT2FS_DEBUG  */

/* Vijay: Changing this for ext2bp */
unsigned long ext2_count_free_blocks (struct super_block * sb)
{
	struct ext2_group_desc * desc;
	unsigned long desc_count = 0;
	int i;
#ifdef EXT2BPFS_DEBUG
	unsigned long bitmap_count, x;
	struct ext2_super_block *es;
	struct ext2_sb_info *sbi = EXT2_SB(sb);
	
	es = EXT2_SB(sb)->s_es;
	desc_count = 0;
	bitmap_count = 0;
	desc = NULL;
	for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
		desc_count += get_free_blocks_count(sb, i);	
	}

	return desc_count;
#else
    for (i = 0; i < EXT2_SB(sb)->s_groups_count; i++) {
        desc_count += get_free_blocks_count(sb, i);	
    }
    return desc_count;
#endif
}

static inline int test_root(int a, int b)
{
	int num = b;

	while (a > num)
		num *= b;
	return num == a;
}

static int ext2_group_sparse(int group)
{
	if (group <= 1)
		return 1;
	return (test_root(group, 3) || test_root(group, 5) ||
		test_root(group, 7));
}

/**
 *	ext2_bg_has_super - number of blocks used by the superblock in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the superblock (primary or backup)
 *	in this group.  Currently this will be only 0 or 1.
 */
int ext2_bg_has_super(struct super_block *sb, int group)
{
	if (EXT2_HAS_RO_COMPAT_FEATURE(sb,EXT2_FEATURE_RO_COMPAT_SPARSE_SUPER)&&
	    !ext2_group_sparse(group))
		return 0;
	return 1;
}

/**
 *	ext2_bg_num_gdb - number of blocks used by the group table in group
 *	@sb: superblock for filesystem
 *	@group: group number to check
 *
 *	Return the number of blocks used by the group descriptor table
 *	(primary or backup) in this group.  In the future there may be a
 *	different number of descriptor blocks in each group.
 */
unsigned long ext2_bg_num_gdb(struct super_block *sb, int group)
{
	return ext2_bg_has_super(sb, group) ? EXT2_SB(sb)->s_gdb_count : 0;
}

