// SPDX-License-Identifier: GPL-2.0-only
/*
 * Memory merging support.
 *
 * This code enables dynamic sharing of identical pages found in different
 * memory areas, even if they are not shared by fork()
 *
 * Copyright (C) 2008-2009 Red Hat, Inc.
 * Authors:
 *	Izik Eidus
 *	Andrea Arcangeli
 *	Chris Wright
 *	Hugh Dickins
 */

#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/mm_inline.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/rwsem.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/spinlock.h>
#include <linux/xxhash.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/memory.h>
#include <linux/mmu_notifier.h>
#include <linux/swap.h>
#include <linux/ksm.h>
#include <linux/hashtable.h>
#include <linux/freezer.h>
#include <linux/oom.h>
#include <linux/numa.h>
#include <linux/pagewalk.h>
#include <linux/irq.h>
#include <linux/vmalloc.h>
#include <linux/timex.h>

#include <linux/dma-mapping.h>
#include <linux/idxd.h>
#include <linux/hrtimer.h>

#include <asm/tlbflush.h>
#include <asm/unaligned.h>
#include "internal.h"
#include "mm_slot.h"

#ifdef CONFIG_NUMA
#define NUMA(x)		(x)
#define DO_NUMA(x)	do { (x); } while (0)
#else
#define NUMA(x)		(0)
#define DO_NUMA(x)	do { } while (0)
#endif

static inline unsigned char
ksm_umwait(unsigned int state, unsigned long long timeout) 
{
  uint8_t r;
  uint32_t timeout_low = (uint32_t)timeout;
  uint32_t timeout_high = (uint32_t)(timeout >> 32);
  asm volatile(".byte 0xf2, 0x48, 0x0f, 0xae, 0xf1\t\n"
    "setc %0\t\n" :
    "=r"(r) :
    "c"(state), "a"(timeout_low), "d"(timeout_high));
  return r;
}

static inline void
ksm_umonitor(void *addr) 
{
  asm volatile(".byte 0xf3, 0x48, 0x0f, 0xae, 0xf0" : : "a"(addr));
}

/**
 * DOC: Overview
 *
 * A few notes about the KSM scanning process,
 * to make it easier to understand the data structures below:
 *
 * In order to reduce excessive scanning, KSM sorts the memory pages by their
 * contents into a data structure that holds pointers to the pages' locations.
 *
 * Since the contents of the pages may change at any moment, KSM cannot just
 * insert the pages into a normal sorted tree and expect it to find anything.
 * Therefore KSM uses two data structures - the stable and the unstable tree.
 *
 * The stable tree holds pointers to all the merged pages (ksm pages), sorted
 * by their contents.  Because each such page is write-protected, searching on
 * this tree is fully assured to be working (except when pages are unmapped),
 * and therefore this tree is called the stable tree.
 *
 * The stable tree node includes information required for reverse
 * mapping from a KSM page to virtual addresses that map this page.
 *
 * In order to avoid large latencies of the rmap walks on KSM pages,
 * KSM maintains two types of nodes in the stable tree:
 *
 * * the regular nodes that keep the reverse mapping structures in a
 *   linked list
 * * the "chains" that link nodes ("dups") that represent the same
 *   write protected memory content, but each "dup" corresponds to a
 *   different KSM page copy of that content
 *
 * Internally, the regular nodes, "dups" and "chains" are represented
 * using the same struct ksm_stable_node structure.
 *
 * In addition to the stable tree, KSM uses a second data structure called the
 * unstable tree: this tree holds pointers to pages which have been found to
 * be "unchanged for a period of time".  The unstable tree sorts these pages
 * by their contents, but since they are not write-protected, KSM cannot rely
 * upon the unstable tree to work correctly - the unstable tree is liable to
 * be corrupted as its contents are modified, and so it is called unstable.
 *
 * KSM solves this problem by several techniques:
 *
 * 1) The unstable tree is flushed every time KSM completes scanning all
 *    memory areas, and then the tree is rebuilt again from the beginning.
 * 2) KSM will only insert into the unstable tree, pages whose hash value
 *    has not changed since the previous scan of all memory areas.
 * 3) The unstable tree is a RedBlack Tree - so its balancing is based on the
 *    colors of the nodes and not on their contents, assuring that even when
 *    the tree gets "corrupted" it won't get out of balance, so scanning time
 *    remains the same (also, searching and inserting nodes in an rbtree uses
 *    the same algorithm, so we have no overhead when we flush and rebuild).
 * 4) KSM never flushes the stable tree, which means that even if it were to
 *    take 10 attempts to find a page in the unstable tree, once it is found,
 *    it is secured in the stable tree.  (When we scan a new page, we first
 *    compare it against the stable tree, and then against the unstable tree.)
 *
 * If the merge_across_nodes tunable is unset, then KSM maintains multiple
 * stable trees and multiple unstable trees: one of each for each NUMA node.
 */

/* The stable and unstable tree heads */
static struct rb_root one_stable_tree[1] = { RB_ROOT };
static struct rb_root one_unstable_tree[1] = { RB_ROOT };
static struct rb_root *root_stable_tree = one_stable_tree;
static struct rb_root *root_unstable_tree = one_unstable_tree;

/**
 * struct ksm_mm_slot - ksm information per mm that is being scanned
 * @slot: hash lookup from mm to mm_slot
 * @rmap_list: head for this mm_slot's singly-linked list of rmap_items
 */
struct ksm_mm_slot {
	struct mm_slot slot;
	struct ksm_rmap_item *rmap_list;
};

/**
 * struct ksm_scan - cursor for scanning
 * @mm_slot: the current mm_slot we are scanning
 * @address: the next address inside that to be scanned
 * @rmap_list: link to the next rmap to be scanned in the rmap_list
 * @seqnr: count of completed full scans (needed when removing unstable node)
 *
 * There is only the one ksm_scan instance of this cursor structure.
 */
struct ksm_scan {
	struct ksm_mm_slot *mm_slot;
	unsigned long address;
	struct ksm_rmap_item **rmap_list;
	unsigned long seqnr;
};

/**
 * struct ksm_stable_node - node of the stable rbtree
 * @node: rb node of this ksm page in the stable tree
 * @head: (overlaying parent) &migrate_nodes indicates temporarily on that list
 * @hlist_dup: linked into the stable_node->hlist with a stable_node chain
 * @list: linked into migrate_nodes, pending placement in the proper node tree
 * @hlist: hlist head of rmap_items using this ksm page
 * @kpfn: page frame number of this ksm page (perhaps temporarily on wrong nid)
 * @chain_prune_time: time of the last full garbage collection
 * @rmap_hlist_len: number of rmap_item entries in hlist or STABLE_NODE_CHAIN
 * @nid: NUMA node id of stable tree in which linked (may not match kpfn)
 */
struct ksm_stable_node {
	union {
		struct rb_node node;
		struct {
			struct list_head *head;
			struct {
				struct hlist_node hlist_dup;
				struct list_head list;
			};
		};
	};
	struct hlist_head hlist;
	union {
		unsigned long kpfn;
		unsigned long chain_prune_time;
	};
	/*
	 * STABLE_NODE_CHAIN can be any negative number in
	 * rmap_hlist_len negative range, but better not -1 to be able
	 * to reliably detect underflows.
	 */
#define STABLE_NODE_CHAIN -1024
	int rmap_hlist_len;
#ifdef CONFIG_NUMA
	int nid;
#endif

	/* used for speculative batching mode */
	struct list_head pending_list;
	bool pended;
};

/**
 * struct ksm_rmap_item - reverse mapping item for virtual addresses
 * @rmap_list: next rmap_item in mm_slot's singly-linked rmap_list
 * @anon_vma: pointer to anon_vma for this mm,address, when in stable tree
 * @nid: NUMA node id of unstable tree in which linked (may not match page)
 * @mm: the memory structure this rmap_item is pointing into
 * @address: the virtual address this rmap_item tracks (+ flags in low bits)
 * @oldchecksum: previous checksum of the page at that virtual address
 * @node: rb node of this rmap_item in the unstable tree
 * @head: pointer to stable_node heading this list in the stable tree
 * @hlist: link into hlist of rmap_items hanging off that stable_node
 */
struct ksm_rmap_item {
	struct ksm_rmap_item *rmap_list;
	union {
		struct anon_vma *anon_vma;	/* when stable */
#ifdef CONFIG_NUMA
		int nid;		/* when node of unstable tree */
#endif
	};
	struct mm_struct *mm;
	unsigned long address;		/* + low bits used for flags below */
	unsigned int oldchecksum;	/* when unstable */
	union {
		struct rb_node node;	/* when node of unstable tree */
		struct {		/* when listed from stable tree */
			struct ksm_stable_node *head;
			struct hlist_node hlist;
		};
	};
};

struct cursor {
	int index;
	struct list_head list;
	bool need_insert;
};

static DECLARE_WAIT_QUEUE_HEAD(ksm_thread_wait);
static DECLARE_WAIT_QUEUE_HEAD(ksm_iter_wait);
static DEFINE_SPINLOCK(ksm_mmlist_lock);
/*
 * Global Variables for DSA Batching
 */
#define MAX_KSM_BATCH_SIZE 1024
#define N_cand 100
#define ZERO_ARRAY(array, size) memset((array), 0, (size) * sizeof(*(array)))
#define ONE_ARRAY(array, size) memset((array), 1, (size) * sizeof(*(array)))

dma_addr_t dsa_calc_checksum_batch_src_addr[MAX_KSM_BATCH_SIZE];

dma_addr_t dsa_memcmp_pages_batch_src_addr[MAX_KSM_BATCH_SIZE];
dma_addr_t dsa_memcmp_pages_batch_dst_addr[MAX_KSM_BATCH_SIZE];

struct rb_node *stable_tree_search_nodes[MAX_KSM_BATCH_SIZE];
struct page *stable_tree_search_tree_pages[MAX_KSM_BATCH_SIZE];
struct ksm_stable_node *stable_tree_search_stable_node_dup[MAX_KSM_BATCH_SIZE];
struct ksm_stable_node *stable_tree_search_stable_node[MAX_KSM_BATCH_SIZE];
struct rb_node **stable_tree_search_new[MAX_KSM_BATCH_SIZE];
struct rb_node *stable_tree_search_parent[MAX_KSM_BATCH_SIZE];
bool stable_tree_search_valid[MAX_KSM_BATCH_SIZE];
bool stable_tree_search_hybrid_valid[MAX_KSM_BATCH_SIZE];
int stable_tree_search_ret[MAX_KSM_BATCH_SIZE];
bool stable_tree_search_returned[MAX_KSM_BATCH_SIZE];
bool stable_tree_search_need_again[MAX_KSM_BATCH_SIZE];
int stable_tree_search_output[MAX_KSM_BATCH_SIZE];
int stable_tree_search_index[MAX_KSM_BATCH_SIZE];

struct rb_node *stable_tree_insert_nodes[MAX_KSM_BATCH_SIZE];
struct page *stable_tree_insert_tree_pages[MAX_KSM_BATCH_SIZE];
struct ksm_stable_node *stable_tree_insert_stable_node_dup[MAX_KSM_BATCH_SIZE];
struct ksm_stable_node *stable_tree_insert_stable_node[MAX_KSM_BATCH_SIZE];
bool stable_tree_insert_valid[MAX_KSM_BATCH_SIZE];
int stable_tree_insert_ret[MAX_KSM_BATCH_SIZE];

struct rb_node *unstable_tree_search_insert_nodes[MAX_KSM_BATCH_SIZE];
struct page *unstable_tree_search_insert_tree_pages[MAX_KSM_BATCH_SIZE];
struct ksm_rmap_item *unstable_tree_search_insert_tree_rmap_items[MAX_KSM_BATCH_SIZE];
bool unstable_tree_search_insert_valid[MAX_KSM_BATCH_SIZE];
bool unstable_tree_search_insert_hybird_valid[MAX_KSM_BATCH_SIZE];
int unstable_tree_search_insert_ret[MAX_KSM_BATCH_SIZE];

struct rb_node **unstable_tree_search_insert_new[MAX_KSM_BATCH_SIZE];
struct rb_node *unstable_tree_search_insert_parent[MAX_KSM_BATCH_SIZE]; 
struct rb_node *unstable_tree_search_insert_sucessor[MAX_KSM_BATCH_SIZE]; 
struct list_head *unstable_tree_search_cursor_list[MAX_KSM_BATCH_SIZE];
bool unstable_tree_search_insert_returned[MAX_KSM_BATCH_SIZE];

// stable tree insert candidate
struct rb_node **stable_tree_insert_new[MAX_KSM_BATCH_SIZE];
struct rb_node *stable_tree_insert_parent[MAX_KSM_BATCH_SIZE]; 
struct rb_node *stable_tree_insert_sucessor[MAX_KSM_BATCH_SIZE]; 
struct list_head *stable_tree_insert_cursor_list[MAX_KSM_BATCH_SIZE];
struct ksm_stable_node *stable_tree_insert_stable_node_any[MAX_KSM_BATCH_SIZE];
unsigned long stable_tree_insert_kpfn[MAX_KSM_BATCH_SIZE];
bool stable_tree_insert_need_again[MAX_KSM_BATCH_SIZE];
bool stable_tree_insert_returned[MAX_KSM_BATCH_SIZE];
bool stable_tree_insert_need_chain[MAX_KSM_BATCH_SIZE];

struct mm_struct *cmp_and_merge_page_mm[MAX_KSM_BATCH_SIZE];
struct ksm_rmap_item *cmp_and_merge_page_tree_rmap_item[MAX_KSM_BATCH_SIZE];
struct page *cmp_and_merge_page_tree_page[MAX_KSM_BATCH_SIZE];
struct ksm_stable_node *cmp_and_merge_page_stable_node[MAX_KSM_BATCH_SIZE];
struct page *cmp_and_merge_page_kpage[MAX_KSM_BATCH_SIZE];
unsigned int cmp_and_merge_page_checksum[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_skip[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_put_skip[MAX_KSM_BATCH_SIZE];

bool cmp_and_merge_page_need_stable_append[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_stable_skip[MAX_KSM_BATCH_SIZE];

struct ksm_rmap_item *ksm_do_scan_rmap_item[MAX_KSM_BATCH_SIZE];
struct page *ksm_do_scan_page[MAX_KSM_BATCH_SIZE];


struct ksm_rmap_item *ksm_do_scan_new_rmap_item[N_cand * MAX_KSM_BATCH_SIZE];
struct page *ksm_do_scan_new_page[N_cand * MAX_KSM_BATCH_SIZE];

struct mm_struct *cmp_and_merge_page_mm_new1[N_cand * MAX_KSM_BATCH_SIZE];
struct ksm_stable_node *cmp_and_merge_page_stable_node_new1[N_cand * MAX_KSM_BATCH_SIZE];
struct page *cmp_and_merge_page_kpage_new1[N_cand * MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_skip_new1[N_cand * MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_skip_merge_new1[N_cand * MAX_KSM_BATCH_SIZE];
int cmp_and_merge_page_errors_new1[N_cand * MAX_KSM_BATCH_SIZE];

bool cmp_and_merge_page_need_skip_new2[MAX_KSM_BATCH_SIZE];
struct page * cmp_and_merge_page_page_new2[MAX_KSM_BATCH_SIZE];
struct ksm_rmap_item *cmp_and_merge_page_rmap_item_new2[MAX_KSM_BATCH_SIZE];
struct ksm_rmap_item *cmp_and_merge_page_tree_rmap_item_new2[MAX_KSM_BATCH_SIZE];
struct page *cmp_and_merge_page_tree_page_new2[MAX_KSM_BATCH_SIZE];
unsigned int cmp_and_merge_page_checksum_new2[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_put_skip_new2[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_stable_append_new2[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_stable_skip_new2[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_skip_merge2_new2[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_skip_merge2_1_new2[MAX_KSM_BATCH_SIZE];
bool cmp_and_merge_page_need_skip_merge3_new2[MAX_KSM_BATCH_SIZE];

struct mm_struct *try_to_merge_with_ksm_page_mm[MAX_KSM_BATCH_SIZE];
struct vm_area_struct *try_to_merge_with_ksm_page_vma[MAX_KSM_BATCH_SIZE];
bool try_to_merge_with_ksm_page_returned[MAX_KSM_BATCH_SIZE];

pte_t try_to_merge_one_page_orig_pte[MAX_KSM_BATCH_SIZE];
bool try_to_merge_one_page_returned[MAX_KSM_BATCH_SIZE];
int try_to_merge_one_page_ret[MAX_KSM_BATCH_SIZE];
bool try_to_merge_one_page_valid[MAX_KSM_BATCH_SIZE];

int try_to_merge_two_pages_err[MAX_KSM_BATCH_SIZE];
struct page *try_to_merge_two_pages_null_page[MAX_KSM_BATCH_SIZE];

/*
 * KSM debug and profiling related
 */
enum ksm_debug_enum {
	HYBRID_CPU_COMPARE,
	COMPARE,
	COMPARE_BATCH,
	CRC,
	CRC_BATCH,
	CREATE_DELTA,
	CREATE_DELTA_BATCH,
	APPLY_DELTA,
	KSM_DO_SCAN,
	SCAN_GET_NEXT_RMAP_ITEM,
	CMP_AND_MERGE,
	STABLE_TREE_SEARCH,
	UNSTABLE_TREE_SEARCH_INSERT,
	STABLE_TREE_INSERT,
	// TODO[osm] : To measure compare_candidate
	COMPARE_CANDIDATE,
	UNSTABLE_UNINSERT_GET_MERGEABLE_PAGE,
	UNSTABLE_UNINSERT_POINTER,
	UNSTABLE_UNINSERT_DIFF_HASH,
	NUM_KSM_DEBUG_STAT
};

static const char * const ksm_debug_stat_strs[] = {
	"hybrid_cpu_compare",
	"compare",
	"compare_batch",
	"crc",
	"crc_batch",
	"create_delta",
	"create_delta_batch",
	"apply_delta",
	"ksm_do_scan",
	"scan_get_next_rmap_item",
	"cmp_and_merge",
	"stable_tree_search",
	"unstable_tree_search_insert",
	"stable_tree_insert",
	// TODO[osm] : To measure compare_candidate
	"compare_candidate",
	"unstable_uninsert_get_mergeable_page",
	"unstable_uninsert_pointer",
	"unstable_uninsert_diff_hash",
};

struct ksm_debug_stat {
	unsigned long num[NUM_KSM_DEBUG_STAT];
	unsigned long start[NUM_KSM_DEBUG_STAT];
	unsigned long end[NUM_KSM_DEBUG_STAT];
	unsigned long total[NUM_KSM_DEBUG_STAT];
	unsigned long avg[NUM_KSM_DEBUG_STAT];
};

struct ksm_debug_stat ksm_debug_stat;
static unsigned long compare_bytes[4096];
static unsigned long compare_cycles[4096];


unsigned long enable_ksm_debug = 0;
static bool ksm_debug_enabled(void)
{
	if (enable_ksm_debug == 1)
		return true;
	else
		return false;
}

static inline void ksm_debug_start(int idx)
{
	if (ksm_debug_enabled())
		ksm_debug_stat.start[idx] = get_cycles();
}

static inline void ksm_debug_end(int idx)
{
	if (ksm_debug_enabled()) {
		ksm_debug_stat.end[idx] = get_cycles();
		ksm_debug_stat.total[idx] += (ksm_debug_stat.end[idx] - ksm_debug_stat.start[idx]);
		ksm_debug_stat.num[idx]++;
	}
}

static void ksm_debug_count(int idx, unsigned long num)
{
	if (ksm_debug_enabled()) 
		ksm_debug_stat.num[idx] += num;
}

static void ksm_debug_stat_reset(void)
{
	int i;
	for (i = 0; i < NUM_KSM_DEBUG_STAT; i++) {
		ksm_debug_stat.num[i] = 0;
		ksm_debug_stat.start[i] = 0;
		ksm_debug_stat.end[i] = 0;
		ksm_debug_stat.total[i] = 0;
		ksm_debug_stat.avg[i] = 0;
	}
	ZERO_ARRAY(compare_bytes, 4096);
	ZERO_ARRAY(compare_cycles, 4096);
}

static void ksm_debug_stat_show(void)
{
	int i;
	trace_printk("name,num,total_cycles,avg_cycles\n");
	for (i = 0; i < NUM_KSM_DEBUG_STAT; i++) {
		if (ksm_debug_stat.num[i] == 0) {
			trace_printk("%s,0,0,0\n", ksm_debug_stat_strs[i]);
		} else {
			ksm_debug_stat.avg[i] = ksm_debug_stat.total[i] / ksm_debug_stat.num[i];
			trace_printk("%s,%lu,%lu,%lu\n",
					ksm_debug_stat_strs[i], ksm_debug_stat.num[i],
					ksm_debug_stat.total[i], ksm_debug_stat.avg[i]);
		}
	}
}

static void ksm_cpu_compare_stat_show(void)
{
	int i;
	trace_printk("byte_offset,memory_reads(B),cycles\n");
	for (i = 0; i < 4096; i++) {
		trace_printk("%d,%lu,%lu\n", i, compare_bytes[i], compare_cycles[i]);
	}
}

__visible int cpu_memcmp(const void *cs, const void *ct, size_t count)
{
	const unsigned char *su1, *su2;
	int res = 0;
	unsigned long start, end, idx;

	idx = 0;
	start = get_cycles();

	if (count >= sizeof(unsigned long)) {
		const unsigned long *u1 = cs;
		const unsigned long *u2 = ct;
		do {
			if (get_unaligned(u1) != get_unaligned(u2))
				break;
			u1++;
			u2++;
			count -= sizeof(unsigned long);
		} while (count >= sizeof(unsigned long));
		cs = u1;
		ct = u2;
	}
	for (su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;

	end = get_cycles();
	if (count > 0)
		idx = PAGE_SIZE - count;
	else
		idx = PAGE_SIZE - 1;

	compare_bytes[idx] += ((idx+1) * 2);
	compare_cycles[idx] += (end - start);
	return res;
}

static unsigned long batch_mode;
static int cpu_memcmp_pages(struct page *page1, struct page *page2)
{
	char *addr1, *addr2;
	int ret = 0;

	if (batch_mode)
		ksm_debug_start(COMPARE_BATCH);
	else
		ksm_debug_start(COMPARE);

	if (!ksm_debug_enabled()) {
		ret = memcmp_pages(page1, page2);
		goto out;
	}

	addr1 = kmap_atomic(page1);
	addr2 = kmap_atomic(page2);
	ret = cpu_memcmp(addr1, addr2, PAGE_SIZE);
	kunmap_atomic(addr2);
	kunmap_atomic(addr1);

out:
	if (batch_mode) {
		ksm_debug_end(COMPARE_BATCH);
		ksm_debug_count(COMPARE, 1);
	} else
		ksm_debug_end(COMPARE);
	return ret;
}

static void cpu_memcmp_pages_batch(struct page **page1, struct page **page2,
		int num_page1, int num_page2, bool *valid, int *ret)
{
	int i, j, k;
	int valid_count = 0;

	ksm_debug_start(COMPARE_BATCH);

	for (i = 0; i < num_page1; i++) {
		for (j = 0; j < num_page2; j++) {
			k = i * num_page2 + j;
			if (valid[k]) {
				ret[k] = memcmp_pages(page1[i], page2[k]);
				valid_count++;
			}
		}
	}

	ksm_debug_end(COMPARE_BATCH);
	ksm_debug_count(COMPARE, valid_count);
}

/*
 * DSA-related struct, variables, funtions
 */
#define DSA_BUF_SIZE MAX_KSM_BATCH_SIZE

struct ksm_dsa_info {
	struct device *dev;
	struct idxd_wq *wq;
	struct idxd_device *idxd;
	void __iomem *wq_portal;

	/* For all op */
	struct dsa_hw_desc *desc;
	struct dsa_completion_record *comp;
	dma_addr_t *comp_dma;

	/* For Batch op */
	struct dsa_hw_desc *batch_desc;
	struct dsa_completion_record *batch_comp;
	dma_addr_t batch_comp_dma;
	dma_addr_t desc_buf_dma;
};
struct ksm_dsa_info ksm_dsa_info;

/* DSA related sysfs parameter */
static char dsa_cdev_name[256] = "/dev/dma_dsa/wq0.0"; // work queue for ksmd
static unsigned long use_dsa = 0;
// TODO[osm] : To measure compare_candidate
static unsigned long use_dsa_for_hash = 1;
enum dsa_completion_modes {
	DSA_COMPL_IRQ,
	DSA_COMPL_SPIN_POLLING,
	DSA_COMPL_SPIN_POLLING_WITH_WAIT,
	DSA_COMPL_MWAIT,
	DSA_COMPL_SPIN_POLLING_WITH_SCHED,
	DSA_COMPL_MWAIT_WITH_SCHED,
	NUM_DSA_COMPL,
};
static unsigned long dsa_completion_mode = DSA_COMPL_IRQ;
static unsigned long dsa_polling_wait_ns = 100;
static unsigned long dsa_sched_us_start = 30;
static unsigned long dsa_sched_us_end = 1;
static unsigned long enable_dsa_hybrid = 0;
static unsigned long dsa_sched_us_max[1025] = {
0,2,3,3,3,4,4,4,4,4,5,5,5,6,6,6,6,6,7,7,7,8,8,8,8,9,9,9,9,10,10,10,10,11,11,11,11,12,12,12,13,13,13,13,14,14,14,14,15,15,15,15,16,16,16,16,17,17,17,18,18,18,18,19,19,19,19,20,20,20,20,21,21,21,22,22,22,22,23,23,23,23,24,24,24,24,25,25,25,26,26,26,26,27,27,27,27,27,28,28,28,29,29,29,29,30,30,30,30,31,31,31,31,32,32,32,32,33,33,33,34,34,34,34,35,35,35,35,36,36,36,36,37,37,37,38,38,38,38,38,39,39,39,40,40,40,40,41,41,41,41,42,42,42,43,43,43,43,44,44,44,44,45,45,45,45,46,46,46,46,47,47,47,47,48,48,48,49,49,49,49,49,50,50,50,51,51,51,51,52,52,52,53,53,53,53,54,54,54,54,55,55,55,55,56,56,56,56,57,57,57,58,58,58,58,59,59,59,59,59,60,60,60,61,61,61,62,62,62,62,63,63,63,63,64,64,64,64,65,65,65,65,66,66,66,66,67,67,67,67,68,68,68,69,69,69,69,70,70,70,70,71,71,71,72,72,72,72,72,72,73,73,74,74,74,74,75,75,75,75,76,76,76,77,77,77,77,78,78,78,78,79,79,80,79,80,80,80,80,81,81,81,81,82,82,82,83,83,83,83,83,84,84,84,85,85,85,85,86,86,86,86,87,87,87,88,88,88,88,89,89,90,89,90,90,90,90,91,91,91,91,92,92,92,93,93,93,93,94,94,94,95,95,94,95,96,96,96,96,97,97,97,97,97,98,98,98,99,99,99,99,100,100,100,100,101,101,101,102,102,102,103,103,103,103,103,104,104,104,105,105,105,105,105,106,106,106,106,107,107,107,107,108,108,108,109,109,109,109,110,110,110,110,111,111,111,111,112,112,112,113,113,113,113,114,114,114,114,115,115,115,115,116,116,116,116,117,117,117,118,118,118,118,118,119,119,119,120,120,120,120,121,121,121,121,122,122,122,123,123,123,123,124,124,124,125,125,125,125,125,126,126,126,127,127,127,127,127,128,128,128,129,129,129,129,130,130,130,130,131,131,131,131,132,132,132,132,133,133,133,134,134,134,134,135,135,135,135,136,136,136,137,137,137,137,138,138,138,138,139,139,139,140,140,140,140,140,140,141,141,141,142,142,142,143,143,143,143,144,144,144,144,145,145,145,145,146,146,146,146,147,146,147,147,148,148,148,149,149,149,149,150,150,150,150,151,151,151,151,152,152,152,153,153,153,153,153,154,154,154,154,155,155,155,156,156,156,156,157,157,157,158,157,158,158,158,159,159,159,160,160,160,160,161,161,161,161,161,162,162,163,163,163,163,164,164,164,164,165,165,164,165,166,166,166,166,167,167,167,167,168,168,168,168,169,168,169,170,170,170,170,171,171,171,171,172,172,172,173,173,173,173,174,174,174,174,175,175,175,175,176,176,176,176,177,177,177,177,177,178,178,179,179,179,179,180,180,180,180,181,181,181,181,182,182,182,182,183,183,183,183,184,184,184,185,185,185,185,186,186,186,186,187,187,187,187,187,188,188,188,189,189,190,189,190,190,190,191,191,191,191,192,191,192,192,193,193,193,193,194,194,194,194,195,195,195,196,196,196,196,197,197,197,197,198,198,198,198,199,199,199,200,200,200,200,201,201,201,201,202,202,202,202,203,203,203,204,204,204,204,205,205,205,205,205,206,206,206,207,207,207,207,207,208,208,208,208,209,209,210,210,210,210,211,211,211,211,212,212,212,212,213,213,213,213,214,214,214,214,217,215,215,216,216,216,216,217,217,217,218,218,218,218,218,219,219,219,219,220,220,220,220,221,221,221,222,222,222,222,223,223,223,223,224,224,224,225,225,225,225,225,226,226,225,227,227,227,227,228,227,228,228,229,229,229,230,230,230,230,231,231,231,231,231,232,232,232,233,233,233,233,234,234,234,234,235,234,235,236,236,236,236,237,237,237,237,237,238,238,238,239,239,238,239,240,240,240,241,241,241,241,241,242,242,242,243,243,243,243,243,244,244,244,245,245,245,245,246,246,246,247,247,247,247,247,248,248,248,248,249,249,249,250,250,250,250,251,250,251,252,252,252,252,252,253,253,253,254,254,254,254,255,255,255,255,256,256,256,257,257,257,257,258,258,258,258,259,259,259,259,260,260,260,260,261,261,261,261,262,262,262,262,263,263,264,264,264,265,264,265,265,265,265,266,266,265,266,267,266,267,268,268,268,268,269,269,269,269,269,270,270,270,271,271,271
};
static unsigned long dsa_sched_us_min[1025] = {
0,1,2,2,2,2,3,3,3,3,3,4,4,4,4,5,5,5,6,6,6,6,7,7,7,7,8,8,8,8,9,9,9,9,10,10,10,10,11,11,11,12,12,12,12,13,13,13,13,14,14,14,14,15,15,15,15,16,16,16,16,17,17,17,18,18,18,18,18,19,19,19,20,20,20,20,21,21,21,21,22,22,22,23,23,23,23,24,24,24,24,25,25,25,25,26,26,26,26,27,27,27,27,28,28,28,29,29,29,29,30,30,30,30,31,31,31,31,32,32,32,32,33,33,33,34,34,34,34,35,35,35,35,36,36,36,36,37,37,37,37,38,38,38,38,39,39,39,39,40,40,40,40,41,41,41,41,42,42,42,43,43,43,43,44,44,44,44,45,45,45,45,46,46,46,47,47,47,47,48,48,48,48,49,49,49,49,50,50,50,50,51,51,51,52,52,52,52,53,53,53,53,54,54,54,54,55,55,55,55,56,56,56,56,57,57,57,57,58,58,58,58,59,59,59,59,60,60,61,61,61,61,61,62,62,62,62,63,63,63,63,64,64,64,65,65,65,65,66,66,66,66,67,67,67,67,68,68,68,68,69,69,69,69,70,70,70,70,71,71,71,72,72,72,72,72,73,73,73,74,74,74,74,75,75,75,75,76,76,76,76,77,77,77,77,78,78,78,79,79,79,79,80,80,80,80,81,81,81,81,82,82,82,82,83,83,83,83,84,84,84,85,85,85,85,86,86,86,86,87,87,87,88,88,88,88,88,89,89,89,90,90,90,90,91,91,91,91,92,92,92,92,93,93,93,93,94,94,94,94,95,95,95,95,96,96,96,97,97,97,97,98,98,98,98,99,99,100,99,100,100,100,100,101,101,101,101,102,102,102,102,103,103,104,104,104,104,104,105,105,105,105,106,106,106,106,107,107,107,107,108,108,108,109,109,109,109,110,110,110,110,111,111,111,111,112,112,112,112,113,113,113,113,114,114,114,115,115,115,115,115,116,116,116,117,117,117,117,118,118,118,118,119,119,119,119,120,120,120,120,121,121,121,122,122,122,122,123,123,123,123,124,124,124,124,125,125,125,126,126,126,126,127,127,127,127,127,128,128,128,129,129,129,129,130,130,130,130,131,131,131,131,132,132,132,133,133,133,133,133,134,134,134,135,135,135,135,136,136,136,136,137,137,137,138,138,138,139,139,139,139,139,140,140,140,140,141,141,141,141,142,142,142,142,143,143,143,143,144,144,144,145,145,145,145,146,146,146,146,147,147,147,147,148,148,148,148,149,149,149,150,150,150,150,151,151,151,151,152,152,152,152,153,153,153,153,154,154,154,154,155,155,156,156,156,156,156,156,157,157,157,158,158,158,158,159,159,160,159,160,160,160,160,161,161,161,162,162,162,162,163,163,163,163,164,164,164,164,165,165,165,165,166,166,166,167,167,167,167,168,168,168,168,169,169,169,169,170,169,170,170,171,171,171,172,172,172,172,172,173,173,173,174,174,174,174,174,175,175,175,176,176,176,176,177,177,177,177,178,178,178,179,179,179,179,180,180,180,180,181,181,181,181,182,182,182,183,183,183,183,183,184,184,184,184,185,185,185,186,186,186,186,186,187,187,187,188,188,188,188,189,189,189,190,190,190,190,191,191,191,192,192,192,192,192,193,193,193,193,194,194,194,194,195,195,195,195,196,196,196,196,197,197,198,198,198,198,198,198,199,199,199,200,200,200,200,201,201,201,201,202,202,202,202,203,203,203,204,204,204,204,205,205,205,205,206,206,206,206,207,207,207,207,208,208,208,209,209,209,209,210,210,210,210,211,211,211,211,212,210,212,212,213,213,213,213,214,214,214,214,215,215,215,215,216,216,216,217,217,217,217,218,218,218,218,219,219,219,219,220,220,220,220,221,221,221,222,222,222,222,223,223,223,224,224,224,224,225,225,225,225,225,226,226,226,227,227,227,227,228,228,228,228,229,229,229,229,230,230,230,230,231,231,231,231,232,233,232,232,233,233,233,233,234,234,234,235,235,235,235,236,236,237,236,237,237,237,237,238,238,238,239,239,239,239,240,240,240,240,241,241,241,241,242,242,242,242,243,243,243,243,244,244,244,245,245,245,245,246,246,246,246,247,247,247,247,248,249,248,248,249,249,249,250,250,250,250,251,251,251,251,252,252,252,252,253,253,253,253,254,254,254,255,255,255,255,255,256,256,256,256,257,257,257,258,258,258,259,259,259,259,260,260,260,260,260,261,261,261,262,262,262,262,263,263,264,264,264,265,264,264,265,265,265,266,266,266,266,266,267,267,267,268,268,268
};
static unsigned long dsa_sched_us_max_checksum[1025] = {
0,2,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,7,8,8,8,8,8,8,8,8,9,9,9,9,9,9,9,10,10,10,10,10,10,10,11,11,11,11,11,11,11,11,12,12,12,12,12,12,12,13,13,13,13,13,13,13,13,14,14,14,14,14,14,14,14,15,15,15,15,15,15,15,15,16,16,16,16,16,16,16,17,17,17,17,17,17,17,17,18,18,18,18,18,18,18,19,19,19,19,19,19,19,19,20,20,20,20,20,20,20,20,21,21,21,21,21,21,21,22,22,22,22,22,22,22,22,23,23,23,23,23,23,23,24,24,24,24,24,24,24,24,25,25,25,25,25,25,25,26,26,26,26,26,26,26,27,27,27,27,27,27,27,27,27,28,28,28,28,28,28,28,29,29,29,29,29,29,30,29,30,30,30,30,30,30,30,31,31,31,31,31,31,31,31,32,32,32,32,32,32,32,32,33,33,33,33,33,33,33,34,34,34,34,34,34,34,35,35,35,35,35,35,35,35,36,35,36,36,36,36,36,36,36,37,37,37,37,37,37,37,38,38,38,38,38,38,38,39,39,39,39,39,39,39,39,40,40,40,40,40,40,40,40,41,41,41,41,41,41,41,42,42,42,42,42,42,42,43,43,43,43,43,43,43,43,44,44,44,44,44,44,44,44,45,45,45,45,45,45,45,45,46,46,46,46,46,46,47,47,47,47,47,47,47,47,47,48,48,48,48,48,48,48,49,49,49,49,49,49,49,49,50,50,50,50,50,50,50,51,51,51,51,51,51,51,52,52,52,52,52,52,52,52,52,53,53,53,53,53,53,53,54,54,54,54,54,54,54,54,55,55,55,55,55,55,55,56,56,56,56,56,56,56,56,57,57,57,57,57,57,57,58,58,58,58,58,58,58,58,59,59,59,59,59,59,59,59,60,60,60,60,60,60,60,61,61,60,61,61,61,61,61,62,62,62,62,62,62,62,63,63,63,63,63,63,63,63,64,64,64,64,64,64,64,65,65,65,65,65,65,65,66,66,66,66,66,66,66,66,66,67,67,67,67,67,67,67,68,68,68,68,68,68,68,68,69,69,69,69,69,69,69,70,70,70,70,70,70,70,70,71,71,71,71,71,71,71,71,72,72,72,72,72,72,72,73,73,73,73,73,73,73,73,74,74,74,74,74,74,74,74,75,75,75,75,75,75,76,76,76,76,76,76,76,76,76,77,77,77,77,77,77,77,78,78,78,78,78,78,78,79,79,79,79,79,79,79,79,80,80,80,80,80,80,80,80,81,81,80,81,81,81,81,82,82,82,82,82,82,82,82,83,83,83,83,83,83,83,83,84,84,84,84,84,84,85,85,84,85,85,85,85,85,85,86,86,86,86,86,86,86,87,87,87,87,87,87,87,87,87,88,87,88,88,88,88,89,89,89,89,89,89,89,89,89,90,90,90,90,90,90,90,91,91,91,91,91,91,91,92,92,92,92,92,92,93,92,92,92,93,93,93,93,93,93,93,94,94,94,94,94,94,94,95,95,95,95,95,95,95,96,96,96,96,96,96,96,96,96,97,96,97,97,97,97,97,98,98,98,98,98,98,99,98,99,99,99,99,99,99,100,100,100,100,100,100,100,101,100,101,101,101,101,101,101,102,102,102,102,102,102,102,102,102,103,103,103,103,103,103,104,104,104,104,104,104,104,104,105,105,105,105,105,105,105,106,106,106,106,106,106,106,106,107,107,107,107,107,107,107,107,108,108,108,108,108,108,108,108,109,109,109,109,109,109,109,109,110,110,110,110,110,110,110,111,111,111,111,111,111,112,111,112,112,112,112,112,113,112,112,113,113,113,113,113,113,113,114,114,114,114,114,114,114,114,115,115,115,115,115,115,115,116,116,116,116,116,116,116,117,117,117,117,117,117,117,117,118,118,118,118,118,118,118,118,119,119,119,119,119,119,119,119,120,120,120,120,120,120,120,121,121,121,121,121,121,121,121,122,122,122,122,122,122,122,122,123,123,123,123,123,123,123,124,124,124,124,124,124,124,125,125,125,125,125,125,125,125,125,126,126,126,126,126,126,127,127,127,127,127,127,127,127,127,128,128,128,128,128,128,129,129,129,129,129,129,129,129,130,130,130,130,130,130,130,130,131,131,131,131,131,131,131,131,132,132,132,132,132,132,132,133,133,133,133,133,133,133,133,134,134,134,134,134,134,134,135,135,135,135,135,135,135,135,136,136,136,136,136,136,136,136,137,137,137,136,137,137
};
static unsigned long dsa_sched_us_min_checksum[1025] = {
0,1,1,2,2,2,2,2,2,2,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,6,6,6,6,6,6,6,6,7,7,7,7,7,7,7,8,8,8,8,8,8,8,8,9,9,9,9,9,9,9,9,10,10,10,10,10,10,10,11,11,11,11,11,11,11,11,12,12,12,12,12,12,12,12,13,13,13,13,13,13,13,14,14,14,14,14,14,14,14,15,15,15,15,15,15,15,15,16,16,16,16,16,16,16,17,17,17,17,17,17,17,18,18,18,18,18,18,18,18,19,19,19,19,19,19,19,19,20,20,20,20,20,20,20,20,21,21,21,21,21,21,21,21,22,22,22,22,22,22,22,23,23,23,23,23,23,23,24,24,24,24,24,24,24,24,25,25,25,25,25,25,25,25,26,26,26,26,26,26,26,26,27,27,27,27,27,27,27,27,28,28,27,28,28,28,28,29,29,29,29,29,29,29,30,30,30,30,30,30,30,30,31,31,31,31,31,31,31,31,32,32,32,32,32,32,32,32,33,33,33,33,33,33,33,34,34,34,34,34,34,34,34,35,35,35,35,35,35,35,35,36,36,36,36,36,36,36,36,37,37,37,37,37,37,37,38,38,38,38,38,38,38,38,39,39,39,39,39,39,39,39,40,40,40,40,40,40,40,41,41,41,41,41,41,41,41,42,42,42,42,42,42,42,43,43,43,43,43,43,43,43,44,44,44,44,44,44,44,44,45,45,45,45,45,45,45,46,46,46,46,46,46,46,46,47,47,47,47,47,47,48,47,48,48,48,48,48,48,48,48,49,49,49,49,49,49,49,50,50,50,50,50,50,50,50,51,51,51,51,51,51,52,52,52,52,52,52,52,52,52,53,53,53,53,53,53,53,53,54,54,54,54,54,54,54,55,55,55,55,55,55,55,55,56,56,56,56,56,56,56,56,57,57,57,57,57,57,57,58,58,58,58,58,58,58,58,58,59,59,59,59,59,59,59,60,60,60,60,60,60,60,61,61,61,61,61,61,61,61,62,62,62,62,62,62,62,62,63,63,63,63,63,63,63,63,63,64,64,64,64,64,64,64,65,65,65,65,65,65,65,66,66,66,66,66,66,66,66,67,67,67,67,67,67,67,68,68,68,68,68,68,68,68,69,69,69,69,69,69,69,70,70,70,70,70,70,70,70,71,71,71,71,71,71,71,71,72,72,72,72,72,72,72,72,73,73,73,73,73,73,73,74,74,74,74,74,74,74,74,74,75,75,75,75,75,75,76,76,76,76,76,76,76,76,76,77,77,77,77,77,77,77,78,78,78,78,78,78,78,79,79,79,79,79,79,79,79,80,79,80,80,80,80,81,80,80,81,81,81,81,81,81,81,82,82,82,82,82,82,82,83,83,83,83,83,83,83,83,84,84,84,84,84,84,84,84,85,85,85,85,85,85,85,86,86,86,86,86,86,86,86,87,87,87,87,87,87,87,88,88,88,88,88,88,88,88,88,89,89,89,89,89,90,89,90,90,90,90,90,90,90,91,91,91,91,91,91,91,92,92,92,92,92,92,92,92,92,93,93,93,93,93,93,93,93,94,94,94,94,94,94,94,95,95,95,95,95,95,95,95,96,96,96,96,96,96,96,97,97,97,97,97,97,97,97,97,98,98,98,98,98,98,99,99,99,99,99,99,99,99,100,100,100,100,100,100,100,100,101,101,101,101,101,101,101,102,101,102,102,102,102,103,102,102,103,103,103,103,103,103,103,104,104,104,104,104,104,104,105,105,105,105,105,105,105,105,106,106,106,106,106,106,106,106,106,107,107,107,107,107,107,108,108,108,108,108,108,108,108,108,109,109,109,109,109,109,109,110,110,110,110,110,110,110,110,111,111,111,111,111,111,111,112,112,112,112,112,112,113,112,113,113,113,113,113,113,113,113,114,114,114,114,114,114,114,115,115,115,115,115,115,115,116,116,116,116,116,116,116,116,116,117,117,117,117,117,117,117,117,118,118,118,118,118,118,118,119,119,119,119,119,119,119,120,120,120,120,120,120,120,120,121,121,121,121,121,121,121,121,122,122,122,122,122,122,122,122,123,123,123,123,123,124,123,124,124,124,124,124,124,124,124,125,125,125,125,125,125,125,125,126,126,126,126,126,126,126,126,127,127,127,127,127,127,127,128,128,128,128,128,128,128,129,129,129,129,129,129,129,129,130,130,130,130,130,130,130,130,130,131,131,131,131,131,131,132,132,132,132,132,132,132,132,133,133,133,133,134,133,133,134,134,134,134,134,134,134,134,135,135,135,135
};

/* Candidate & Tree Batching related */
enum batch_modes {
	CANDIDATE,
	SPECULATIVE,
};
static unsigned long batch_mode = 0;
static unsigned long candidate_batch_size = 4;
static unsigned long tree_batch_size = 4;
static unsigned long spec_batch_level = 2; // number of tree level
static unsigned long spec_batch_size = (1<<2) - 1;
LIST_HEAD(stable_node_erase_pending_list);
static inline bool check_batch_mode(int mode)
{
	return test_bit(mode, &batch_mode);
}
static void remove_node_from_stable_tree(struct ksm_stable_node *stable_node);
static __always_inline bool is_stable_node_chain(struct ksm_stable_node *chain);
static inline void free_stable_node_chain(struct ksm_stable_node *chain);
static void flush_stable_node_erase_pending_list(void)
{
	struct ksm_stable_node *pos_stable_node, *tmp;

	if (list_empty(&stable_node_erase_pending_list))
		return;

	list_for_each_entry_safe(pos_stable_node, tmp, &stable_node_erase_pending_list, pending_list) {
		list_del(&pos_stable_node->pending_list);
		pos_stable_node->pended = false;
		if (is_stable_node_chain(pos_stable_node))
		    	free_stable_node_chain(pos_stable_node);
		else
			remove_node_from_stable_tree(pos_stable_node);
	}
}
static inline bool need_pending_in_stable_tree(void)
{
	return batch_mode != 0;
}

#define MAX_DELTA PAGE_SIZE / 8 * 10

/* The number of nodes in the stable tree */
static unsigned long ksm_pages_shared;

/* The number of page slots additionally sharing those nodes */
static unsigned long ksm_pages_sharing;

/* The number of nodes in the unstable tree */
static unsigned long ksm_pages_unshared;

/* The number of rmap_items in use: to calculate pages_volatile */
static unsigned long ksm_rmap_items;

/* The number of stable_node chains */
static unsigned long ksm_stable_node_chains;

/* The number of stable_node dups linked to the stable_node chains */
static unsigned long ksm_stable_node_dups;

/* Delay in pruning stale stable_node_dups in the stable_node_chains */
static unsigned int ksm_stable_node_chains_prune_millisecs = 2000;

/* Maximum number of page slots sharing a stable node */
static int ksm_max_page_sharing = 256;

/* Number of pages ksmd should scan in one batch */
static unsigned int ksm_thread_pages_to_scan = 100;

/* Milliseconds ksmd should sleep between batches */
static unsigned int ksm_thread_sleep_millisecs = 20;

/* Whether to merge empty (zeroed) pages with actual zero pages */
static bool ksm_use_zero_pages __read_mostly;

#ifdef CONFIG_NUMA
/* Zeroed when merging across nodes is not allowed */
static unsigned int ksm_merge_across_nodes = 1;
static int ksm_nr_node_ids = 1;
#else
#define ksm_merge_across_nodes	1U
#define ksm_nr_node_ids		1
#endif

#define KSM_RUN_STOP	0
#define KSM_RUN_MERGE	1
#define KSM_RUN_UNMERGE	2
#define KSM_RUN_OFFLINE	4

static unsigned long ksm_run = KSM_RUN_STOP;

static DEFINE_MUTEX(ksm_thread_mutex);

static void dsa_spin_polling(struct dsa_completion_record *comp)
{
    for (;;) {
        if (comp->status != 0)
            break;
    }
}

static void dsa_spin_polling_with_sched(struct dsa_completion_record *comp,
		int batch_size, bool checksum)
{
	bool first = true;
    	for (;;) {
        	if (comp->status != 0)
           		break;


		if (first) {
			might_sleep();

			set_current_state(TASK_INTERRUPTIBLE);
			if (checksum) {
				if (dsa_sched_us_min_checksum[batch_size] < dsa_sched_us_start)
					usleep_range(dsa_sched_us_start, dsa_sched_us_start + 1);
				else 
					usleep_range(dsa_sched_us_min_checksum[batch_size], dsa_sched_us_max_checksum[batch_size]);
			} else {
				if (dsa_sched_us_min[batch_size] < dsa_sched_us_start)
					usleep_range(dsa_sched_us_start, dsa_sched_us_start + 1);
				else
					usleep_range(dsa_sched_us_min[batch_size], dsa_sched_us_max[batch_size]);
			}
			first = false;
			set_current_state(TASK_RUNNING);
		}
		//usleep_range(dsa_sched_us_start, dsa_sched_us_end);
    	}
}

static void dsa_spin_polling_with_wait(struct dsa_completion_record *comp)
{
	for (;;) {
		if (comp->status != 0)
			break;
		ndelay(dsa_polling_wait_ns);
	}
}

#define KSM_UMWAIT_DELAY 100000
static void dsa_mwait(struct dsa_completion_record *comp) 
{
	uint64_t delay;
	for (;;) {
		if (comp->status != 0)
			break;

		ksm_umonitor(comp);
		delay = get_cycles() + KSM_UMWAIT_DELAY;
		if (dsa_completion_mode == DSA_COMPL_MWAIT_WITH_SCHED
		    	&& dsa_sched_us_end > 0) {
			set_current_state(TASK_INTERRUPTIBLE);
			usleep_range(dsa_sched_us_start, dsa_sched_us_end);
			set_current_state(TASK_RUNNING);
		}
		ksm_umwait(1, delay);
	}
}

static void wait_dsa_desc_submission(struct dsa_completion_record *comp, int batch_size, bool checksum)
{
	switch (dsa_completion_mode) {
	case DSA_COMPL_SPIN_POLLING:
		dsa_spin_polling(comp);
		break;
	case DSA_COMPL_SPIN_POLLING_WITH_SCHED:
		dsa_spin_polling_with_sched(comp, batch_size, checksum);
		break;
	case DSA_COMPL_SPIN_POLLING_WITH_WAIT:
		dsa_spin_polling_with_wait(comp);
		break;
	case DSA_COMPL_MWAIT:
	case DSA_COMPL_MWAIT_WITH_SCHED:
	default:
		dsa_mwait(comp);
	}
}

static void dsa_desc_submit_sync(struct dsa_hw_desc *desc, 
		struct dsa_completion_record *comp,
		int batch_size, bool checksum)
{
	desc->int_handle = 0;

	wmb();
	iosubmit_cmds512(ksm_dsa_info.wq_portal, desc, 1);

	wait_dsa_desc_submission(comp, batch_size, checksum);
}

static void dsa_desc_submit_async(struct dsa_hw_desc *desc, 
		struct dsa_completion_record *comp, struct idxd_irq_entry *ie)
{
	desc->int_handle = ie->int_handle;
	//init_completion(&ie->done);
	ie->ksm_wait_queue = &ksm_iter_wait;
	ie->done = 0;

	wmb();
	iosubmit_cmds512(ksm_dsa_info.wq_portal, desc, 1);

	wait_event_interruptible(ksm_iter_wait, ie->done);
	//if (!wait_for_completion_timeout(&ie->done, usecs_to_jiffies(50)))
	//	pr_err("DSA irq timeout\n");
	for (;;) {
		if (comp->status != 0)
			break;
	}

}

/* Checksum of an empty (zeroed) page */
static unsigned int zero_checksum __read_mostly;

static u32 calc_checksum(struct page *page)
{
	u32 checksum;
	void *addr;

	ksm_debug_start(CRC);

	addr = kmap_atomic(page);
	checksum = xxhash(addr, PAGE_SIZE, 0);
	kunmap_atomic(addr);

	ksm_debug_end(CRC);

	return checksum;
}

static u32 dsa_calc_checksum(struct page *page)
{
	struct idxd_irq_entry *ie = &ksm_dsa_info.wq->ie;
	struct dsa_hw_desc *desc = &ksm_dsa_info.desc[0];
	struct dsa_completion_record *comp = &ksm_dsa_info.comp[0];
	dma_addr_t src_addr = dma_map_page(ksm_dsa_info.dev, page, 0, PAGE_SIZE, DMA_TO_DEVICE);
	u32 checksum;

	if (batch_mode)
		ksm_debug_start(CRC_BATCH);
	else
		ksm_debug_start(CRC);

	comp->status = 0;
	desc->opcode = DSA_OPCODE_CRCGEN;
	desc->flags = 0;
	if (dsa_completion_mode == DSA_COMPL_IRQ)
		desc->flags = IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCI;
	else
		desc->flags = IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CRAV;
	desc->src_addr = src_addr;
	desc->dst_addr = 0;
	desc->completion_addr = ksm_dsa_info.comp_dma[0];
	desc->delta_addr = 0;
	desc->max_delta_size = 0;

	if (dsa_completion_mode == DSA_COMPL_IRQ)
		dsa_desc_submit_async(desc, comp, ie);
	else
		dsa_desc_submit_sync(desc, comp, 1, true);

	if (comp->status != 1) {
		pr_err("DSA CRCGEN error, status: %x\n", comp->status);
		checksum = calc_checksum(page);
		goto out;
	}

	checksum = comp->crc_val;
out:
	dma_unmap_page(ksm_dsa_info.dev, src_addr, PAGE_SIZE, DMA_TO_DEVICE);

	if (batch_mode) {
		ksm_debug_end(CRC_BATCH);
		ksm_debug_count(CRC, 1);
	} else {
		ksm_debug_end(CRC);
	}

	return checksum;
}

/*
 * need skip이 아닌 개수가 항상 2 이상임을 보장해야함.
 */
static int dsa_calc_checksum_batch(struct page **page, int num_page, bool *need_skip, unsigned int *result)
{
	struct idxd_irq_entry *ie = &ksm_dsa_info.wq->ie;
	struct dsa_hw_desc *desc = ksm_dsa_info.desc;
	struct dsa_completion_record *comp = ksm_dsa_info.comp;
	dma_addr_t *src_addr = dsa_calc_checksum_batch_src_addr;
	struct dsa_hw_desc *batch_desc = ksm_dsa_info.batch_desc;
	struct dsa_completion_record *batch_comp = ksm_dsa_info.batch_comp;
	int i, l, failed = 0;

	ksm_debug_start(CRC_BATCH);

	l = 0;
	for (i = 0; i < num_page; i++) {
		if (need_skip[i])
			continue;
		src_addr[i] = dma_map_page(ksm_dsa_info.dev, page[i], 0, PAGE_SIZE, DMA_TO_DEVICE);
		if (dma_mapping_error(ksm_dsa_info.dev, src_addr[i])) {
			pr_err("dma_map_page failed\n");
			failed = 1;
			goto out;
		}

		comp[l].status = 0;
		desc[l].opcode = DSA_OPCODE_CRCGEN;
		desc[l].flags = IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CRAV;
		desc[l].src_addr = src_addr[i];
		desc[l].dst_addr = 0;
		desc[l].completion_addr = ksm_dsa_info.comp_dma[l];
		desc[l].int_handle = 0;
		desc[l].delta_addr = 0;
		desc[l].max_delta_size = 0;
		l++;
	}


	batch_comp->status = 0;
	batch_desc->desc_count = l;
	batch_desc->desc_list_addr = ksm_dsa_info.desc_buf_dma;
	batch_desc->completion_addr = ksm_dsa_info.batch_comp_dma;

	if (dsa_completion_mode == DSA_COMPL_IRQ)
		dsa_desc_submit_async(batch_desc, batch_comp, ie);
	else
		dsa_desc_submit_sync(batch_desc, batch_comp, l, true);

	//if (batch_comp->status == 0 && dsa_completion_mode == DSA_COMPL_IRQ)
	//	wait_for_completion_timeout(&ie->done, msecs_to_jiffies(1));

	if (batch_comp->status != 1) {
		pr_err("DSA Batched crc gen failed, status: %x, l: %d\n", batch_comp->status, l);
		failed = 1;
		goto out;
	}

	l = 0;
	for (i = 0; i < num_page; i++) {
		if (need_skip[i])
			continue;
		result[i] = comp[l].crc_val;
		l++;
	}

out:
	for (i = 0; i < num_page; i++) {
		if (need_skip[i])
			continue;
		dma_unmap_page(ksm_dsa_info.dev, src_addr[i], PAGE_SIZE, DMA_TO_DEVICE);
	}

	ksm_debug_end(CRC_BATCH);
	ksm_debug_count(CRC, batch_desc->desc_count);

	return failed;
}

static int hybrid_cpu_memcmp_pages(struct page *page1, struct page *page2)
{
	char *addr1, *addr2;
	int ret;

	ksm_debug_start(HYBRID_CPU_COMPARE);

	addr1 = kmap_atomic(page1);
	addr2 = kmap_atomic(page2);

	if (!ksm_debug_enabled())
		ret = memcmp(addr1, addr2, 64);
	else
		ret = cpu_memcmp(addr1, addr2, 64);
	kunmap_atomic(addr2);
	kunmap_atomic(addr1);

	ksm_debug_end(HYBRID_CPU_COMPARE);

	return ret;
}

static int dsa_memcmp_pages(struct page *page1, struct page *page2)
{
	struct idxd_irq_entry *ie = &ksm_dsa_info.wq->ie;
	struct dsa_hw_desc *desc = &ksm_dsa_info.desc[0];
	struct dsa_completion_record *comp = &ksm_dsa_info.comp[0];
	dma_addr_t src_addr;
	dma_addr_t dst_addr;
	int ret;

	if (enable_dsa_hybrid && !batch_mode) {
		ret = hybrid_cpu_memcmp_pages(page1, page2);
		if (ret != 0) {
			return ret;
		}
	}

	if (batch_mode)
		ksm_debug_start(COMPARE_BATCH);
	else
		ksm_debug_start(COMPARE);

	src_addr = dma_map_page(ksm_dsa_info.dev, page1, 0, PAGE_SIZE, DMA_TO_DEVICE);
	dst_addr = dma_map_page(ksm_dsa_info.dev, page2, 0, PAGE_SIZE, DMA_TO_DEVICE);
	comp->status = 0;
	desc->opcode = DSA_OPCODE_COMPARE;
	desc->flags = 0;
	if (dsa_completion_mode == DSA_COMPL_IRQ)
		desc->flags = IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCI;
	else
		desc->flags = IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CRAV;
	desc->src_addr = src_addr;
	desc->dst_addr = dst_addr;
	desc->completion_addr = ksm_dsa_info.comp_dma[0];
	desc->delta_addr = 0;
	desc->max_delta_size = 0;

	if (dsa_completion_mode == DSA_COMPL_IRQ)
		dsa_desc_submit_async(desc, comp, ie);
	else
		dsa_desc_submit_sync(desc, comp, 1, false);
	
	if (comp->status != 1) {
		pr_err("DSA compare failed!, status: %x\n", comp->status);
		ret = memcmp_pages(page1, page2);
		goto out;
	}

	if (comp->result) {
		char *addr1, *addr2;
		int idx = comp->bytes_completed;
		addr1 = kmap_atomic(page1);
		addr2 = kmap_atomic(page2);
		ret = addr1[idx] - addr2[idx];
		kunmap_atomic(addr2);
		kunmap_atomic(addr1);
	} else 
		ret = 0;

out:
	dma_unmap_page(ksm_dsa_info.dev, src_addr, PAGE_SIZE, DMA_TO_DEVICE);
	dma_unmap_page(ksm_dsa_info.dev, dst_addr, PAGE_SIZE, DMA_TO_DEVICE);

	if (batch_mode) {
		ksm_debug_end(COMPARE_BATCH);
		ksm_debug_count(COMPARE, 1);
	} else {
		ksm_debug_end(COMPARE);
	}

	return ret;
}

/**
 * This function performs a comparison with a separate set of num_page2 
 * pages for each of the num_page1 pages of page1 using DSA Batch op. 
 * (page1[i] is compared with the pages of page2 corresponding to the 
 * indices from i * num_page2 to (i+1) * num_page2 - 1)
 *
 * @page1, page2: array of pages for memcmp (NOTE: not all pages in page2 is valid).
 * @num_page1: size of page1 array
 * @num_page2: maximum number of pages to compare for each page of page1 array 
 *             => size of page2 array is num_page1 * num_page2
 * @valid: if valid[k] is true, then page2[k] is valid 
 * @ret: array for storing comparison results.
 *       size of ret array is num_page1 * num_page2
 * 
 * output: if batch op is failed -> 1,
 *         otherwise -> 0
 *
 * valid count should be greater than 1.
 */
static int dsa_memcmp_pages_batch(struct page **page1, struct page **page2,
				int num_page1, int num_page2, bool *valid, int *ret)
{
	struct idxd_irq_entry *ie = &ksm_dsa_info.wq->ie;
	struct dsa_hw_desc *desc = ksm_dsa_info.desc;
	struct dsa_completion_record *comp = ksm_dsa_info.comp;
	dma_addr_t *src_addr = dsa_memcmp_pages_batch_src_addr;
	dma_addr_t *dst_addr = dsa_memcmp_pages_batch_dst_addr;
	struct dsa_hw_desc *batch_desc = ksm_dsa_info.batch_desc;
	struct dsa_completion_record *batch_comp = ksm_dsa_info.batch_comp;
	int i, j, k, l, failed = 0;

	ksm_debug_start(COMPARE_BATCH);

	l = 0; // index for completion, descriptor array
	for (i = 0; i < num_page1; i++) {
		for (j = 0; j < num_page2; j++) {
			k = i * num_page2 + j;
			if (!valid[k])
				continue;
			src_addr[k] = dma_map_page(ksm_dsa_info.dev, page1[i], 0, PAGE_SIZE, DMA_TO_DEVICE);
			if (unlikely(dma_mapping_error(ksm_dsa_info.dev, src_addr[k]))) {
				BUG_ON(1);
			}

			dst_addr[k] = dma_map_page(ksm_dsa_info.dev, page2[k], 0, PAGE_SIZE, DMA_TO_DEVICE);
			if (unlikely(dma_mapping_error(ksm_dsa_info.dev, dst_addr[k]))) {
				BUG_ON(1);
			}

			comp[l].status = 0;
			desc[l].opcode = DSA_OPCODE_COMPARE;
			desc[l].flags = IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CRAV;
			desc[l].src_addr = src_addr[k];
			desc[l].dst_addr = dst_addr[k];
			desc[l].completion_addr = ksm_dsa_info.comp_dma[l];
			desc[l].delta_addr = 0;
			desc[l].max_delta_size = 0;
			desc[l].int_handle = 0;
			l++;
		}
	}

	
	batch_comp->status = 0;
	batch_desc->desc_count = l;
	batch_desc->desc_list_addr = ksm_dsa_info.desc_buf_dma;
	batch_desc->completion_addr = ksm_dsa_info.batch_comp_dma;

	if (dsa_completion_mode == DSA_COMPL_IRQ)
		dsa_desc_submit_async(batch_desc, batch_comp, ie);
	else
		dsa_desc_submit_sync(batch_desc, batch_comp, l, false);

	if (batch_comp->status != 1) {
		pr_err("DSA Batched compare failed, status: %x, l: %d\n", batch_comp->status, l);
		for (i = 0; i < l; i++)
			pr_err("Desc %d status: %x\n", i, comp[i].status);
		failed = 1;
		goto out;
	}
	
	l = 0;
	for (i = 0; i < num_page1; i++) {
		for (j = 0; j < num_page2; j++) {
			k = i * num_page2 + j;
			if (!valid[k])
				continue;
			if (comp[l].result) {
				char *addr1, *addr2;
				int page_idx = comp[l].bytes_completed;
				addr1 = kmap_atomic(page1[i]);
				addr2 = kmap_atomic(page2[k]);
				ret[k] = addr1[page_idx] - addr2[page_idx];
				kunmap_atomic(addr2);
				kunmap_atomic(addr1);
			} else 
				ret[k] = 0;

			l++;
		}
	}
	
out:
	for (i = 0; i < num_page1; i++) {
		for (j = 0; j < num_page2; j++) {
			k = i * num_page2 + j;
			if (!valid[k])
				continue;
			dma_unmap_page(ksm_dsa_info.dev, src_addr[k], PAGE_SIZE, DMA_TO_DEVICE);
			dma_unmap_page(ksm_dsa_info.dev, dst_addr[k], PAGE_SIZE, DMA_TO_DEVICE);
		}
	}

	ksm_debug_end(COMPARE_BATCH);
	ksm_debug_count(COMPARE, batch_desc->desc_count);

	return failed;
}

static int dsa_pages_mergeable(struct page *page, struct page *kpage, 
					struct ksm_rmap_item *rmap_item)
{
	int ret;
	if (use_dsa)
		return !dsa_memcmp_pages(page, kpage);
	else
		return !cpu_memcmp_pages(page, kpage);
}


static void ksm_dsa_init(void)
{
	struct file *filp;
	int i;
	filp = filp_open(dsa_cdev_name, O_RDWR, 0);
	if (IS_ERR(filp)) {
		pr_err("Failed to open DSA device\n");
		return;
	}

	if (filp->f_op->unlocked_ioctl)
		ksm_dsa_info.wq = (struct idxd_wq*) filp->f_op->unlocked_ioctl(filp, 0, 0);
	else {
		pr_err("No ioctl for DSA\n");
		return;
	}
	filp_close(filp, NULL);

	if (!ksm_dsa_info.wq) {
		pr_err("Failed to get wq\n");
		return;
	}

	ksm_dsa_info.idxd = ksm_dsa_info.wq->idxd;
	ksm_dsa_info.dev = &ksm_dsa_info.idxd->pdev->dev;
	ksm_dsa_info.wq_portal = idxd_wq_portal_addr(ksm_dsa_info.wq);
	ksm_dsa_info.desc = kzalloc(DSA_BUF_SIZE * sizeof(struct dsa_hw_desc), GFP_KERNEL);
	ksm_dsa_info.comp = kzalloc(DSA_BUF_SIZE * sizeof(struct dsa_completion_record), GFP_KERNEL);
	ksm_dsa_info.comp_dma = kmalloc(DSA_BUF_SIZE * sizeof(dma_addr_t), GFP_KERNEL);
	for (i = 0; i < DSA_BUF_SIZE; i++) {
		ksm_dsa_info.desc[i].priv = 1;
		if (device_pasid_enabled(ksm_dsa_info.idxd))
			ksm_dsa_info.desc[i].pasid = ksm_dsa_info.idxd->pasid;
		else
			ksm_dsa_info.desc[i].pasid = 0;
		ksm_dsa_info.desc[i].xfer_size = PAGE_SIZE;

		ksm_dsa_info.comp_dma[i] = dma_map_page(ksm_dsa_info.dev, virt_to_page(&ksm_dsa_info.comp[i]),
							(size_t)(&ksm_dsa_info.comp[i]) % PAGE_SIZE, 
							sizeof(struct dsa_completion_record),
							DMA_BIDIRECTIONAL);
	}

	// batch desc init
	ksm_dsa_info.batch_desc = kzalloc(sizeof(struct dsa_hw_desc), GFP_KERNEL);
	ksm_dsa_info.batch_comp = kzalloc(sizeof(struct dsa_completion_record), GFP_KERNEL);
	ksm_dsa_info.batch_desc->priv = 1;	
	if (device_pasid_enabled(ksm_dsa_info.idxd))
		ksm_dsa_info.batch_desc->pasid = ksm_dsa_info.idxd->pasid;
	else
		ksm_dsa_info.batch_desc->pasid = 0;
	ksm_dsa_info.batch_desc->opcode = DSA_OPCODE_BATCH;
	if (dsa_completion_mode == DSA_COMPL_IRQ)
		ksm_dsa_info.batch_desc->flags = IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CRAV | IDXD_OP_FLAG_RCI;	
	else
		ksm_dsa_info.batch_desc->flags = IDXD_OP_FLAG_RCR | IDXD_OP_FLAG_CRAV;	
	ksm_dsa_info.batch_comp_dma = dma_map_page(ksm_dsa_info.dev, virt_to_page(ksm_dsa_info.batch_comp),
						(size_t)(ksm_dsa_info.batch_comp) % PAGE_SIZE, 
						sizeof(struct dsa_completion_record),
						DMA_BIDIRECTIONAL);
	ksm_dsa_info.desc_buf_dma = dma_map_page(ksm_dsa_info.dev, virt_to_page(ksm_dsa_info.desc),
						(size_t)ksm_dsa_info.desc % PAGE_SIZE,
						DSA_BUF_SIZE * sizeof(struct dsa_hw_desc),
						DMA_BIDIRECTIONAL);
	if (dma_mapping_error(ksm_dsa_info.dev, ksm_dsa_info.batch_comp_dma))
		pr_err("batch_comp_dma failed\n");
	if (dma_mapping_error(ksm_dsa_info.dev, ksm_dsa_info.desc_buf_dma))
		pr_err("desc_buf_dma failed\n");

	if (use_dsa_for_hash)
		zero_checksum = dsa_calc_checksum(ZERO_PAGE(0));
	use_dsa = 1;
}

static void ksm_dsa_exit(void)
{
	int i;

	zero_checksum = calc_checksum(ZERO_PAGE(0));
	use_dsa = 0;

	for (i = 0; i < DSA_BUF_SIZE; i++) {
		dma_unmap_page(ksm_dsa_info.dev, ksm_dsa_info.comp_dma[i], sizeof(struct dsa_completion_record),
				DMA_BIDIRECTIONAL);
	}

	dma_unmap_page(ksm_dsa_info.dev, ksm_dsa_info.batch_comp_dma, sizeof(struct dsa_completion_record),
				DMA_BIDIRECTIONAL);
	dma_unmap_page(ksm_dsa_info.dev, ksm_dsa_info.desc_buf_dma, DSA_BUF_SIZE * sizeof(struct dsa_hw_desc),
				DMA_BIDIRECTIONAL);

	kfree(ksm_dsa_info.comp_dma);
	kfree(ksm_dsa_info.desc);
	kfree(ksm_dsa_info.comp);
	kfree(ksm_dsa_info.batch_desc);
	kfree(ksm_dsa_info.batch_comp);
}

static struct ksm_stable_node *stable_node_dup_any(struct ksm_stable_node *stable_node);
enum get_ksm_page_flags {
	GET_KSM_PAGE_NOLOCK,
	GET_KSM_PAGE_LOCK,
	GET_KSM_PAGE_TRYLOCK
};
static struct page *get_ksm_page(struct ksm_stable_node *stable_node,
				 enum get_ksm_page_flags flags);
static struct page *get_mergeable_page(struct ksm_rmap_item *rmap_item);

#define SEQNR_MASK	0x0ff	/* low bits of unstable tree seqnr */
#define UNSTABLE_FLAG	0x100	/* is a node of the unstable tree */
#define STABLE_FLAG	0x200	/* is listed from the stable tree */

/* Recently migrated nodes of stable tree, pending proper placement */
static LIST_HEAD(migrate_nodes);
#define STABLE_NODE_DUP_HEAD ((struct list_head *)&migrate_nodes.prev)

#define MM_SLOTS_HASH_BITS 10
static DEFINE_HASHTABLE(mm_slots_hash, MM_SLOTS_HASH_BITS);

static struct ksm_mm_slot ksm_mm_head = {
	.slot.mm_node = LIST_HEAD_INIT(ksm_mm_head.slot.mm_node),
};
static struct ksm_scan ksm_scan = {
	.mm_slot = &ksm_mm_head,
};

static struct kmem_cache *rmap_item_cache;
static struct kmem_cache *stable_node_cache;
static struct kmem_cache *mm_slot_cache;

static void wait_while_offlining(void);

#define KSM_KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
		sizeof(struct __struct), __alignof__(struct __struct),\
		(__flags), NULL)

static int __init ksm_slab_init(void)
{
	rmap_item_cache = KSM_KMEM_CACHE(ksm_rmap_item, 0);
	if (!rmap_item_cache)
		goto out;

	stable_node_cache = KSM_KMEM_CACHE(ksm_stable_node, 0);
	if (!stable_node_cache)
		goto out_free1;

	mm_slot_cache = KSM_KMEM_CACHE(ksm_mm_slot, 0);
	if (!mm_slot_cache)
		goto out_free2;

	return 0;

out_free2:
	kmem_cache_destroy(stable_node_cache);
out_free1:
	kmem_cache_destroy(rmap_item_cache);
out:
	return -ENOMEM;
}

static void __init ksm_slab_free(void)
{
	kmem_cache_destroy(mm_slot_cache);
	kmem_cache_destroy(stable_node_cache);
	kmem_cache_destroy(rmap_item_cache);
	mm_slot_cache = NULL;
}

static __always_inline bool is_stable_node_chain(struct ksm_stable_node *chain)
{
	return chain->rmap_hlist_len == STABLE_NODE_CHAIN;
}

static __always_inline bool is_stable_node_dup(struct ksm_stable_node *dup)
{
	return dup->head == STABLE_NODE_DUP_HEAD;
}

static inline void stable_node_chain_add_dup(struct ksm_stable_node *dup,
					     struct ksm_stable_node *chain)
{
	VM_BUG_ON(is_stable_node_dup(dup));
	dup->head = STABLE_NODE_DUP_HEAD;
	VM_BUG_ON(!is_stable_node_chain(chain));
	hlist_add_head(&dup->hlist_dup, &chain->hlist);
	ksm_stable_node_dups++;
}

static inline void __stable_node_dup_del(struct ksm_stable_node *dup)
{
	VM_BUG_ON(!is_stable_node_dup(dup));
	hlist_del(&dup->hlist_dup);
	ksm_stable_node_dups--;
}

static inline void stable_node_dup_del(struct ksm_stable_node *dup)
{
	VM_BUG_ON(is_stable_node_chain(dup));
	if (is_stable_node_dup(dup)) {
		__stable_node_dup_del(dup);
	} else {
		rb_erase(&dup->node, root_stable_tree + NUMA(dup->nid));
	}
#ifdef CONFIG_DEBUG_VM
	dup->head = NULL;
#endif
}

static inline struct ksm_rmap_item *alloc_rmap_item(void)
{
	struct ksm_rmap_item *rmap_item;

	rmap_item = kmem_cache_zalloc(rmap_item_cache, GFP_KERNEL |
						__GFP_NORETRY | __GFP_NOWARN);
	if (rmap_item)
		ksm_rmap_items++;
	return rmap_item;
}

static inline void free_rmap_item(struct ksm_rmap_item *rmap_item)
{
	ksm_rmap_items--;
	rmap_item->mm->ksm_rmap_items--;
	rmap_item->mm = NULL;	/* debug safety */
	kmem_cache_free(rmap_item_cache, rmap_item);
}

static inline void set_page_stable_node(struct page *page,
					struct ksm_stable_node *stable_node);

static struct ksm_stable_node *alloc_stable_node(void)
{
	struct ksm_stable_node *stable_node;

	/*
	 * The allocation can take too long with GFP_KERNEL when memory is under
	 * pressure, which may lead to hung task warnings.  Adding __GFP_HIGH
	 * grants access to memory reserves, helping to avoid this problem.
	 */
	stable_node = kmem_cache_alloc(stable_node_cache, GFP_KERNEL | __GFP_HIGH);

	stable_node->pended = false;

	return stable_node;
}

static inline void free_stable_node(struct ksm_stable_node *stable_node)
{
	VM_BUG_ON(stable_node->rmap_hlist_len &&
		  !is_stable_node_chain(stable_node));
	kmem_cache_free(stable_node_cache, stable_node);
}

/*
 * ksmd, and unmerge_and_remove_all_rmap_items(), must not touch an mm's
 * page tables after it has passed through ksm_exit() - which, if necessary,
 * takes mmap_lock briefly to serialize against them.  ksm_exit() does not set
 * a special flag: they can just back out as soon as mm_users goes to zero.
 * ksm_test_exit() is used throughout to make this test for exit: in some
 * places for correctness, in some places just to avoid unnecessary work.
 */
static inline bool ksm_test_exit(struct mm_struct *mm)
{
	return atomic_read(&mm->mm_users) == 0;
}

static int break_ksm_pmd_entry(pmd_t *pmd, unsigned long addr, unsigned long next,
			struct mm_walk *walk)
{
	struct page *page = NULL;
	spinlock_t *ptl;
	pte_t *pte;
	int ret;

	if (pmd_leaf(*pmd) || !pmd_present(*pmd))
		return 0;

	pte = pte_offset_map_lock(walk->mm, pmd, addr, &ptl);
	if (pte_present(*pte)) {
		page = vm_normal_page(walk->vma, addr, *pte);
	} else if (!pte_none(*pte)) {
		swp_entry_t entry = pte_to_swp_entry(*pte);

		/*
		 * As KSM pages remain KSM pages until freed, no need to wait
		 * here for migration to end.
		 */
		if (is_migration_entry(entry))
			page = pfn_swap_entry_to_page(entry);
	}
	ret = page && PageKsm(page);
	pte_unmap_unlock(pte, ptl);

	return ret;
}

static const struct mm_walk_ops break_ksm_ops = {
	.pmd_entry = break_ksm_pmd_entry,
};

/*
 * We use break_ksm to break COW on a ksm page by triggering unsharing,
 * such that the ksm page will get replaced by an exclusive anonymous page.
 *
 * We take great care only to touch a ksm page, in a VM_MERGEABLE vma,
 * in case the application has unmapped and remapped mm,addr meanwhile.
 * Could a ksm page appear anywhere else?  Actually yes, in a VM_PFNMAP
 * mmap of /dev/mem, where we would not want to touch it.
 *
 * FAULT_FLAG_REMOTE/FOLL_REMOTE are because we do this outside the context
 * of the process that owns 'vma'.  We also do not want to enforce
 * protection keys here anyway.
 */
static int break_ksm(struct vm_area_struct *vma, unsigned long addr)
{
	vm_fault_t ret = 0;

	do {
		int ksm_page;

		cond_resched();
		ksm_page = walk_page_range_vma(vma, addr, addr + 1,
					       &break_ksm_ops, NULL);
		if (WARN_ON_ONCE(ksm_page < 0))
			return ksm_page;
		if (!ksm_page)
			return 0;
		ret = handle_mm_fault(vma, addr,
				      FAULT_FLAG_UNSHARE | FAULT_FLAG_REMOTE,
				      NULL);
	} while (!(ret & (VM_FAULT_SIGBUS | VM_FAULT_SIGSEGV | VM_FAULT_OOM)));
	/*
	 * We must loop until we no longer find a KSM page because
	 * handle_mm_fault() may back out if there's any difficulty e.g. if
	 * pte accessed bit gets updated concurrently.
	 *
	 * VM_FAULT_SIGBUS could occur if we race with truncation of the
	 * backing file, which also invalidates anonymous pages: that's
	 * okay, that truncation will have unmapped the PageKsm for us.
	 *
	 * VM_FAULT_OOM: at the time of writing (late July 2009), setting
	 * aside mem_cgroup limits, VM_FAULT_OOM would only be set if the
	 * current task has TIF_MEMDIE set, and will be OOM killed on return
	 * to user; and ksmd, having no mm, would never be chosen for that.
	 *
	 * But if the mm is in a limited mem_cgroup, then the fault may fail
	 * with VM_FAULT_OOM even if the current task is not TIF_MEMDIE; and
	 * even ksmd can fail in this way - though it's usually breaking ksm
	 * just to undo a merge it made a moment before, so unlikely to oom.
	 *
	 * That's a pity: we might therefore have more kernel pages allocated
	 * than we're counting as nodes in the stable tree; but ksm_do_scan
	 * will retry to break_cow on each pass, so should recover the page
	 * in due course.  The important thing is to not let VM_MERGEABLE
	 * be cleared while any such pages might remain in the area.
	 */
	return (ret & VM_FAULT_OOM) ? -ENOMEM : 0;
}

static struct vm_area_struct *find_mergeable_vma(struct mm_struct *mm,
		unsigned long addr)
{
	struct vm_area_struct *vma;
	if (ksm_test_exit(mm))
		return NULL;
	vma = vma_lookup(mm, addr);
	if (!vma || !(vma->vm_flags & VM_MERGEABLE) || !vma->anon_vma)
		return NULL;
	return vma;
}

static void break_cow(struct ksm_rmap_item *rmap_item)
{
	struct mm_struct *mm = rmap_item->mm;
	unsigned long addr = rmap_item->address;
	struct vm_area_struct *vma;

	/*
	 * It is not an accident that whenever we want to break COW
	 * to undo, we also need to drop a reference to the anon_vma.
	 */
	put_anon_vma(rmap_item->anon_vma);

	mmap_read_lock(mm);
	vma = find_mergeable_vma(mm, addr);
	if (vma)
		break_ksm(vma, addr);
	mmap_read_unlock(mm);
}

static struct page *get_mergeable_page(struct ksm_rmap_item *rmap_item)
{
	struct mm_struct *mm = rmap_item->mm;
	unsigned long addr = rmap_item->address;
	struct vm_area_struct *vma;
	struct page *page;

	mmap_read_lock(mm);
	vma = find_mergeable_vma(mm, addr);
	if (!vma) {
		goto out;
	}

	page = follow_page(vma, addr, FOLL_GET);
	if (IS_ERR_OR_NULL(page)) {
		goto out;
	}
	if (is_zone_device_page(page)) {
		goto out_putpage;
	}
	if (PageAnon(page)) {
		flush_anon_page(vma, page, addr);
		flush_dcache_page(page);
	} else {
out_putpage:
		put_page(page);
out:
		page = NULL;
	}
	mmap_read_unlock(mm);
	return page;
}

/*
 * This helper is used for getting right index into array of tree roots.
 * When merge_across_nodes knob is set to 1, there are only two rb-trees for
 * stable and unstable pages from all nodes with roots in index 0. Otherwise,
 * every node has its own stable and unstable tree.
 */
static inline int get_kpfn_nid(unsigned long kpfn)
{
	return ksm_merge_across_nodes ? 0 : NUMA(pfn_to_nid(kpfn));
}

static struct ksm_stable_node *alloc_stable_node_chain(struct ksm_stable_node *dup)
{
	struct ksm_stable_node *chain = alloc_stable_node();
	VM_BUG_ON(is_stable_node_chain(dup));
	if (likely(chain)) {
		INIT_HLIST_HEAD(&chain->hlist);
		chain->chain_prune_time = jiffies;
		chain->rmap_hlist_len = STABLE_NODE_CHAIN;
#if defined (CONFIG_DEBUG_VM) && defined(CONFIG_NUMA)
		chain->nid = NUMA_NO_NODE; /* debug */
#endif
		ksm_stable_node_chains++;

		/*
		 * Put the stable node chain in the first dimension of
		 * the stable tree and at the same time remove the old
		 * stable node.
		 */
		rb_replace_node(&dup->node, &chain->node, root_stable_tree);

		/*
		 * Move the old stable node to the second dimension
		 * queued in the hlist_dup. The invariant is that all
		 * dup stable_nodes in the chain->hlist point to pages
		 * that are write protected and have the exact same
		 * content.
		 */
		stable_node_chain_add_dup(dup, chain);
	}
	return chain;
}

static inline void free_stable_node_chain(struct ksm_stable_node *chain)
{
	rb_erase(&chain->node, root_stable_tree);
	free_stable_node(chain);
	ksm_stable_node_chains--;
}

static void remove_node_from_stable_tree(struct ksm_stable_node *stable_node)
{
	struct ksm_rmap_item *rmap_item;

	/* check it's not STABLE_NODE_CHAIN or negative */
	BUG_ON(stable_node->rmap_hlist_len < 0);

	if (!stable_node) {
		pr_err("stable_node is NULL!!\n");
	}

	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		if (rmap_item->hlist.next)
			ksm_pages_sharing--;
		else
			ksm_pages_shared--;

		rmap_item->mm->ksm_merging_pages--;

		cond_resched();
		VM_BUG_ON(stable_node->rmap_hlist_len <= 0);
		stable_node->rmap_hlist_len--;
		put_anon_vma(rmap_item->anon_vma);
		rmap_item->address &= PAGE_MASK;
		cond_resched();
	}

	/*
	 * We need the second aligned pointer of the migrate_nodes
	 * list_head to stay clear from the rb_parent_color union
	 * (aligned and different than any node) and also different
	 * from &migrate_nodes. This will verify that future list.h changes
	 * don't break STABLE_NODE_DUP_HEAD. Only recent gcc can handle it.
	 */
	BUILD_BUG_ON(STABLE_NODE_DUP_HEAD <= &migrate_nodes);
	BUILD_BUG_ON(STABLE_NODE_DUP_HEAD >= &migrate_nodes + 1);

	if (stable_node->head == &migrate_nodes)
		list_del(&stable_node->list);
	else
		stable_node_dup_del(stable_node);
	free_stable_node(stable_node);
}


/*
 * get_ksm_page: checks if the page indicated by the stable node
 * is still its ksm page, despite having held no reference to it.
 * In which case we can trust the content of the page, and it
 * returns the gotten page; but if the page has now been zapped,
 * remove the stale node from the stable tree and return NULL.
 * But beware, the stable node's page might be being migrated.
 *
 * You would expect the stable_node to hold a reference to the ksm page.
 * But if it increments the page's count, swapping out has to wait for
 * ksmd to come around again before it can free the page, which may take
 * seconds or even minutes: much too unresponsive.  So instead we use a
 * "keyhole reference": access to the ksm page from the stable node peeps
 * out through its keyhole to see if that page still holds the right key,
 * pointing back to this stable node.  This relies on freeing a PageAnon
 * page to reset its page->mapping to NULL, and relies on no other use of
 * a page to put something that might look like our key in page->mapping.
 * is on its way to being freed; but it is an anomaly to bear in mind.
 */
static struct page *get_ksm_page(struct ksm_stable_node *stable_node,
				 enum get_ksm_page_flags flags)
{
	struct page *page;
	void *expected_mapping;
	unsigned long kpfn;

	expected_mapping = (void *)((unsigned long)stable_node |
					PAGE_MAPPING_KSM);
again:
	kpfn = READ_ONCE(stable_node->kpfn); /* Address dependency. */
	page = pfn_to_page(kpfn);
	if (READ_ONCE(page->mapping) != expected_mapping) {
		goto stale;
	}

	/*
	 * We cannot do anything with the page while its refcount is 0.
	 * Usually 0 means free, or tail of a higher-order page: in which
	 * case this node is no longer referenced, and should be freed;
	 * however, it might mean that the page is under page_ref_freeze().
	 * The __remove_mapping() case is easy, again the node is now stale;
	 * the same is in reuse_ksm_page() case; but if page is swapcache
	 * in folio_migrate_mapping(), it might still be our page,
	 * in which case it's essential to keep the node.
	 */
	while (!get_page_unless_zero(page)) {
		/*
		 * Another check for page->mapping != expected_mapping would
		 * work here too.  We have chosen the !PageSwapCache test to
		 * optimize the common case, when the page is or is about to
		 * be freed: PageSwapCache is cleared (under spin_lock_irq)
		 * in the ref_freeze section of __remove_mapping(); but Anon
		 * page->mapping reset to NULL later, in free_pages_prepare().
		 */
		if (!PageSwapCache(page))
			goto stale;
		cpu_relax();
	}

	if (READ_ONCE(page->mapping) != expected_mapping) {
		put_page(page);
		goto stale;
	}

	if (flags == GET_KSM_PAGE_TRYLOCK) {
		if (!trylock_page(page)) {
			put_page(page);
			return ERR_PTR(-EBUSY);
		}
	} else if (flags == GET_KSM_PAGE_LOCK)
		lock_page(page);

	if (flags != GET_KSM_PAGE_NOLOCK) {
		if (READ_ONCE(page->mapping) != expected_mapping) {
			unlock_page(page);
			put_page(page);
			goto stale;
		}
	}
	return page;

stale:
	/*
	 * We come here from above when page->mapping or !PageSwapCache
	 * suggests that the node is stale; but it might be under migration.
	 * We need smp_rmb(), matching the smp_wmb() in folio_migrate_ksm(),
	 * before checking whether node->kpfn has been changed.
	 */
	smp_rmb();
	if (READ_ONCE(stable_node->kpfn) != kpfn)
		goto again;
	if (!need_pending_in_stable_tree() || is_stable_node_dup(stable_node)) {
		remove_node_from_stable_tree(stable_node);
	} else {
		if (!stable_node->pended) {
			stable_node->pended = true;
			list_add_tail(&stable_node->pending_list, &stable_node_erase_pending_list);
		}
	}
	return NULL;
}

/*
 * Removing rmap_item from stable or unstable tree.
 * This function will clean the information from the stable/unstable tree.
 */
static void remove_rmap_item_from_tree(struct ksm_rmap_item *rmap_item)
{
	if (rmap_item->address & STABLE_FLAG) {
		struct ksm_stable_node *stable_node;
		struct page *page;

		stable_node = rmap_item->head;
		page = get_ksm_page(stable_node, GET_KSM_PAGE_LOCK);
		if (!page) {
			if (need_pending_in_stable_tree()) {
				flush_stable_node_erase_pending_list();
			}
			goto out;
		}

		hlist_del(&rmap_item->hlist);
		unlock_page(page);
		put_page(page);

		if (!hlist_empty(&stable_node->hlist))
			ksm_pages_sharing--;
		else
			ksm_pages_shared--;

		rmap_item->mm->ksm_merging_pages--;

		VM_BUG_ON(stable_node->rmap_hlist_len <= 0);
		stable_node->rmap_hlist_len--;

		put_anon_vma(rmap_item->anon_vma);
		rmap_item->head = NULL;
		rmap_item->address &= PAGE_MASK;

	} else if (rmap_item->address & UNSTABLE_FLAG) {
		unsigned char age;
		/*
		 * Usually ksmd can and must skip the rb_erase, because
		 * root_unstable_tree was already reset to RB_ROOT.
		 * But be careful when an mm is exiting: do the rb_erase
		 * if this rmap_item was inserted by this scan, rather
		 * than left over from before.
		 */
		age = (unsigned char)(ksm_scan.seqnr - rmap_item->address);
		BUG_ON(age > 1);
		if (!age) {
			rb_erase(&rmap_item->node, root_unstable_tree);
		}
		ksm_pages_unshared--;
		rmap_item->address &= PAGE_MASK;
	}
out:
	cond_resched();		/* we're called from many long loops */
}

static void remove_trailing_rmap_items(struct ksm_rmap_item **rmap_list)
{
	while (*rmap_list) {
		struct ksm_rmap_item *rmap_item = *rmap_list;
		*rmap_list = rmap_item->rmap_list;
		remove_rmap_item_from_tree(rmap_item);
		free_rmap_item(rmap_item);
	}
}

/*
 * Though it's very tempting to unmerge rmap_items from stable tree rather
 * than check every pte of a given vma, the locking doesn't quite work for
 * that - an rmap_item is assigned to the stable tree after inserting ksm
 * page and upping mmap_lock.  Nor does it fit with the way we skip dup'ing
 * rmap_items from parent to child at fork time (so as not to waste time
 * if exit comes before the next scan reaches it).
 *
 * Similarly, although we'd like to remove rmap_items (so updating counts
 * and freeing memory) when unmerging an area, it's easier to leave that
 * to the next pass of ksmd - consider, for example, how ksmd might be
 * in cmp_and_merge_page on one of the rmap_items we would be removing.
 */
static int unmerge_ksm_pages(struct vm_area_struct *vma,
			     unsigned long start, unsigned long end)
{
	unsigned long addr;
	int err = 0;

	for (addr = start; addr < end && !err; addr += PAGE_SIZE) {
		if (ksm_test_exit(vma->vm_mm))
			break;
		if (signal_pending(current))
			err = -ERESTARTSYS;
		else
			err = break_ksm(vma, addr);
	}
	return err;
}

static inline struct ksm_stable_node *folio_stable_node(struct folio *folio)
{
	return folio_test_ksm(folio) ? folio_raw_mapping(folio) : NULL;
}

static inline struct ksm_stable_node *page_stable_node(struct page *page)
{
	return folio_stable_node(page_folio(page));
}

static inline void set_page_stable_node(struct page *page,
					struct ksm_stable_node *stable_node)
{
	VM_BUG_ON_PAGE(PageAnon(page) && PageAnonExclusive(page), page);
	page->mapping = (void *)((unsigned long)stable_node | PAGE_MAPPING_KSM);
}

#ifdef CONFIG_SYSFS
/*
 * Only called through the sysfs control interface:
 */
static int remove_stable_node(struct ksm_stable_node *stable_node)
{
	struct page *page;
	int err;

	page = get_ksm_page(stable_node, GET_KSM_PAGE_LOCK);
	if (!page) {
		/*
		 * get_ksm_page did remove_node_from_stable_tree itself.
		 */
		if (need_pending_in_stable_tree())
			flush_stable_node_erase_pending_list();
		return 0;
	}

	/*
	 * Page could be still mapped if this races with __mmput() running in
	 * between ksm_exit() and exit_mmap(). Just refuse to let
	 * merge_across_nodes/max_page_sharing be switched.
	 */
	err = -EBUSY;
	if (!page_mapped(page)) {
		/*
		 * The stable node did not yet appear stale to get_ksm_page(),
		 * since that allows for an unmapped ksm page to be recognized
		 * right up until it is freed; but the node is safe to remove.
		 * This page might be in a pagevec waiting to be freed,
		 * or it might be PageSwapCache (perhaps under writeback),
		 * or it might have been removed from swapcache a moment ago.
		 */
		set_page_stable_node(page, NULL);
		remove_node_from_stable_tree(stable_node);
		err = 0;
	}

	unlock_page(page);
	put_page(page);
	return err;
}

static int remove_stable_node_chain(struct ksm_stable_node *stable_node)
{
	struct ksm_stable_node *dup;
	struct hlist_node *hlist_safe;

	if (!is_stable_node_chain(stable_node)) {
		VM_BUG_ON(is_stable_node_dup(stable_node));
		if (remove_stable_node(stable_node))
			return true;
		else
			return false;
	}

	hlist_for_each_entry_safe(dup, hlist_safe,
				  &stable_node->hlist, hlist_dup) {
		VM_BUG_ON(!is_stable_node_dup(dup));
		if (remove_stable_node(dup))
			return true;
	}
	BUG_ON(!hlist_empty(&stable_node->hlist));
	free_stable_node_chain(stable_node);
	return false;
}

static int remove_all_stable_nodes(void)
{
	struct ksm_stable_node *stable_node;
	int nid;
	int err = 0;

	for (nid = 0; nid < ksm_nr_node_ids; nid++) {
		while (root_stable_tree[nid].rb_node) {
			stable_node = rb_entry(root_stable_tree[nid].rb_node,
						struct ksm_stable_node, node);
			if (remove_stable_node_chain(stable_node)) {
				err = -EBUSY;
				break;
			}
			cond_resched();
		}
	}

	return err;
}

static int unmerge_and_remove_all_rmap_items(void)
{
	struct ksm_mm_slot *mm_slot;
	struct mm_slot *slot;
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	int err = 0;


	spin_lock(&ksm_mmlist_lock);
	slot = list_entry(ksm_mm_head.slot.mm_node.next,
			  struct mm_slot, mm_node);
	ksm_scan.mm_slot = mm_slot_entry(slot, struct ksm_mm_slot, slot);
	spin_unlock(&ksm_mmlist_lock);

	for (mm_slot = ksm_scan.mm_slot; mm_slot != &ksm_mm_head;
	     mm_slot = ksm_scan.mm_slot) {
		VMA_ITERATOR(vmi, mm_slot->slot.mm, 0);

		mm = mm_slot->slot.mm;
		mmap_read_lock(mm);

		/*
		 * Exit right away if mm is exiting to avoid lockdep issue in
		 * the maple tree
		 */
		if (ksm_test_exit(mm))
			goto mm_exiting;

		for_each_vma(vmi, vma) {
			if (!(vma->vm_flags & VM_MERGEABLE) || !vma->anon_vma)
				continue;
			err = unmerge_ksm_pages(vma,
						vma->vm_start, vma->vm_end);
			if (err)
				goto error;
		}

mm_exiting:
		remove_trailing_rmap_items(&mm_slot->rmap_list);
		
		mmap_read_unlock(mm);

		spin_lock(&ksm_mmlist_lock);
		slot = list_entry(mm_slot->slot.mm_node.next,
				  struct mm_slot, mm_node);
		ksm_scan.mm_slot = mm_slot_entry(slot, struct ksm_mm_slot, slot);
		if (ksm_test_exit(mm)) {
			hash_del(&mm_slot->slot.hash);
			list_del(&mm_slot->slot.mm_node);
			spin_unlock(&ksm_mmlist_lock);

			mm_slot_free(mm_slot_cache, mm_slot);
			clear_bit(MMF_VM_MERGEABLE, &mm->flags);
			mmdrop(mm);
		} else
			spin_unlock(&ksm_mmlist_lock);
	}

	/* Clean up stable nodes, but don't worry if some are still busy */
	remove_all_stable_nodes();
	ksm_scan.seqnr = 0;
	return 0;

error:
	mmap_read_unlock(mm);
	spin_lock(&ksm_mmlist_lock);
	ksm_scan.mm_slot = &ksm_mm_head;
	spin_unlock(&ksm_mmlist_lock);
	return err;
}
#endif /* CONFIG_SYSFS */

static int write_protect_page(struct vm_area_struct *vma, struct page *page,
			      pte_t *orig_pte)
{
	struct mm_struct *mm = vma->vm_mm;
	DEFINE_PAGE_VMA_WALK(pvmw, page, vma, 0, 0);
	int swapped;
	int err = -EFAULT;
	struct mmu_notifier_range range;
	bool anon_exclusive;
	pte_t tmp;
	tmp = mk_pte(page, vma->vm_page_prot);

	pvmw.address = page_address_in_vma(page, vma);
	if (pvmw.address == -EFAULT) {
		goto out;
	}

	BUG_ON(PageTransCompound(page));

	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, mm,
				pvmw.address,
				pvmw.address + PAGE_SIZE);
	mmu_notifier_invalidate_range_start(&range);

	if (!page_vma_mapped_walk(&pvmw)) {
		goto out_mn;
	}
	if (WARN_ONCE(!pvmw.pte, "Unexpected PMD mapping?")) {
		goto out_unlock;
	}

	anon_exclusive = PageAnonExclusive(page);
	if (pte_write(*pvmw.pte) || pte_dirty(*pvmw.pte) ||
	    anon_exclusive || mm_tlb_flush_pending(mm)) {
		pte_t entry;

		swapped = PageSwapCache(page);
		flush_cache_page(vma, pvmw.address, page_to_pfn(page));
		/*
		 * Ok this is tricky, when get_user_pages_fast() run it doesn't
		 * take any lock, therefore the check that we are going to make
		 * with the pagecount against the mapcount is racy and
		 * O_DIRECT can happen right after the check.
		 * So we clear the pte and flush the tlb before the check
		 * this assure us that no O_DIRECT can happen after the check
		 * or in the middle of the check.
		 *
		 * No need to notify as we are downgrading page table to read
		 * only not changing it to point to a new page.
		 *
		 * See Documentation/mm/mmu_notifier.rst
		 */
		entry = ptep_clear_flush(vma, pvmw.address, pvmw.pte);
		/*
		 * Check that no O_DIRECT or similar I/O is in progress on the
		 * page
		 */
		if (page_mapcount(page) + 1 + swapped != page_count(page)) {
			set_pte_at(mm, pvmw.address, pvmw.pte, entry);
			goto out_unlock;
		}

		/* See page_try_share_anon_rmap(): clear PTE first. */
		if (anon_exclusive && page_try_share_anon_rmap(page)) {
			set_pte_at(mm, pvmw.address, pvmw.pte, entry);
			goto out_unlock;
		}

		if (pte_dirty(entry))
			set_page_dirty(page);
		entry = pte_mkclean(entry);

		if (pte_write(entry))
			entry = pte_wrprotect(entry);

		set_pte_at_notify(mm, pvmw.address, pvmw.pte, entry);
	}
	*orig_pte = *pvmw.pte;
	err = 0;

out_unlock:
	page_vma_mapped_walk_done(&pvmw);
out_mn:
	mmu_notifier_invalidate_range_end(&range);
out:
	return err;
}

/**
 * replace_page - replace page in vma by new ksm page
 * @vma:      vma that holds the pte pointing to page
 * @page:     the page we are replacing by kpage
 * @kpage:    the ksm page we replace page by
 * @orig_pte: the original value of the pte
 *
 * Returns 0 on success, -EFAULT on failure.
 */
static int replace_page(struct vm_area_struct *vma, struct page *page,
			struct page *kpage, pte_t orig_pte, struct ksm_rmap_item *rmap_item)
{
	struct mm_struct *mm = vma->vm_mm;
	struct folio *folio;
	pmd_t *pmd;
	pmd_t pmde;
	pte_t *ptep;
	pte_t newpte;
	spinlock_t *ptl;
	unsigned long addr;
	int err = -EFAULT;
	struct mmu_notifier_range range;

	addr = page_address_in_vma(page, vma);
	if (addr == -EFAULT) {
		goto out;
	}

	pmd = mm_find_pmd(mm, addr);
	if (!pmd) {
		goto out;
	}
	/*
	 * Some THP functions use the sequence pmdp_huge_clear_flush(), set_pmd_at()
	 * without holding anon_vma lock for write.  So when looking for a
	 * genuine pmde (in which to find pte), test present and !THP together.
	 */
	pmde = *pmd;
	barrier();
	if (!pmd_present(pmde) || pmd_trans_huge(pmde)) {
		goto out;
	}

	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, mm, addr,
				addr + PAGE_SIZE);
	mmu_notifier_invalidate_range_start(&range);

	ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
	if (!pte_same(*ptep, orig_pte)) {
		pte_unmap_unlock(ptep, ptl);
		goto out_mn;
	}
	VM_BUG_ON_PAGE(PageAnonExclusive(page), page);
	VM_BUG_ON_PAGE(PageAnon(kpage) && PageAnonExclusive(kpage), kpage);

	/*
	 * No need to check ksm_use_zero_pages here: we can only have a
	 * zero_page here if ksm_use_zero_pages was enabled already.
	 */
	if (!is_zero_pfn(page_to_pfn(kpage))) {
		get_page(kpage);
		page_add_anon_rmap(kpage, vma, addr, RMAP_NONE);
		newpte = mk_pte(kpage, vma->vm_page_prot);
	} else {
		newpte = pte_mkspecial(pfn_pte(page_to_pfn(kpage),
					       vma->vm_page_prot));
		/*
		 * We're replacing an anonymous page with a zero page, which is
		 * not anonymous. We need to do proper accounting otherwise we
		 * will get wrong values in /proc, and a BUG message in dmesg
		 * when tearing down the mm.
		 */
		dec_mm_counter(mm, MM_ANONPAGES);
	}

	flush_cache_page(vma, addr, pte_pfn(*ptep));
	/*
	 * No need to notify as we are replacing a read only page with another
	 * read only page with the same content.
	 *
	 * See Documentation/mm/mmu_notifier.rst
	 */
	ptep_clear_flush(vma, addr, ptep);
	set_pte_at_notify(mm, addr, ptep, newpte);

	folio = page_folio(page);
	page_remove_rmap(page, vma, false);
	if (!folio_mapped(folio))
		folio_free_swap(folio);
	folio_put(folio);

	pte_unmap_unlock(ptep, ptl);
	err = 0;
out_mn:
	mmu_notifier_invalidate_range_end(&range);
out:
	return err;
}

/*
 * try_to_merge_one_page - take two pages and merge them into one
 * @vma: the vma that holds the pte pointing to page
 * @page: the PageAnon page that we want to replace with kpage
 * @kpage: the PageKsm page that we want to map instead of page,
 *         or NULL the first time when we want to use page as kpage.
 *
 * This function returns 0 if the pages were merged, -EFAULT otherwise.
 */
static int try_to_merge_one_page(struct vm_area_struct *vma,
				 struct page *page, struct page *kpage, struct ksm_rmap_item *rmap_item)
{
	pte_t orig_pte = __pte(0);
	int err = -EFAULT;

	if (page == kpage) {			/* ksm page forked */
		return 0;
	}

	if (!PageAnon(page)) {
		goto out;
	}

	/*
	 * We need the page lock to read a stable PageSwapCache in
	 * write_protect_page().  We use trylock_page() instead of
	 * lock_page() because we don't want to wait here - we
	 * prefer to continue scanning and merging different pages,
	 * then come back to this page when it is unlocked.
	 */
	if (!trylock_page(page)) {
		goto out;
	}

	if (PageTransCompound(page)) {
		if (split_huge_page(page)) {
			goto out_unlock;
		}
	}

	/*
	 * If this anonymous page is mapped only here, its pte may need
	 * to be write-protected.  If it's mapped elsewhere, all of its
	 * ptes are necessarily already write-protected.  But in either
	 * case, we need to lock and check page_count is not raised.
	 */
	if (write_protect_page(vma, page, &orig_pte) == 0) {
		if (!kpage) {
			/*
			 * While we hold page lock, upgrade page from
			 * PageAnon+anon_vma to PageKsm+NULL stable_node:
			 * stable_tree_insert() will update stable_node.
			 */
			set_page_stable_node(page, NULL);
			mark_page_accessed(page);
			/*
			 * Page reclaim just frees a clean page with no dirty
			 * ptes: make sure that the ksm page would be swapped.
			 */
			if (!PageDirty(page))
				SetPageDirty(page);
			err = 0;
		} else if (dsa_pages_mergeable(page, kpage, rmap_item)) {
			err = replace_page(vma, page, kpage, orig_pte, rmap_item);
		}
	}

out_unlock:
	unlock_page(page);
out:
	return err;
}

static void try_to_merge_one_page_candidate(struct vm_area_struct **vma,
				 struct page **page, struct page **kpage, struct ksm_rmap_item **rmap_item,
				 bool *need_skip, int *err)
{
	pte_t *orig_pte = try_to_merge_one_page_orig_pte;
	bool *returned = try_to_merge_one_page_returned;
	int i;

	int *ret = try_to_merge_one_page_ret;
	bool *valid = try_to_merge_one_page_valid;
	int valid_idx;
	int valid_count = 0;
	bool failed;

	for (i = 0; i < candidate_batch_size; i++) {
		err[i] = -EFAULT;
		returned[i] = true;
		valid[i] = false;
		if (need_skip[i])
			continue;

		orig_pte[i] = __pte(0);
		if (page[i] == kpage[i]) {
			err[i] = 0;
			continue;
		}

		if (!PageAnon(page[i]))
			continue;

		if (!trylock_page(page[i])) {
			continue;
		}

		if (PageTransCompound(page[i])) {
			if (split_huge_page(page[i])) {
				unlock_page(page[i]);
				continue;
			}
		}

		if (write_protect_page(vma[i], page[i], &orig_pte[i]) != 0) {
			unlock_page(page[i]);
			continue;
		}

		if (!kpage[i]) {
			set_page_stable_node(page[i], NULL);
			mark_page_accessed(page[i]);

			if (!PageDirty(page[i]))
				SetPageDirty(page[i]);
			err[i] = 0;
			unlock_page(page[i]);
			continue;
		}

		valid_count++;
		valid_idx = i;
		valid[i] = true;
		returned[i] = false;
	}

	if (valid_count == 0)
		return;

	if (valid_count == 1) {
		ret[valid_idx] = use_dsa ?
			dsa_memcmp_pages(page[valid_idx], kpage[valid_idx]) :
			cpu_memcmp_pages(page[valid_idx], kpage[valid_idx]);
	} else if (use_dsa) {
		failed = dsa_memcmp_pages_batch(page, kpage, candidate_batch_size, 1, valid, ret);
		if (failed)
			goto dsa_failed;
	} else {
dsa_failed:
		cpu_memcmp_pages_batch(page, kpage, candidate_batch_size, 1, valid, ret);
	}

	for (i = 0; i < candidate_batch_size; i++) {
		if (!valid[i])
			continue;
		if (!ret[i])
			err[i] = replace_page(vma[i], page[i], kpage[i], orig_pte[i], rmap_item[i]);
		unlock_page(page[i]);
	}
}

/*
 * try_to_merge_with_ksm_page - like try_to_merge_two_pages,
 * but no new kernel page is allocated: kpage must already be a ksm page.
 *
 * This function returns 0 if the pages were merged, -EFAULT otherwise.
 */
static int try_to_merge_with_ksm_page(struct ksm_rmap_item *rmap_item,
				      struct page *page, struct page *kpage)
{
	struct mm_struct *mm = rmap_item->mm;
	struct vm_area_struct *vma;
	int err = -EFAULT;

	mmap_read_lock(mm);
	vma = find_mergeable_vma(mm, rmap_item->address);
	if (!vma) {
		goto out;
	}

	err = try_to_merge_one_page(vma, page, kpage, rmap_item);
	if (err) {
		goto out;
	}

	/* Unstable nid is in union with stable anon_vma: remove first */
	remove_rmap_item_from_tree(rmap_item);

	/* Must get reference to anon_vma while still holding mmap_lock */
	rmap_item->anon_vma = vma->anon_vma;
	get_anon_vma(vma->anon_vma);
out:
	mmap_read_unlock(mm);
	return err;
}

static void try_to_merge_with_ksm_page_candidate(struct ksm_rmap_item **rmap_item,
				      struct page **page, struct page **kpage,
				      bool *need_skip, int *err)
{
	struct mm_struct **mm = try_to_merge_with_ksm_page_mm;
	struct vm_area_struct **vma = try_to_merge_with_ksm_page_vma;
	bool *returned = try_to_merge_with_ksm_page_returned;
	int i;

	for (i = 0; i < candidate_batch_size; i++) {
		err[i] = -EFAULT;
		if (need_skip[i]) {
			returned[i] = true;
			continue;
		}
		returned[i] = false;
		mm[i] = rmap_item[i]->mm;

		if (i != 0 && mm[i-1] == mm[i])
			vma[i] = find_mergeable_vma(mm[i], rmap_item[i]->address);
		else {
			mmap_read_lock(mm[i]);
			vma[i] = find_mergeable_vma(mm[i], rmap_item[i]->address);
		}
		if (!vma[i]) {
			returned[i] = true;
		}
		
	}
	try_to_merge_one_page_candidate(vma, page, kpage, rmap_item, returned, err);

	for (i = 0; i < candidate_batch_size; i++) {
		if (returned[i])
			continue;
		if (err[i]) {
			continue;
		}
		remove_rmap_item_from_tree(rmap_item[i]);
		rmap_item[i]->anon_vma = vma[i]->anon_vma;
		get_anon_vma(vma[i]->anon_vma);
	}

	for (i = 0; i < candidate_batch_size; i++) {
		if (need_skip[i])
			continue;
		if (i != 0 && mm[i-1] == mm[i])
			continue;
		mmap_read_unlock(mm[i]);
	}
}
/*
 * try_to_merge_two_pages - take two identical pages and prepare them
 * to be merged into one page.
 *
 * This function returns the kpage if we successfully merged two identical
 * pages into one ksm page, NULL otherwise.
 *
 * Note that this function upgrades page to ksm page: if one of the pages
 * is already a ksm page, try_to_merge_with_ksm_page should be used.
 */
static struct page *try_to_merge_two_pages(struct ksm_rmap_item *rmap_item,
					   struct page *page,
					   struct ksm_rmap_item *tree_rmap_item,
					   struct page *tree_page)
{
	int err;

	err = try_to_merge_with_ksm_page(rmap_item, page, NULL);
	if (!err) {
		err = try_to_merge_with_ksm_page(tree_rmap_item,
							tree_page, page);
		/*
		 * If that fails, we have a ksm page with only one pte
		 * pointing to it: so break it.
		 */
		if (err) {
			break_cow(rmap_item);
		}
	}
	return err ? NULL : page;
}

static void try_to_merge_two_pages_candidate(struct ksm_rmap_item **rmap_item,
					   struct page **page,
					   struct ksm_rmap_item **tree_rmap_item,
					   struct page **tree_page,
					   bool *need_skip, struct page **returned_kpage)
{
	int *err = try_to_merge_two_pages_err;
	struct page **null_page = try_to_merge_two_pages_null_page;
	int i;

	ZERO_ARRAY(null_page, candidate_batch_size);

	try_to_merge_with_ksm_page_candidate(rmap_item, page, null_page, need_skip, err);

	for (i = 0; i < candidate_batch_size; i++) {
		if (need_skip[i])
			continue;
		if (err[i]) {
			need_skip[i] = true;
			returned_kpage[i] = NULL;
		}
	}

	try_to_merge_with_ksm_page_candidate(tree_rmap_item, tree_page, page, need_skip, err);

	for (i = 0; i < candidate_batch_size; i++) {
		if (need_skip[i])
			continue;
		if (err[i]) {
			break_cow(rmap_item[i]);
			returned_kpage[i] = NULL;
		} else {
			returned_kpage[i] = page[i];
		}
	}
}

static __always_inline
bool __is_page_sharing_candidate(struct ksm_stable_node *stable_node, int offset)
{
	VM_BUG_ON(stable_node->rmap_hlist_len < 0);
	/*
	 * Check that at least one mapping still exists, otherwise
	 * there's no much point to merge and share with this
	 * stable_node, as the underlying tree_page of the other
	 * sharer is going to be freed soon.
	 */
	return stable_node->rmap_hlist_len &&
		stable_node->rmap_hlist_len + offset < ksm_max_page_sharing;
}

static __always_inline
bool is_page_sharing_candidate(struct ksm_stable_node *stable_node)
{
	return __is_page_sharing_candidate(stable_node, 0);
}

static struct page *stable_node_dup(struct ksm_stable_node **_stable_node_dup,
				    struct ksm_stable_node **_stable_node,
				    bool prune_stale_stable_nodes)
{
	struct ksm_stable_node *dup, *found = NULL, *stable_node = *_stable_node;
	struct hlist_node *hlist_safe;
	struct page *_tree_page, *tree_page = NULL;
	int nr = 0;
	int found_rmap_hlist_len;

	if (!prune_stale_stable_nodes ||
	    time_before(jiffies, stable_node->chain_prune_time +
			msecs_to_jiffies(
				ksm_stable_node_chains_prune_millisecs)))
		prune_stale_stable_nodes = false;
	else
		stable_node->chain_prune_time = jiffies;

	hlist_for_each_entry_safe(dup, hlist_safe,
				  &stable_node->hlist, hlist_dup) {
		cond_resched();
		/*
		 * We must walk all stable_node_dup to prune the stale
		 * stable nodes during lookup.
		 *
		 * get_ksm_page can drop the nodes from the
		 * stable_node->hlist if they point to freed pages
		 * (that's why we do a _safe walk). The "dup"
		 * stable_node parameter itself will be freed from
		 * under us if it returns NULL.
		 */
		_tree_page = get_ksm_page(dup, GET_KSM_PAGE_NOLOCK);
		if (!_tree_page)
			continue;
		nr += 1;
		if (is_page_sharing_candidate(dup)) {
			if (!found ||
			    dup->rmap_hlist_len > found_rmap_hlist_len) {
				if (found)
					put_page(tree_page);
				found = dup;
				found_rmap_hlist_len = found->rmap_hlist_len;
				tree_page = _tree_page;

				/* skip put_page for found dup */
				if (!prune_stale_stable_nodes)
					break;
				continue;
			}
		}
		put_page(_tree_page);
	}

	if (found) {
		/*
		 * nr is counting all dups in the chain only if
		 * prune_stale_stable_nodes is true, otherwise we may
		 * break the loop at nr == 1 even if there are
		 * multiple entries.
		 */
		if (prune_stale_stable_nodes && nr == 1) {
			/*
			 * If there's not just one entry it would
			 * corrupt memory, better BUG_ON. In KSM
			 * context with no lock held it's not even
			 * fatal.
			 */
			BUG_ON(stable_node->hlist.first->next);

			/*
			 * There's just one entry and it is below the
			 * deduplication limit so drop the chain.
			 */
			rb_replace_node(&stable_node->node, &found->node,
						root_stable_tree);
			free_stable_node(stable_node);
			ksm_stable_node_chains--;
			ksm_stable_node_dups--;
			/*
			 * NOTE: the caller depends on the stable_node
			 * to be equal to stable_node_dup if the chain
			 * was collapsed.
			 */
			*_stable_node = found;
			/*
			 * Just for robustness, as stable_node is
			 * otherwise left as a stable pointer, the
			 * compiler shall optimize it away at build
			 * time.
			 */
			stable_node = NULL;
		} else if (stable_node->hlist.first != &found->hlist_dup &&
			   __is_page_sharing_candidate(found, 1)) {
			/*
			 * If the found stable_node dup can accept one
			 * more future merge (in addition to the one
			 * that is underway) and is not at the head of
			 * the chain, put it there so next search will
			 * be quicker in the !prune_stale_stable_nodes
			 * case.
			 *
			 * NOTE: it would be inaccurate to use nr > 1
			 * instead of checking the hlist.first pointer
			 * directly, because in the
			 * prune_stale_stable_nodes case "nr" isn't
			 * the position of the found dup in the chain,
			 * but the total number of dups in the chain.
			 */
			hlist_del(&found->hlist_dup);
			hlist_add_head(&found->hlist_dup,
				       &stable_node->hlist);
		}
	}

	*_stable_node_dup = found;
	return tree_page;
}

static struct ksm_stable_node *stable_node_dup_any(struct ksm_stable_node *stable_node)
{
	if (!is_stable_node_chain(stable_node))
		return stable_node;
	if (hlist_empty(&stable_node->hlist)) {
		if (!need_pending_in_stable_tree()) {
			free_stable_node_chain(stable_node);
		} else {
			if (!stable_node->pended) {
				stable_node->pended = true;
				list_add_tail(&stable_node->pending_list, &stable_node_erase_pending_list);
			}
		}
		return NULL;
	}
	return hlist_entry(stable_node->hlist.first,
			   typeof(*stable_node), hlist_dup);
}

/*
 * Like for get_ksm_page, this function can free the *_stable_node and
 * *_stable_node_dup if the returned tree_page is NULL.
 *
 * It can also free and overwrite *_stable_node with the found
 * stable_node_dup if the chain is collapsed (in which case
 * *_stable_node will be equal to *_stable_node_dup like if the chain
 * never existed). It's up to the caller to verify tree_page is not
 * NULL before dereferencing *_stable_node or *_stable_node_dup.
 *
 * *_stable_node_dup is really a second output parameter of this
 * function and will be overwritten in all cases, the caller doesn't
 * need to initialize it.
 */
static struct page *__stable_node_chain(struct ksm_stable_node **_stable_node_dup,
					struct ksm_stable_node **_stable_node,
					bool prune_stale_stable_nodes)
{
	struct ksm_stable_node *stable_node = *_stable_node;
	if (!is_stable_node_chain(stable_node)) {
		if (is_page_sharing_candidate(stable_node)) {
			*_stable_node_dup = stable_node;
			return get_ksm_page(stable_node, GET_KSM_PAGE_NOLOCK);
		}
		/*
		 * _stable_node_dup set to NULL means the stable_node
		 * reached the ksm_max_page_sharing limit.
		 */
		*_stable_node_dup = NULL;
		return NULL;
	}
	return stable_node_dup(_stable_node_dup, _stable_node,
			       prune_stale_stable_nodes);
}

static __always_inline struct page *chain_prune(struct ksm_stable_node **s_n_d,
						struct ksm_stable_node **s_n)
{
	return __stable_node_chain(s_n_d, s_n, true);
}

static __always_inline struct page *chain(struct ksm_stable_node **s_n_d,
					  struct ksm_stable_node *s_n)
{
	struct ksm_stable_node *old_stable_node = s_n;
	struct page *tree_page;

	tree_page = __stable_node_chain(s_n_d, &s_n, false);
	/* not pruning dups so s_n cannot have changed */
	VM_BUG_ON(s_n != old_stable_node);
	return tree_page;
}

/*
 * stable_tree_search - search for page inside the stable tree
 *
 * This function checks if there is a page inside the stable tree
 * with identical content to the page that we are scanning right now.
 *
 * This function returns the stable tree node of identical content if found,
 * NULL otherwise.
 */
static struct page *stable_tree_search(struct page *page, struct ksm_rmap_item *rmap_item)
{
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *parent;
	struct ksm_stable_node *stable_node, *stable_node_dup, *stable_node_any;
	unsigned long delta;

	ksm_debug_start(STABLE_TREE_SEARCH);

	root = root_stable_tree;
again:
	new = &root->rb_node;
	parent = NULL;

	while (*new) {
		struct page *tree_page;
		int ret;

		cond_resched();
		stable_node = rb_entry(*new, struct ksm_stable_node, node);
		stable_node_any = NULL;
		tree_page = chain_prune(&stable_node_dup, &stable_node);
		/*
		 * NOTE: stable_node may have been freed by
		 * chain_prune() if the returned stable_node_dup is
		 * not NULL. stable_node_dup may have been inserted in
		 * the rbtree instead as a regular stable_node (in
		 * order to collapse the stable_node chain if a single
		 * stable_node dup was found in it). In such case the
		 * stable_node is overwritten by the callee to point
		 * to the stable_node_dup that was collapsed in the
		 * stable rbtree and stable_node will be equal to
		 * stable_node_dup like if the chain never existed.
		 */
		if (!stable_node_dup) {
			/*
			 * Either all stable_node dups were full in
			 * this stable_node chain, or this chain was
			 * empty and should be rb_erased.
			 */
			stable_node_any = stable_node_dup_any(stable_node);

			if (!stable_node_any) {
				/* rb_erase just run */
				if (need_pending_in_stable_tree()) {
					flush_stable_node_erase_pending_list();
				}
				goto again;
			}
			/*
			 * Take any of the stable_node dups page of
			 * this stable_node chain to let the tree walk
			 * continue. All KSM pages belonging to the
			 * stable_node dups in a stable_node chain
			 * have the same content and they're
			 * write protected at all times. Any will work
			 * fine to continue the walk.
			 */
			tree_page = get_ksm_page(stable_node_any,
						 GET_KSM_PAGE_NOLOCK);
		}
		VM_BUG_ON(!stable_node_dup ^ !!stable_node_any);
		if (!tree_page) {
			/*
			 * If we walked over a stale stable_node,
			 * get_ksm_page() will call rb_erase() and it
			 * may rebalance the tree from under us. So
			 * restart the search from scratch. Returning
			 * NULL would be safe too, but we'd generate
			 * false negative insertions just because some
			 * stable_node was stale.
			 */
			if (need_pending_in_stable_tree()) {
				flush_stable_node_erase_pending_list();
			}
			goto again;
		}

		if (use_dsa) {
			ret = dsa_memcmp_pages(page, tree_page);
		} else
			ret = cpu_memcmp_pages(page, tree_page);
check_ret:
		put_page(tree_page);

		parent = *new;
		if (ret < 0)
			new = &parent->rb_left;
		else if (ret > 0)
			new = &parent->rb_right;
		else {
merge_page:
			if (!stable_node_dup) {
				/*
				 * If the stable_node is a chain and
				 * we got a payload match in memcmp
				 * but we cannot merge the scanned
				 * page in any of the existing
				 * stable_node dups because they're
				 * all full, we need to wait the
				 * scanned page to find itself a match
				 * in the unstable tree to create a
				 * brand new KSM page to add later to
				 * the dups of this stable_node.
				 */

				if (need_pending_in_stable_tree()) {
					flush_stable_node_erase_pending_list();
				}
				ksm_debug_end(STABLE_TREE_SEARCH);
				return NULL;
			}

			/*
			 * Lock and unlock the stable_node's page (which
			 * might already have been migrated) so that page
			 * migration is sure to notice its raised count.
			 * It would be more elegant to return stable_node
			 * than kpage, but that involves more changes.
			 */
			tree_page = get_ksm_page(stable_node_dup,
						 GET_KSM_PAGE_TRYLOCK);

			if (PTR_ERR(tree_page) == -EBUSY) {
				if (need_pending_in_stable_tree()) {
					flush_stable_node_erase_pending_list();
				}
				ksm_debug_end(STABLE_TREE_SEARCH);
				return ERR_PTR(-EBUSY);
			}

			if (unlikely(!tree_page)) {
				/*
				 * The tree may have been rebalanced,
				 * so re-evaluate parent and new.
				 */
				if (need_pending_in_stable_tree()) {
					flush_stable_node_erase_pending_list();
				}
				goto again;
			}
			unlock_page(tree_page);

			if (need_pending_in_stable_tree()) {
				flush_stable_node_erase_pending_list();
			}
			ksm_debug_end(STABLE_TREE_SEARCH);
			return tree_page;
		}
	}

	if (need_pending_in_stable_tree()) {
		flush_stable_node_erase_pending_list();
	}
	ksm_debug_end(STABLE_TREE_SEARCH);
	return NULL;
}

/*
 * stable_tree_insert - insert stable tree node pointing to new ksm page
 * into the stable tree.
 *
 * This function returns the stable tree node just allocated on success,
 * NULL otherwise.
 */
static struct ksm_stable_node *stable_tree_insert(struct page *kpage)
{
	int nid;
	unsigned long kpfn;
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *parent;
	struct ksm_stable_node *stable_node, *stable_node_dup, *stable_node_any;
	bool need_chain = false;

	ksm_debug_start(STABLE_TREE_INSERT);

	kpfn = page_to_pfn(kpage);
	nid = get_kpfn_nid(kpfn);
	root = root_stable_tree + nid;
again:
	parent = NULL;
	new = &root->rb_node;

	while (*new) {
		struct page *tree_page;
		int ret;

		cond_resched();
		stable_node = rb_entry(*new, struct ksm_stable_node, node);
		stable_node_any = NULL;
		tree_page = chain(&stable_node_dup, stable_node);
		if (!stable_node_dup) {
			/*
			 * Either all stable_node dups were full in
			 * this stable_node chain, or this chain was
			 * empty and should be rb_erased.
			 */
			stable_node_any = stable_node_dup_any(stable_node);

			if (!stable_node_any) {
				/* rb_erase just run */
				if (need_pending_in_stable_tree()) {
					flush_stable_node_erase_pending_list();
				}
				goto again;
			}
			/*
			 * Take any of the stable_node dups page of
			 * this stable_node chain to let the tree walk
			 * continue. All KSM pages belonging to the
			 * stable_node dups in a stable_node chain
			 * have the same content and they're
			 * write protected at all times. Any will work
			 * fine to continue the walk.
			 */
			tree_page = get_ksm_page(stable_node_any,
						 GET_KSM_PAGE_NOLOCK);
		}
		VM_BUG_ON(!stable_node_dup ^ !!stable_node_any);
		if (!tree_page) {
			/*
			 * If we walked over a stale stable_node,
			 * get_ksm_page() will call rb_erase() and it
			 * may rebalance the tree from under us. So
			 * restart the search from scratch. Returning
			 * NULL would be safe too, but we'd generate
			 * false negative insertions just because some
			 * stable_node was stale.
			 */
			if (need_pending_in_stable_tree()) {
				flush_stable_node_erase_pending_list();
			}
			goto again;
		}

		if (use_dsa)
			ret = dsa_memcmp_pages(kpage, tree_page);
		else
			ret = cpu_memcmp_pages(kpage, tree_page);
		//ret = memcmp_pages(kpage, tree_page);
		put_page(tree_page);

		parent = *new;
		if (ret < 0)
			new = &parent->rb_left;
		else if (ret > 0)
			new = &parent->rb_right;
		else {
			need_chain = true;
			break;
		}
	}
	
	stable_node_dup = alloc_stable_node();
	if (!stable_node_dup) {
		ksm_debug_end(STABLE_TREE_INSERT);
		if (need_pending_in_stable_tree()) {
			flush_stable_node_erase_pending_list();
		}
		return NULL;
	}

	INIT_HLIST_HEAD(&stable_node_dup->hlist);
	stable_node_dup->kpfn = kpfn;
	set_page_stable_node(kpage, stable_node_dup);
	stable_node_dup->rmap_hlist_len = 0;
	DO_NUMA(stable_node_dup->nid = nid);
	if (!need_chain) {
		rb_link_node(&stable_node_dup->node, parent, new);
		rb_insert_color(&stable_node_dup->node, root);
	} else {
		if (!is_stable_node_chain(stable_node)) {
			struct ksm_stable_node *orig = stable_node;
			/* chain is missing so create it */
			stable_node = alloc_stable_node_chain(orig);
			if (!stable_node) {
				free_stable_node(stable_node_dup);
				ksm_debug_end(STABLE_TREE_INSERT);
				if (need_pending_in_stable_tree()) {
					flush_stable_node_erase_pending_list();
				}
				return NULL;
			}
		}
		stable_node_chain_add_dup(stable_node_dup, stable_node);
	}

	if (need_pending_in_stable_tree()) {
		flush_stable_node_erase_pending_list();
	}
	ksm_debug_end(STABLE_TREE_INSERT);
	return stable_node_dup;
}

struct rb_node *find_sucessor(struct rb_node *node, int ret) {
	if (!(node))
		return NULL;

	if (ret < 0)
		return node;
	else
		return rb_next(node);
}

void find_node_by_sucessor(struct rb_node *sucessor, struct rb_root *root, struct rb_node **parent, struct rb_node ***new) {
	if (!(root->rb_node)) { 
		//*parent = NULL; 
		*parent = NULL; 
		*new = &root->rb_node;
		return;
	}

	if(!(sucessor)) {
		*parent = rb_last(root); 
		*new = &(*parent)->rb_right;
	} else if (!(sucessor->rb_left)) {
		*parent = sucessor;
		*new = &sucessor->rb_left;
	} else {
		*parent = rb_prev(sucessor);
		*new = &(*parent)->rb_right;
	}
}

void stable_tree_insert_candidate(struct page **kpage,
					struct ksm_stable_node **returned_stable_node_dup, 
					bool* need_skip)
{
	unsigned long *kpfn = stable_tree_insert_kpfn;
	struct rb_root *root;
	struct rb_node ***new = stable_tree_insert_new;
	struct rb_node **parent = stable_tree_insert_parent; 
	struct ksm_stable_node **stable_node = stable_tree_insert_stable_node;
	struct ksm_stable_node **stable_node_dup = stable_tree_insert_stable_node_dup;
	struct ksm_stable_node **stable_node_any = stable_tree_insert_stable_node_any;
	struct page **tree_page = stable_tree_insert_tree_pages;
	bool *need_chain = stable_tree_insert_need_chain;

	// for candidate
	int i;
	int failed = 0;
	int *ret = stable_tree_insert_ret;
	bool stop;
	bool again = false;
	bool *returned = stable_tree_insert_returned;
	bool *need_again = stable_tree_insert_need_again;
	bool *valid = stable_tree_insert_valid;

	// for predecessor
	struct list_head **cursor_bucket = stable_tree_insert_cursor_list;
	struct list_head *pos, *tmp_list;
	struct rb_node **sucessor = stable_tree_insert_sucessor;
	struct cursor *tmp_cursor;
	int j;
	int s_idx;

	ksm_debug_start(STABLE_TREE_INSERT);

	root = root_stable_tree;
	for( i = 0; i < candidate_batch_size; i++ ) {
		need_chain[i] = false;
		need_again[i] = false;
		returned[i] = false;
		parent[i] = NULL;
		new[i] = NULL;
		if (need_skip[i]) {
			kpage[i] = NULL;
			returned[i] = true;
			continue;
		}
		kpfn[i] = page_to_pfn(kpage[i]);
		new[i] = &root->rb_node;
	}
	
again:
	if (again) {
		again = false;
		for (i = 0; i < candidate_batch_size; i++) {
			if (!need_again[i]) {
				continue;
			}
			returned[i] = false;
			need_again[i] = false;

			new[i] = &root->rb_node;
			parent[i] = NULL;
		}
	}

	for(;;) {
		int valid_count = 0, valid_idx;
		
		for (i = 0; i < candidate_batch_size; i++) {
			stop = (returned[i] || !(*new[i]) || need_chain[i]);
			
			if (!stop)
				break;
		}

		if(stop)
			break;

		cond_resched();

		for (i = 0; i < candidate_batch_size; i++) {
			valid[i] = false;
			if (returned[i] || !(*new[i]) || need_chain[i]) {
				continue;
			}

			stable_node[i] = rb_entry(*new[i], struct ksm_stable_node, node);
			stable_node_any[i] = NULL;
			tree_page[i] = chain(&stable_node_dup[i], stable_node[i]);
			if (!stable_node_dup[i]) {
				stable_node_any[i] = stable_node_dup_any(stable_node[i]);

				if (!stable_node_any[i]) {
					returned[i] = true;
					valid[i] = false;
					need_again[i] = true;
					continue;
				}
				tree_page[i] = get_ksm_page(stable_node_any[i],
							 GET_KSM_PAGE_NOLOCK);
			}
			VM_BUG_ON(!stable_node_dup[i] ^ !!stable_node_any[i]);
			if (!tree_page[i]) {
				returned[i] = true;
				valid[i] = false;
				need_again[i] = true;
				continue;
			}
			valid[i] = true;
			valid_count++;
			valid_idx = i;
		}

		if (valid_count == 0)
			break;

		if (valid_count == 1) {
			ret[valid_idx] = use_dsa ?
					dsa_memcmp_pages(kpage[valid_idx], tree_page[valid_idx]) :
					cpu_memcmp_pages(kpage[valid_idx], tree_page[valid_idx]);
		} else if (use_dsa) {
			failed = dsa_memcmp_pages_batch(kpage, tree_page, candidate_batch_size, 1, valid, ret);
			if (failed) 
				goto dsa_failed;
		} else {
dsa_failed:
			failed = 0;
			cpu_memcmp_pages_batch(kpage, tree_page, candidate_batch_size, 1, valid, ret);
		}

		for( i = 0; i < candidate_batch_size; i++ ) {
			if(!valid[i])
				continue;

			put_page(tree_page[i]);
			parent[i] = *new[i];
			if (ret[i] < 0)
				new[i] = &parent[i]->rb_left;
			else if (ret[i] > 0)
				new[i] = &parent[i]->rb_right;
			else {
				need_chain[i] = true;
			}
		}
	}
	
	ZERO_ARRAY(cursor_bucket, candidate_batch_size);
	for (i = 0; i < candidate_batch_size; i++) {
		if (returned[i]) 
			continue;

		stable_node_dup[i] = alloc_stable_node();
		if (!stable_node_dup[i]) {
			returned_stable_node_dup[i] = NULL;
			returned[i] = true;
			continue;
		}

		INIT_HLIST_HEAD(&stable_node_dup[i]->hlist);
		stable_node_dup[i]->kpfn = kpfn[i];
		set_page_stable_node(kpage[i], stable_node_dup[i]);
		stable_node_dup[i]->rmap_hlist_len = 0;
		DO_NUMA(stable_node_dup[i]->nid = 0);

		if (need_chain[i])
			continue;

		BUG_ON((*new[i]) != NULL);
		sucessor[i] = find_sucessor(parent[i], ret[i]); 
		
		tmp_cursor = kmalloc(sizeof(struct cursor), GFP_KERNEL);
		tmp_cursor->index = i;
		for (j = 0; j < candidate_batch_size; j++) {
			if(!cursor_bucket[j]){ 
				cursor_bucket[j] = kmalloc(sizeof(struct list_head), GFP_KERNEL);
				INIT_LIST_HEAD(cursor_bucket[j]);
				list_add(&tmp_cursor->list, cursor_bucket[j]);
				break;
			}
			s_idx = list_entry(cursor_bucket[j]->next, struct cursor, list)->index;
			if(sucessor[s_idx] == sucessor[i] ) {
				list_for_each_safe(pos, tmp_list, cursor_bucket[j]) {
					s_idx = list_entry(pos, struct cursor, list)->index;
					ret[i] = memcmp_pages(kpage[i], kpage[s_idx]);
					if (ret[i] < 0){
						if(list_is_last(pos, cursor_bucket[j])) {
							list_add_tail(&tmp_cursor->list, cursor_bucket[j]);
						}
						continue;
					} else if (ret[i] > 0){
						list_add_tail(&tmp_cursor->list, pos);
					} else {
						returned_stable_node_dup[i] = NULL;
						returned[i] = true;
						/*
						 * For stable_tree_insert_candidate(),
						 * kpages must be different
						 * But if tree_page is changed, and candidate page also changed.
						 * And they are same, they become kpage.
						 * And this kpage may be same with other kpage.
						 */
					}
					break;
				}
				break;
			}
		}
	}
	
	for( j = 0; j < candidate_batch_size; j++ ) {
		if(!cursor_bucket[j])
			break;

		list_for_each_safe(pos, tmp_list, cursor_bucket[j]) {
			tmp_cursor = list_entry(pos, struct cursor, list);
			
			s_idx = tmp_cursor->index;
			
			find_node_by_sucessor(sucessor[s_idx], root, &parent[s_idx], &new[s_idx]);
			rb_link_node(&stable_node_dup[s_idx]->node, parent[s_idx], new[s_idx]);
			rb_insert_color(&stable_node_dup[s_idx]->node, root);
			
			if(!list_is_last(pos, cursor_bucket[j])) {
				sucessor[list_entry(pos->next, struct cursor, list)->index] = &stable_node_dup[s_idx]->node;
			}
			
			returned_stable_node_dup[s_idx] = stable_node_dup[s_idx];
			returned[s_idx] = true;
			
			list_del(&tmp_cursor->list);
			kfree(tmp_cursor);
		}
		kfree(cursor_bucket[j]);
	}
	
	for (i = 0; i < candidate_batch_size; i++) {
		if (returned[i]) 
			continue;
		if (!need_chain[i])
			continue;

		returned[i] = true;
		if (!is_stable_node_chain(stable_node[i])) {
			struct ksm_stable_node *orig = stable_node[i];
			/* chain is missing so create it */
			stable_node[i] = alloc_stable_node_chain(orig);
			if (!stable_node[i]) {
				free_stable_node(stable_node_dup[i]);
				returned_stable_node_dup[i] = NULL;
				continue;
			}
		}
		stable_node_chain_add_dup(stable_node_dup[i], stable_node[i]);
		returned_stable_node_dup[i] = stable_node_dup[i];
	}

	for (i = 0; i < candidate_batch_size; i++) {
		if (need_again[i]) {
			flush_stable_node_erase_pending_list();
			again = true;
			goto again;
		}
	}
	flush_stable_node_erase_pending_list();
	ksm_debug_end(STABLE_TREE_INSERT);
}

/*
 * unstable_tree_search_insert - search for identical page,
 * else insert rmap_item into the unstable tree.
 *
 * This function searches for a page in the unstable tree identical to the
 * page currently being scanned; and if no identical page is found in the
 * tree, we insert rmap_item as a new object into the unstable tree.
 *
 * This function returns pointer to rmap_item found to be identical
 * to the currently scanned page, NULL otherwise.
 *
 * This function does both searching and inserting, because they share
 * the same walking algorithm in an rbtree.
 */
static
struct ksm_rmap_item *unstable_tree_search_insert(struct ksm_rmap_item *rmap_item,
					      struct page *page,
					      struct page **tree_pagep)
{
	struct rb_node **new;
	struct rb_root *root;
	struct rb_node *parent = NULL;
	int nid;
	unsigned long delta;

	ksm_debug_start(UNSTABLE_TREE_SEARCH_INSERT);

	nid = get_kpfn_nid(page_to_pfn(page));
	root = root_unstable_tree + nid;
	new = &root->rb_node;

	while (*new) {
		struct ksm_rmap_item *tree_rmap_item;
		struct page *tree_page;
		int ret;

		cond_resched();
		tree_rmap_item = rb_entry(*new, struct ksm_rmap_item, node);
		tree_page = get_mergeable_page(tree_rmap_item);
		if (!tree_page) {
			ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
			return NULL;
		}

		/*
		 * Don't substitute a ksm page for a forked page.
		 */
		if (page == tree_page) {
			put_page(tree_page);
			ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
			return NULL;
		}

		if (use_dsa) {
			ret = dsa_memcmp_pages(page, tree_page);
		} else
			ret = cpu_memcmp_pages(page, tree_page);

		parent = *new;
		if (ret < 0) {
			put_page(tree_page);
			new = &parent->rb_left;
		} else if (ret > 0) {
			put_page(tree_page);
			new = &parent->rb_right;
		} else {
merge_page:
			*tree_pagep = tree_page;
			ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
			return tree_rmap_item;
		}
	}

	rmap_item->address |= UNSTABLE_FLAG;
	rmap_item->address |= (ksm_scan.seqnr & SEQNR_MASK);
	DO_NUMA(rmap_item->nid = nid);
	rb_link_node(&rmap_item->node, parent, new);
	rb_insert_color(&rmap_item->node, root);

	ksm_pages_unshared++;
	ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
	return NULL;
}

void unstable_tree_search_insert_candidate(struct ksm_rmap_item **rmap_item,
					      struct page **page,
					      struct page **return_tree_page,
					      struct ksm_rmap_item **return_tree_rmap_item,
					      bool *need_skip,
					      bool *need_put_skip)
{
	struct rb_node ***new = unstable_tree_search_insert_new;
	struct rb_root *root;
	struct rb_node **parent = unstable_tree_search_insert_parent;

	struct ksm_rmap_item **tree_rmap_item = unstable_tree_search_insert_tree_rmap_items;
	struct page **tree_page = unstable_tree_search_insert_tree_pages;
	int *ret = unstable_tree_search_insert_ret;
	
	// For candidate
	int i;
	bool stop;
	bool *returned = unstable_tree_search_insert_returned;
	bool *valid = unstable_tree_search_insert_valid;
	
	// For predecessor
	struct list_head **cursor_bucket = unstable_tree_search_cursor_list;
	struct list_head *pos, *tmp_list;
	struct rb_node **sucessor = unstable_tree_search_insert_sucessor;
	struct cursor *tmp_cursor;
	struct cursor *bucket_cursor;
	int j, s_idx;
	int failed = 0;
	
	ksm_debug_start(UNSTABLE_TREE_SEARCH_INSERT);

	root = root_unstable_tree;

	for( i = 0; i < candidate_batch_size; i++ ) {
		cursor_bucket[i] = NULL;
		return_tree_page[i] = NULL;	
		return_tree_rmap_item[i] = NULL;
		new[i] = &root->rb_node;
		parent[i] = NULL;
		returned[i] = false;
		sucessor[i] = NULL; 
		if (need_skip[i]) {
			returned[i] = true;
		}
	}
		
	for(;;) {
		int valid_count = 0, valid_idx;

		for (i = 0; i < candidate_batch_size; i++) {
			stop = (returned[i] || !(*new[i]));
			
			if (!stop)
				break;
		}

		if (stop)
			break;

		cond_resched();
		
		for( i = 0; i < candidate_batch_size; i++ ) {
			valid[i] = false;
			if (returned[i] || !(*new[i])) {
				continue;
			}

			tree_rmap_item[i] = rb_entry(*new[i], struct ksm_rmap_item, node);
			tree_page[i] = get_mergeable_page(tree_rmap_item[i]);
			if (!tree_page[i]) {
				return_tree_page[i] = NULL;
				return_tree_rmap_item[i] = NULL;
				returned[i] = true;
				continue;
			}

			/*
			 * Don't substitute a ksm page for a forked page.
			 */
			if (page[i] == tree_page[i]) {
				put_page(tree_page[i]);
				return_tree_page[i] = NULL;
				return_tree_rmap_item[i] = NULL;
				returned[i] = true;
				continue;
			}

			valid[i] = true;
			valid_count++;
			valid_idx = i;
		}

		if (valid_count == 0)
			break;

		if (valid_count == 1) {
			ret[valid_idx] = use_dsa ?
					dsa_memcmp_pages(page[valid_idx], tree_page[valid_idx]) :
					cpu_memcmp_pages(page[valid_idx], tree_page[valid_idx]);
		} else if (use_dsa) {
			failed = dsa_memcmp_pages_batch(page, tree_page, candidate_batch_size, 1, valid, ret);
			if (failed)
				goto dsa_failed;
		} else {
dsa_failed:
			cpu_memcmp_pages_batch(page, tree_page, candidate_batch_size, 1, valid, ret);
		}

		for( i = 0; i < candidate_batch_size; i++ ) {
			if(!valid[i])
				continue;

			parent[i] = *new[i];
			if (ret[i] < 0) {
				put_page(tree_page[i]);
				new[i] = &parent[i]->rb_left;
			} else if (ret[i] > 0) {
				put_page(tree_page[i]);
				new[i] = &parent[i]->rb_right;
			} else {
				return_tree_page[i] = tree_page[i];
				return_tree_rmap_item[i] = tree_rmap_item[i];
				returned[i] = true;
				put_page(tree_page[i]);
			}
		}
	}

	for (i = 0; i < candidate_batch_size; i++) {
		if (returned[i]) 
			continue;

		BUG_ON((*new[i]) != NULL);
		sucessor[i] = find_sucessor(parent[i], ret[i]); 
		
		tmp_cursor = kzalloc(sizeof(struct cursor), GFP_KERNEL);
		tmp_cursor->index = i;
		tmp_cursor->need_insert = true;

		for (j = 0; j < candidate_batch_size; j++) {
			if (!cursor_bucket[j]) { 
				cursor_bucket[j] = kmalloc(sizeof(struct list_head), GFP_KERNEL);
				INIT_LIST_HEAD(cursor_bucket[j]);
				list_add(&tmp_cursor->list, cursor_bucket[j]);
				break;
			}
			
			s_idx = list_entry(cursor_bucket[j]->next, struct cursor, list)->index;
			BUG_ON((*new[s_idx]) != NULL);
			if (sucessor[s_idx] == sucessor[i] ) {
				list_for_each_safe(pos, tmp_list, cursor_bucket[j]) {
					bucket_cursor = list_entry(pos, struct cursor, list);
					s_idx = bucket_cursor->index;
					
					ksm_debug_start(COMPARE_CANDIDATE);
					ret[i] = memcmp_pages(page[i], page[s_idx]);
					ksm_debug_end(COMPARE_CANDIDATE);

					if (ret[i] < 0){
						if(list_is_last(pos, cursor_bucket[j])) {
							list_add_tail(&tmp_cursor->list, cursor_bucket[j]);
						}
						continue;
					} else if (ret[i] > 0){
						list_add_tail(&tmp_cursor->list, pos);
					} else {
						bucket_cursor->need_insert = false;
						need_put_skip[i] = true;
						return_tree_page[i] = page[s_idx];
						return_tree_rmap_item[i] = rmap_item[s_idx];
						returned[i] = true;
						kfree(tmp_cursor);
					}
					break;
				}
				break;
			}
		}
	}
	
	for( j = 0; j < candidate_batch_size; j++ ) {
		if(!cursor_bucket[j])
			break;

		list_for_each_safe(pos, tmp_list, cursor_bucket[j]) {
			tmp_cursor = list_entry(pos, struct cursor, list);

			if (!tmp_cursor->need_insert)
				goto skip_insert;

			s_idx = tmp_cursor->index;
			
			find_node_by_sucessor(sucessor[s_idx], root, &parent[s_idx], &new[s_idx]);
			
			rmap_item[s_idx]->address |= UNSTABLE_FLAG;
			rmap_item[s_idx]->address |= (ksm_scan.seqnr & SEQNR_MASK);
			DO_NUMA(rmap_item[s_idx]->nid = 0);
			rb_link_node(&rmap_item[s_idx]->node, parent[s_idx], new[s_idx]);
			rb_insert_color(&rmap_item[s_idx]->node, root);
			ksm_pages_unshared++;
			
			if(!list_is_last(pos, cursor_bucket[j])) {
				sucessor[list_entry(pos->next, struct cursor, list)->index] = &rmap_item[s_idx]->node;
			}
skip_insert:
			return_tree_page[s_idx] = NULL;
			return_tree_rmap_item[s_idx] = NULL;
			returned[s_idx] = true;

			list_del(&tmp_cursor->list);
			kfree(tmp_cursor);
		}
		kfree(cursor_bucket[j]);
	}
	ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
}

struct node_level {
	struct rb_node *node;
	struct list_head list;
	int level;
	int idx;
};

int collect_rmap_item(struct rb_node *start_node, int n, struct page **array, 
		struct ksm_rmap_item **tree_rmap_items,
		bool *valid, int *valid_idx, struct rb_node **nodes, struct page *page)
{
	int valid_count = 0;
	struct node_level *start_node_level = kmalloc(sizeof(struct node_level), GFP_KERNEL);
	struct list_head queue;
	INIT_LIST_HEAD(&queue);

	start_node_level->node = start_node;
	start_node_level->level = 0;
	start_node_level->idx = 0;
	list_add_tail(&start_node_level->list, &queue);

	while (!list_empty(&queue)) {
		struct ksm_rmap_item *tree_rmap_item;
		struct page *tree_page;
		struct node_level *curr = list_first_entry(&queue, struct node_level, list);
		list_del(&curr->list);

		if (curr->level >= n) {
			kfree(curr);
			continue;
		}

		tree_rmap_item = rb_entry(curr->node, struct ksm_rmap_item, node);
		tree_page = get_mergeable_page(tree_rmap_item);

		if (tree_page) {
			if (page == tree_page) {
				put_page(tree_page);
			} else {
				array[curr->idx] = tree_page;
				tree_rmap_items[curr->idx] = tree_rmap_item;
				valid[curr->idx] = true;
				valid_count++;
				*valid_idx = curr->idx;
				nodes[curr->idx] = curr->node;
			}
		}

		if (curr->node->rb_left) {
			struct node_level *left_child = kmalloc(sizeof(struct node_level), GFP_KERNEL);
			left_child->node = curr->node->rb_left;
			left_child->level = curr->level + 1;
			left_child->idx = curr->idx * 2 + 1;
			list_add_tail(&left_child->list, &queue);
		}

		if (curr->node->rb_right) {
			struct node_level *right_child = kmalloc(sizeof(struct node_level), GFP_KERNEL);
			right_child->node = curr->node->rb_right;
			right_child->level = curr->level + 1;
			right_child->idx = curr->idx * 2 + 2;
			list_add_tail(&right_child->list, &queue);
		}

		kfree(curr);
	}

	return valid_count;
}

/*
 * return -1 if we have to traverse rbtree again
 * else return the index of node we have to search continuously
 */
static int find_idx_spec_batch(int *ret, bool *valid, struct rb_node **nodes)
{
	int i = 0;
	int tmp;

	while (i < spec_batch_size) {
		if (!valid[i])
			return -1;
		if (ret[i] == 0)
			return i;

		if (ret[i] < 0)
			tmp = 2 * i + 1;
		else
			tmp = 2 * i + 2;

		if (tmp < spec_batch_size && nodes[tmp] == NULL)
			return i;
		i = tmp;
	}

	return (i-1)/2;
}

static 
void unstable_tree_search_insert_candidate_spec(struct ksm_rmap_item **rmap_item,
					      struct page **page,
					      struct page **return_tree_page,
					      struct ksm_rmap_item **return_tree_rmap_item,
					      bool *need_skip)
{
	struct rb_node ***new = unstable_tree_search_insert_new;
	struct rb_root *root;
	struct rb_node **parent = unstable_tree_search_insert_parent;

	struct rb_node **nodes = unstable_tree_search_insert_nodes;
	struct page **tree_pages = unstable_tree_search_insert_tree_pages;
	struct ksm_rmap_item **tree_rmap_items = unstable_tree_search_insert_tree_rmap_items;
	int *ret = unstable_tree_search_insert_ret;
	int nid;
	
	// For candidate
	int i, j, k, tmp_k;
	bool stop;
	bool *returned = unstable_tree_search_insert_returned;
	bool *valid = unstable_tree_search_insert_valid;
	
	// For predecessor
	struct list_head **cursor_bucket = unstable_tree_search_cursor_list;
	struct list_head *pos, *tmp_list;
	struct rb_node **sucessor = unstable_tree_search_insert_sucessor;
	struct cursor *tmp_cursor;
	int s_idx;
	
	ksm_debug_start(UNSTABLE_TREE_SEARCH_INSERT);

	root = root_unstable_tree;
	for( i = 0; i < candidate_batch_size; i++ ) {
		return_tree_page[i] = NULL;	
		return_tree_rmap_item[i] = NULL;
		
		new[i] = &root->rb_node;
		parent[i] = NULL;
		
		for (j = 0; j < tree_batch_size; j++) {
			k = i * candidate_batch_size + j;
			nodes[k] = NULL;
			tree_pages[k] = NULL;
			tree_rmap_items[k] = NULL;
		}

		nid = get_kpfn_nid(page_to_pfn(page[i]));

		returned[i] = false;
		
		cursor_bucket[i] = NULL;
		sucessor[i] = NULL; 
		if (need_skip[i]) {
			returned[i] = true;
		}
	}
	
	for(;;) {
		int valid_count, valid_idx, valid_idx2,  tmp, batch_size;
		valid_count = valid_idx = valid_idx2 = tmp = batch_size = 0;
		
		for (i = 0; i < candidate_batch_size; i++) {
			stop = (returned[i] || !(new[i]));

			if (!stop)
				break;
		}

		if (stop) {
			break;
		}

		cond_resched();

		for (i = 0; i < candidate_batch_size; i++) {
			k = i * tree_batch_size;
			memset(&valid[k], 0, spec_batch_size * sizeof(bool));
			if (returned[i] || !(new[i])) 
				continue;
			memset(&nodes[k], 0, spec_batch_size * sizeof(*nodes[k]));
			
			tmp = collect_rmap_item(*new[i], spec_batch_level, &tree_pages[k], &tree_rmap_items[k],
					&valid[k], &valid_idx2, &nodes[k], page[i]);

			if (tmp == 0) {
				for (j = 0; j < spec_batch_size; j++) {
					k = i * spec_batch_size + j;
					if (valid[k])
						put_page(tree_pages[k]);
				}
				returned[i] = true;
				return_tree_page[i] = NULL;
				return_tree_rmap_item[i] = NULL;
				continue;
			}
			valid_idx2 += k;
			valid_idx = i;
			valid_count += tmp;
		}
	
		if (valid_count == 0)
			break;

		if (valid_count == 1) {
			ret[valid_idx2] = use_dsa ?
					dsa_memcmp_pages(page[valid_idx], tree_pages[valid_idx2]) :
					cpu_memcmp_pages(page[valid_idx], tree_pages[valid_idx2]);
		} else if (use_dsa) {
			dsa_memcmp_pages_batch(page, tree_pages, candidate_batch_size, spec_batch_size, valid, ret);
		} else {
			cpu_memcmp_pages_batch(page, tree_pages, candidate_batch_size, spec_batch_size, valid, ret);
		}


		for (i = 0; i < candidate_batch_size; i++) {
			if (returned[i] || !(new[i])) 
				continue;
			
			k = i * tree_batch_size;
			j = find_idx_spec_batch(&ret[k], &valid[k], &nodes[k]);

			if (j < 0) {
				for (j = 0; j < spec_batch_size; j++) {
					k = i * spec_batch_size + j;
					if (valid[k])
						put_page(tree_pages[k]);
				}
				returned[i] = true;
				return_tree_page[i] = NULL;
				return_tree_rmap_item[i] = NULL;
				continue;
			}

			k = i * tree_batch_size + j;
			if (ret[k] == 0) {
				tmp_k = k;
				for (j = 0; j < batch_size; j++) {
					k = i * tree_batch_size + j;
					if (tmp_k != k && valid[k])
						put_page(tree_pages[k]);
				}
				k = tmp_k;
				returned[i] = true;
				return_tree_page[i] = tree_pages[k];
				return_tree_rmap_item[i] = tree_rmap_items[k];
				continue;
			}

			tmp_k = k;
			for (j = 0; j < batch_size; j++) {
				k = i * tree_batch_size + j;
				if (valid[k])
					put_page(tree_pages[k]);
			}

			k = tmp_k;
			parent[i] = nodes[k];
			if (ret[k] < 0)
				new[i] = &parent[i]->rb_left;
			else
				new[i] = &parent[i]->rb_right;
			continue;
		}
	}
	
	for (i = 0; i < candidate_batch_size; i++) {
		if (returned[i]) 
			continue;

		BUG_ON((*new[i]) != NULL);
		sucessor[i] = find_sucessor(parent[i], ret[i]); 
		
		tmp_cursor = kmalloc(sizeof(struct cursor), GFP_KERNEL);
		tmp_cursor->index = i;
		INIT_LIST_HEAD(&tmp_cursor->list);

		for (j = 0; j < candidate_batch_size; j++) {
			if(!cursor_bucket[j]){ 
				cursor_bucket[j] = kmalloc(sizeof(struct list_head), GFP_KERNEL);
				INIT_LIST_HEAD(cursor_bucket[j]);
				list_add(cursor_bucket[j], &tmp_cursor->list);
				break;
			}
			
			s_idx = list_entry(cursor_bucket[j]->next, struct cursor, list)->index;
			BUG_ON((*new[s_idx]) != NULL);
			if(sucessor[s_idx] == sucessor[i] ) {
				list_for_each(pos, cursor_bucket[j]) {
					s_idx = list_entry(pos, struct cursor, list)->index;
					
					ret[i] = use_dsa ?
							dsa_memcmp_pages(page[i], page[s_idx]) :
							cpu_memcmp_pages(page[i], page[s_idx]);
					if (ret[i] < 0){
						if(list_is_last(pos, cursor_bucket[j])) {
							list_add_tail(&tmp_cursor->list, pos);
						}
						continue;
					} else if (ret[i] > 0){
						list_add(&tmp_cursor->list, pos);
					} else {
						get_page(page[s_idx]);
						return_tree_page[i] = page[s_idx];
						return_tree_rmap_item[i] = rmap_item[s_idx];
						returned[i] = true;
					}
					break;
				}
				break;
			}
		}
	}

	for( j = 0; j < candidate_batch_size; j++ ) {
		if(!cursor_bucket[j])
			break;

		list_for_each_safe(pos, tmp_list, cursor_bucket[j]) {
			tmp_cursor = list_entry(pos, struct cursor, list);
			s_idx = tmp_cursor->index;
			
			find_node_by_sucessor(sucessor[s_idx], root, &parent[s_idx], &new[s_idx]);
			
			rmap_item[s_idx]->address |= UNSTABLE_FLAG;
			rmap_item[s_idx]->address |= (ksm_scan.seqnr & SEQNR_MASK);
			DO_NUMA(rmap_item[s_idx]->nid = nid);
			rb_link_node(&rmap_item[s_idx]->node, parent[s_idx], new[s_idx]);
			rb_insert_color(&rmap_item[s_idx]->node, root);
			ksm_pages_unshared++;
			
			return_tree_page[s_idx] = NULL;
			return_tree_rmap_item[s_idx] = NULL;
			returned[s_idx] = true;
			
			if(!list_is_last(pos, cursor_bucket[j])) {
				sucessor[list_entry(pos->next, struct cursor, list)->index] = &rmap_item[s_idx]->node;
			}
			
			list_del(&tmp_cursor->list);
			kfree(tmp_cursor);
		}
		kfree(cursor_bucket[j]);
	}
}

int collect_stable_node_spec(struct rb_node *start_node, int n, struct page **array, 
		bool *valid, int *valid_idx, 
		struct ksm_stable_node **dups, 
		struct ksm_stable_node **stable_nodes,
		struct rb_node **nodes, bool prune)
{
	struct ksm_stable_node *stable_node, *stable_node_dup, *stable_node_any;
	int valid_count = 0;
	struct node_level *start_node_level = kmalloc(sizeof(struct node_level), GFP_KERNEL);
	struct list_head queue;
	INIT_LIST_HEAD(&queue);

	start_node_level->node = start_node;
	start_node_level->level = 1;
	start_node_level->idx = 0;
	list_add_tail(&start_node_level->list, &queue);

	while (!list_empty(&queue)) {
		struct page *tree_page;
		struct ksm_stable_node *orig;
		struct node_level *curr = list_first_entry(&queue, struct node_level, list);
		list_del(&curr->list);

		BUG_ON(curr->node == NULL);
		stable_node = rb_entry(curr->node, struct ksm_stable_node, node);
		BUG_ON(stable_node == NULL);
		stable_node_any = NULL;
		if (prune) {
			orig = stable_node;
			tree_page = chain_prune(&stable_node_dup, &stable_node);
			if (orig != stable_node)
				curr->node = &stable_node->node;
		} else
			tree_page = chain(&stable_node_dup, stable_node);
		if (!stable_node_dup) {
			stable_node_any = stable_node_dup_any(stable_node);
			if (stable_node_any) {
				tree_page = get_ksm_page(stable_node_any,
								GET_KSM_PAGE_NOLOCK);
			}
		}

		if (tree_page) {
			array[curr->idx] = tree_page;
			valid[curr->idx] = true;
			valid_count++;
			*valid_idx = curr->idx;
			dups[curr->idx] = stable_node_dup;
			stable_nodes[curr->idx] = stable_node;
			nodes[curr->idx] = curr->node;
		}

		if (curr->level == n)
			goto out;

		if (curr->node->rb_left) {
			struct node_level *left_child = kmalloc(sizeof(struct node_level), GFP_KERNEL);
			left_child->node = curr->node->rb_left;
			left_child->level = curr->level + 1;
			left_child->idx = curr->idx * 2 + 1;
			list_add_tail(&left_child->list, &queue);
		}

		if (curr->node->rb_right) {
			struct node_level *right_child = kmalloc(sizeof(struct node_level), GFP_KERNEL);
			right_child->node = curr->node->rb_right;
			right_child->level = curr->level + 1;
			right_child->idx = curr->idx * 2 + 2;
			list_add_tail(&right_child->list, &queue);
		}

out:
		kfree(curr);
	}

	return valid_count;
}

static struct page *stable_tree_search_spec(struct page *page, struct ksm_rmap_item *rmap_item)
{
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *parent;

	struct rb_node **nodes = stable_tree_search_nodes;
	struct page **tree_pages = stable_tree_search_tree_pages;
	struct ksm_stable_node **stable_node_dup = stable_tree_search_stable_node_dup;
	struct ksm_stable_node **stable_node = stable_tree_search_stable_node;
	bool *valid = stable_tree_search_valid;
	int *ret = stable_tree_search_ret;
	int i, output, index;

	ksm_debug_start(STABLE_TREE_SEARCH);

	root = root_stable_tree;
again:
	new = &root->rb_node;
	parent = NULL;

	while (*new) {
		int valid_count = 0;
		int valid_idx;

		ZERO_ARRAY(valid, spec_batch_size);
		ZERO_ARRAY(nodes, spec_batch_size);

		cond_resched();
		valid_count = collect_stable_node_spec(*new, spec_batch_level, tree_pages, 
						valid, &valid_idx, 
						stable_node_dup, stable_node, nodes, true); 	

		if (valid_count == 0) {
			flush_stable_node_erase_pending_list();
			goto again;
		} 

		if (valid_count == 1) {
			ret[valid_idx] = dsa_memcmp_pages(page, tree_pages[valid_idx]);
		} else {
			dsa_memcmp_pages_batch(&page, tree_pages, 1, spec_batch_size, valid, ret);
		}
		
		for (i = 0; i < spec_batch_size; i++) {
			if (valid[i])
				put_page(tree_pages[i]);
		}

		i = find_idx_spec_batch(ret, valid, nodes);

		if (i < 0) {
			flush_stable_node_erase_pending_list();
			goto again;
		}

		parent = nodes[i];
		if (ret[i] < 0)
			new = &parent->rb_left;
		else if (ret[i] > 0)
			new = &parent->rb_right;
		else {
			if (!stable_node_dup[i]) {
				flush_stable_node_erase_pending_list();
				ksm_debug_end(STABLE_TREE_SEARCH);
				return NULL;	
			}
			tree_pages[i] = get_ksm_page(stable_node_dup[i],
						 GET_KSM_PAGE_TRYLOCK);
			flush_stable_node_erase_pending_list();

			if (PTR_ERR(tree_pages[i]) == -EBUSY) {
				ksm_debug_end(STABLE_TREE_SEARCH);
				return ERR_PTR(-EBUSY);
			}

			if (unlikely(!tree_pages[i])) {
				goto again;
			}
			unlock_page(tree_pages[i]);

			ksm_debug_end(STABLE_TREE_SEARCH);
			return tree_pages[i];
		}
	}

	flush_stable_node_erase_pending_list();
	ksm_debug_end(STABLE_TREE_SEARCH);
	return NULL;
}

static struct ksm_stable_node *stable_tree_insert_spec(struct page *kpage)
{
	int nid;
	unsigned long kpfn;
	struct rb_root *root;
	struct rb_node **new;
	struct rb_node *parent;
	bool need_chain = false;

	struct rb_node **nodes = stable_tree_insert_nodes;
	struct page **tree_pages = stable_tree_insert_tree_pages;
	struct ksm_stable_node **stable_node_dup = stable_tree_insert_stable_node_dup;
	struct ksm_stable_node **stable_node = stable_tree_insert_stable_node;
	bool *valid = stable_tree_insert_valid;
	int *ret = stable_tree_insert_ret;
	int i;

	ksm_debug_start(STABLE_TREE_INSERT);

	kpfn = page_to_pfn(kpage);
	nid = get_kpfn_nid(kpfn);
	root = root_stable_tree + nid;
again:
	parent = NULL;
	new = &root->rb_node;

	while (*new) {
		int valid_count = 0;
		int valid_idx;

		ZERO_ARRAY(valid, spec_batch_size);
		ZERO_ARRAY(nodes, spec_batch_size);

		cond_resched();
		valid_count = collect_stable_node_spec(*new, spec_batch_level, tree_pages,
						valid, &valid_idx, 
						stable_node_dup, stable_node, nodes, false);

		if (valid_count == 0) {
			flush_stable_node_erase_pending_list();
			goto again;
		} else if (valid_count == 1) {
			ret[valid_idx] = dsa_memcmp_pages(kpage, tree_pages[valid_idx]);
		} else {
			dsa_memcmp_pages_batch(&kpage, tree_pages, 1, spec_batch_size, valid, ret);
		}

		for (i = 0; i < spec_batch_size; i++) {
			if (valid[i])
				put_page(tree_pages[i]);
		}

		i = find_idx_spec_batch(ret, valid, nodes);

		if (i < 0) {
			flush_stable_node_erase_pending_list();
			goto again;
		}

		parent = nodes[i];
		if (ret[i] < 0)
			new = &parent->rb_left;
		else if (ret[i] > 0)
			new = &parent->rb_right;
		else {
			need_chain = true;
			break;
		}
	}

	stable_node_dup[0] = alloc_stable_node();
	if (!stable_node_dup[0]) {
		ksm_debug_end(STABLE_TREE_INSERT);
		return NULL;
	}

	INIT_HLIST_HEAD(&stable_node_dup[0]->hlist);
	stable_node_dup[0]->kpfn = kpfn;
	set_page_stable_node(kpage, stable_node_dup[0]);
	stable_node_dup[0]->rmap_hlist_len = 0;
	DO_NUMA(stable_node_dup[0]->nid = nid);
	if (!need_chain) {
		rb_link_node(&stable_node_dup[0]->node, parent, new);
		rb_insert_color(&stable_node_dup[0]->node, root);
	} else {
		if (!is_stable_node_chain(stable_node[i])) {
			struct ksm_stable_node *orig = stable_node[i];
			/* chain is missing so create it */
			stable_node[i] = alloc_stable_node_chain(orig);
			if (!stable_node[i]) {
				free_stable_node(stable_node_dup[0]);
				ksm_debug_end(STABLE_TREE_INSERT);
				return NULL;
			}
		}
		stable_node_chain_add_dup(stable_node_dup[0], stable_node[i]);
	}

	flush_stable_node_erase_pending_list();
	ksm_debug_end(STABLE_TREE_INSERT);
	return stable_node_dup[0];
}

static
struct ksm_rmap_item *unstable_tree_search_insert_spec(struct ksm_rmap_item *rmap_item,
					      struct page *page,
					      struct page **tree_pagep)
{
	struct rb_node **new;
	struct rb_root *root;
	struct rb_node *parent = NULL;
	int nid;

	struct rb_node **nodes = unstable_tree_search_insert_nodes;
	struct page **tree_pages = unstable_tree_search_insert_tree_pages;
	struct ksm_rmap_item **tree_rmap_items = unstable_tree_search_insert_tree_rmap_items;
	bool *valid = unstable_tree_search_insert_valid;
	int *ret = unstable_tree_search_insert_ret;
	int i,j, output, index;

	ksm_debug_start(UNSTABLE_TREE_SEARCH_INSERT);

	nid = get_kpfn_nid(page_to_pfn(page));
	root = root_unstable_tree;
	new = &root->rb_node;

	while (*new) {
		int valid_count = 0;
		int valid_idx;

		ZERO_ARRAY(valid, spec_batch_size);
		ZERO_ARRAY(nodes, spec_batch_size);

		cond_resched();
		valid_count = collect_rmap_item(*new, spec_batch_level, tree_pages, tree_rmap_items,
					valid, &valid_idx, nodes, page);

		if (valid_count == 0) {
			for (j = 0; j < spec_batch_size; j++) {
				if (valid[j])
					put_page(tree_pages[j]);
			}
			ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
			return NULL;
		}
		
		if (valid_count == 1) {
			ret[valid_idx] = dsa_memcmp_pages(page, tree_pages[valid_idx]);
		} else {
			dsa_memcmp_pages_batch(&page, tree_pages, 1, spec_batch_size, valid, ret);
		}

		i = find_idx_spec_batch(ret, valid, nodes);

		if (i < 0) {
			for (j = 0; j < spec_batch_size; j++) {
				if (valid[j])
					put_page(tree_pages[j]);
			}
			ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
			return NULL;
		}

		if (ret[i] == 0) {
			for (j = 0; j < spec_batch_size; j++) {
				if (i != j && valid[j])
					put_page(tree_pages[j]);
			}
			*tree_pagep = tree_pages[i];
			ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
			return tree_rmap_items[i];
		}

		for (j = 0; j < spec_batch_size; j++) {
			if (valid[j])
				put_page(tree_pages[j]);
		}

		parent = nodes[i];
		if (ret[i] < 0)
			new = &parent->rb_left;
		else
			new = &parent->rb_right;
	}

	rmap_item->address |= UNSTABLE_FLAG;
	rmap_item->address |= (ksm_scan.seqnr & SEQNR_MASK);
	DO_NUMA(rmap_item->nid = nid);
	rb_link_node(&rmap_item->node, parent, new);
	rb_insert_color(&rmap_item->node, root);

	ksm_pages_unshared++;
	ksm_debug_end(UNSTABLE_TREE_SEARCH_INSERT);
	return NULL;
}

static void stable_tree_search_candidate(struct page **page, bool* need_skip, 
		struct ksm_rmap_item **rmap_item, struct page **kpage)
{
	struct rb_root *root;
	struct rb_node ***new = stable_tree_search_new;
	struct rb_node **parent = stable_tree_search_parent;
	struct ksm_stable_node **stable_node = stable_tree_search_stable_node;
	struct ksm_stable_node **stable_node_dup = stable_tree_search_stable_node_dup;
	struct ksm_stable_node *stable_node_any;
	struct page **tree_pages = stable_tree_search_tree_pages;
	bool stop;
	bool *returned = stable_tree_search_returned;
	bool *need_again = stable_tree_search_need_again;
	bool *valid = stable_tree_search_valid;
	int *ret = stable_tree_search_ret;
	int *output = stable_tree_search_output;
	int *index = stable_tree_search_index;
	int i;
	bool again = false;

	ksm_debug_start(STABLE_TREE_SEARCH);

	root = root_stable_tree;

	for (i = 0; i < candidate_batch_size; i++) {
		need_again[i] = false;
		if (need_skip[i]) {
			returned[i] = true;
			continue;
		}
		returned[i] = false;

		new[i] = &root->rb_node;
		parent[i] = NULL;
	}
again:
	if (again) {
		again = false;
		for (i = 0; i < candidate_batch_size; i++) {
			if (!need_again[i]) {
				returned[i] = true;
				continue;
			}
			returned[i] = false;
			need_again[i] = false;

			new[i] = &root->rb_node;
			parent[i] = NULL;
		}
	}
	
	for (;;) {
		int valid_count = 0, valid_idx;

		for (i = 0; i < candidate_batch_size; i++) {
			stop = (returned[i] || !(*new[i]));
			if (!stop)
				break;
		}

		if (stop)
			break;

		cond_resched();

		for (i = 0; i < candidate_batch_size; i++) {
			if (returned[i] || !(*new[i])) {
				valid[i] = false;
				continue;
			}

			stable_node[i] = rb_entry(*new[i], struct ksm_stable_node, node);
			stable_node_any = NULL;
			tree_pages[i] = chain_prune(&stable_node_dup[i], &stable_node[i]);
			if (!stable_node_dup[i]) {
				stable_node_any = stable_node_dup_any(stable_node[i]);

				if (!stable_node_any) {
					returned[i] = true;
					valid[i] = false;
					need_again[i] = true;
					continue;
				}

				tree_pages[i] = get_ksm_page(stable_node_any,
							GET_KSM_PAGE_NOLOCK);
			}

			if (!tree_pages[i]) {
				returned[i] = true;
				valid[i] = false;
				need_again[i] = true;
				continue;
			}

			valid[i] = true;
			valid_count++;
			valid_idx = i;
		}

		if (valid_count == 0)
			break;

		if (valid_count == 1) {
			ret[valid_idx] = use_dsa ?
					dsa_memcmp_pages(page[valid_idx], tree_pages[valid_idx]) :
					cpu_memcmp_pages(page[valid_idx], tree_pages[valid_idx]);
		} else if (use_dsa) {
			dsa_memcmp_pages_batch(page, tree_pages, candidate_batch_size, 1, valid, ret);
		} else {
			cpu_memcmp_pages_batch(page, tree_pages, candidate_batch_size, 1, valid, ret);
		}

		for (i = 0; i < candidate_batch_size; i++) {
			if (!valid[i])
				continue;
			put_page(tree_pages[i]);

			parent[i] = *new[i];
			if (ret[i] < 0)
				new[i] = &parent[i]->rb_left;
			else if (ret[i] > 0)
				new[i] = &parent[i]->rb_right;
			else {
				returned[i] = true;
				if  (!stable_node_dup[i]) {
					kpage[i] = NULL;
					continue;
				}

				tree_pages[i] = get_ksm_page(stable_node_dup[i],
							GET_KSM_PAGE_TRYLOCK);
				if (PTR_ERR(tree_pages[i]) == -EBUSY) {
					kpage[i] = ERR_PTR(-EBUSY);
					continue;
				}
				
				if (unlikely(!tree_pages[i])) {
					kpage[i] = NULL;
					continue;
				}
				unlock_page(tree_pages[i]);

				kpage[i] = tree_pages[i];
			}
		}
	}
	
	for (i = 0; i < candidate_batch_size; i++) {
		if (need_again[i])
			again = true;
		if (returned[i])
			continue;

		kpage[i] = NULL;
	}
	flush_stable_node_erase_pending_list();
	if (again)
		goto again;
	ksm_debug_end(STABLE_TREE_SEARCH);
}

static void stable_tree_search_candidate_spec(struct page **page, bool* need_skip, 
		struct ksm_rmap_item **rmap_item, struct page **kpage)
{
	struct rb_root *root;
	struct rb_node ***new = stable_tree_search_new;
	struct rb_node **parent = stable_tree_search_parent;
	struct rb_node **nodes = stable_tree_search_nodes;
	struct ksm_stable_node **stable_node = stable_tree_search_stable_node;
	struct ksm_stable_node **stable_node_dup = stable_tree_search_stable_node_dup;
	struct page **tree_pages = stable_tree_search_tree_pages;
	bool stop;
	bool *returned = stable_tree_search_returned;
	bool *valid = stable_tree_search_valid;
	int *ret = stable_tree_search_ret;
	int *output = stable_tree_search_output;
	int *index = stable_tree_search_index;
	int i, j, k;

	ksm_debug_start(STABLE_TREE_SEARCH);

	root = root_stable_tree;

	for (i = 0; i < candidate_batch_size; i++) {
		if (need_skip[i]) {
			returned[i] = true;
			continue;
		} else {
			returned[i] = false;
		}

		new[i] = &root->rb_node;
		parent[i] = NULL;
	}

	for (;;) {
		int valid_count = 0, valid_idx, valid_idx2, tmp;

		for (i = 0; i < candidate_batch_size; i++) {
			if (!(*new[i])) {
				returned[i] = true;
				kpage[i] = NULL;
			}
			stop &= returned[i];
		}

		if (stop)
			break;

		cond_resched();

		for (i = 0; i < candidate_batch_size; i++) {
			k = i * spec_batch_size;
			memset(&valid[k], 0, spec_batch_size * sizeof(bool));
			if (returned[i]) 
				continue;
			memset(&nodes[k], 0, spec_batch_size * sizeof(*nodes));

			tmp = collect_stable_node_spec(*new[i], spec_batch_level, &tree_pages[k],
					&valid[k], &valid_idx2,
					&stable_node_dup[k], &stable_node[k], &nodes[k], true);

			if (!tmp) {
				returned[i] = true;
				kpage[i] = NULL;
				continue;
			}

			valid_idx2 += k;
			valid_idx = i;
			valid_count += tmp;
		}

		if (valid_count == 0)
			break;

		if (valid_count == 1) {
			ret[valid_idx2] = use_dsa ?
					dsa_memcmp_pages(page[valid_idx], tree_pages[valid_idx2]) :
					cpu_memcmp_pages(page[valid_idx], tree_pages[valid_idx2]);
		} else if (use_dsa) {
			dsa_memcmp_pages_batch(page, tree_pages, candidate_batch_size, 
					spec_batch_size, valid, ret);
		} else {
			cpu_memcmp_pages_batch(page, tree_pages, candidate_batch_size, 
					spec_batch_size, valid, ret);
		}

		for (i = 0; i < candidate_batch_size; i++) {
			if (returned[i])
				continue;
			
			for (j = 0; j < spec_batch_size; j++) {
				k = i * spec_batch_size + j;
				if (valid[k])
					put_page(tree_pages[k]);
			}

			k = i * spec_batch_size;
			j = find_idx_spec_batch(&ret[k], &valid[k], &nodes[k]);

			if (j < 0) {
				returned[i] = true;
				kpage[i] = NULL;
				continue;
			}

			k += j;
			parent[i] = nodes[k];
			if (ret[k] < 0)
				new[i] = &parent[i]->rb_left;
			else if (ret[k] > 0)
				new[i] = &parent[i]->rb_right;
			else {
				if  (!stable_node_dup[k]) {
					returned[i] = true;
					kpage[i] = NULL;
					continue;
				}

				tree_pages[k] = get_ksm_page(stable_node_dup[k],
							GET_KSM_PAGE_TRYLOCK);
				if (PTR_ERR(tree_pages[k]) == -EBUSY) {
					returned[i] = true;
					kpage[i] = NULL;
					continue;
				}
				if (unlikely(!tree_pages[k])) {
					returned[i] = true;
					kpage[i] = NULL;
					continue;
				}
				unlock_page(tree_pages[k]);

				kpage[i] = tree_pages[k];
				returned[i] = true;
			}
		}
	}
	
	flush_stable_node_erase_pending_list();
	ksm_debug_end(STABLE_TREE_SEARCH);
}

/*
 * stable_tree_append - add another rmap_item to the linked list of
 * rmap_items hanging off a given node of the stable tree, all sharing
 * the same ksm page.
 */
static void stable_tree_append(struct ksm_rmap_item *rmap_item,
			       struct ksm_stable_node *stable_node,
			       bool max_page_sharing_bypass)
{
	unsigned long address;
	/*
	 * rmap won't find this mapping if we don't insert the
	 * rmap_item in the right stable_node
	 * duplicate. page_migration could break later if rmap breaks,
	 * so we can as well crash here. We really need to check for
	 * rmap_hlist_len == STABLE_NODE_CHAIN, but we can as well check
	 * for other negative values as an underflow if detected here
	 * for the first time (and not when decreasing rmap_hlist_len)
	 * would be sign of memory corruption in the stable_node.
	 */
	BUG_ON(stable_node->rmap_hlist_len < 0);

	stable_node->rmap_hlist_len++;
	//if (!max_page_sharing_bypass)
		/* possibly non fatal but unexpected overflow, only warn */
		//WARN_ON_ONCE(stable_node->rmap_hlist_len >
			    // ksm_max_page_sharing);

	rmap_item->head = stable_node;
	rmap_item->address |= STABLE_FLAG;

	hlist_add_head(&rmap_item->hlist, &stable_node->hlist);

	if (rmap_item->hlist.next)
		ksm_pages_sharing++;
	else
		ksm_pages_shared++;

	rmap_item->mm->ksm_merging_pages++;
}

/*
 * cmp_and_merge_page - first see if page can be merged into the stable tree;
 * if not, compare checksum to previous and if it's the same, see if page can
 * be inserted into the unstable tree, or merged with a page already there and
 * both transferred to the stable tree.
 *
 * @page: the page that we are searching identical page to.
 * @rmap_item: the reverse mapping into the virtual address of this page
 */
static void cmp_and_merge_page(struct page *page, struct ksm_rmap_item *rmap_item)
{
	struct mm_struct *mm = rmap_item->mm;
	struct ksm_rmap_item *tree_rmap_item;
	struct page *tree_page = NULL;
	struct ksm_stable_node *stable_node;
	struct page *kpage;
	unsigned int checksum;
	int err;
	bool max_page_sharing_bypass = false;

	ksm_debug_start(CMP_AND_MERGE);

	stable_node = page_stable_node(page);
	if (stable_node) {
		if (stable_node->head != &migrate_nodes &&
		    get_kpfn_nid(READ_ONCE(stable_node->kpfn)) !=
		    NUMA(stable_node->nid)) {
			stable_node_dup_del(stable_node);
			stable_node->head = &migrate_nodes;
			list_add(&stable_node->list, stable_node->head);
		}
		if (stable_node->head != &migrate_nodes &&
		    rmap_item->head == stable_node) {
			ksm_debug_end(CMP_AND_MERGE);
			return;
		}
		/*
		 * If it's a KSM fork, allow it to go over the sharing limit
		 * without warnings.
		 */
		if (!is_page_sharing_candidate(stable_node))
			max_page_sharing_bypass = true;
	}

	/* We first start with searching the page inside the stable tree */
	if (check_batch_mode(SPECULATIVE))
		kpage = stable_tree_search_spec(page, rmap_item);
	else
		kpage = stable_tree_search(page, rmap_item);
	if (kpage == page && rmap_item->head == stable_node) {
		put_page(kpage);
		ksm_debug_end(CMP_AND_MERGE);
		return;
	}

	remove_rmap_item_from_tree(rmap_item);

	if (kpage) {
		if (PTR_ERR(kpage) == -EBUSY) {
			ksm_debug_end(CMP_AND_MERGE);
			return;
		}

		err = try_to_merge_with_ksm_page(rmap_item, page, kpage);
		if (!err) {
			/*
			 * The page was successfully merged:
			 * add its rmap_item to the stable tree.
			 */
			lock_page(kpage);
			stable_tree_append(rmap_item, page_stable_node(kpage),
					   max_page_sharing_bypass);
			unlock_page(kpage);
		}
		put_page(kpage);
		ksm_debug_end(CMP_AND_MERGE);
		return;
	}

	/*
	 * If the hash value of the page has changed from the last time
	 * we calculated it, this page is changing frequently: therefore we
	 * don't want to insert it in the unstable tree, and we don't want
	 * to waste our time searching for something identical to it there.
	 */
	if (use_dsa && use_dsa_for_hash)
		checksum = dsa_calc_checksum(page);
	else
		checksum = calc_checksum(page);
	if (rmap_item->oldchecksum != checksum) {
		rmap_item->oldchecksum = checksum;
		ksm_debug_end(CMP_AND_MERGE);
		return;
	}

	/*
	 * Same checksum as an empty page. We attempt to merge it with the
	 * appropriate zero page if the user enabled this via sysfs.
	 */
	if (ksm_use_zero_pages && (checksum == zero_checksum)) {
		struct vm_area_struct *vma;

		mmap_read_lock(mm);
		vma = find_mergeable_vma(mm, rmap_item->address);
		if (vma) {
			err = try_to_merge_one_page(vma, page,
					ZERO_PAGE(rmap_item->address), rmap_item);
		} else {
			/*
			 * If the vma is out of date, we do not need to
			 * continue.
			 */
			err = 0;
		}
		mmap_read_unlock(mm);
		/*
		 * In case of failure, the page was not really empty, so we
		 * need to continue. Otherwise we're done.
		 */
		if (!err) {
			ksm_debug_end(CMP_AND_MERGE);
			return;
		}
	}
	if (check_batch_mode(SPECULATIVE))
		tree_rmap_item = unstable_tree_search_insert_spec(rmap_item, page, &tree_page);
	else
		tree_rmap_item = unstable_tree_search_insert(rmap_item, page, &tree_page);
	if (tree_rmap_item) {
		bool split;

		kpage = try_to_merge_two_pages(rmap_item, page,
						tree_rmap_item, tree_page);
		/*
		 * If both pages we tried to merge belong to the same compound
		 * page, then we actually ended up increasing the reference
		 * count of the same compound page twice, and split_huge_page
		 * failed.
		 * Here we set a flag if that happened, and we use it later to
		 * try split_huge_page again. Since we call put_page right
		 * afterwards, the reference count will be correct and
		 * split_huge_page should succeed.
		 */
		split = PageTransCompound(page)
			&& compound_head(page) == compound_head(tree_page);
		put_page(tree_page);
		if (kpage) {
			/*
			 * The pages were successfully merged: insert new
			 * node in the stable tree and add both rmap_items.
			 */
			lock_page(kpage);
			if (check_batch_mode(SPECULATIVE))
				stable_node = stable_tree_insert_spec(kpage);
			else
				stable_node = stable_tree_insert(kpage);
			if (stable_node) {
				stable_tree_append(tree_rmap_item, stable_node,
						   false);
				stable_tree_append(rmap_item, stable_node,
						   false);
			}
			unlock_page(kpage);

			/*
			 * If we fail to insert the page into the stable tree,
			 * we will have 2 virtual addresses that are pointing
			 * to a ksm page left outside the stable tree,
			 * in which case we need to break_cow on both.
			 */
			if (!stable_node) {
				break_cow(tree_rmap_item);
				break_cow(rmap_item);
			}
		} else if (split) {
			/*
			 * We are here if we tried to merge two pages and
			 * failed because they both belonged to the same
			 * compound page. We will split the page now, but no
			 * merging will take place.
			 * We do not want to add the cost of a full lock; if
			 * the page is locked, it is better to skip it and
			 * perhaps try again later.
			 */
			if (!trylock_page(page)) {
				ksm_debug_end(CMP_AND_MERGE);
				return;
			}
			split_huge_page(page);
			unlock_page(page);
		}
	}
	ksm_debug_end(CMP_AND_MERGE);
}
	
static void cmp_and_merge_page_candidate(struct page **page, struct ksm_rmap_item **rmap_item)
{
	struct mm_struct **mm = cmp_and_merge_page_mm_new1;
	struct ksm_stable_node **stable_node =  cmp_and_merge_page_stable_node_new1;
	struct page **kpage =  cmp_and_merge_page_kpage_new1;

	bool *need_skip_round1 =  cmp_and_merge_page_need_skip_new1;
	bool *need_skip_merge_round1 =  cmp_and_merge_page_need_skip_merge_new1;
	int *errors =  cmp_and_merge_page_errors_new1;
	int valid_count_round1 = 0;

	bool *need_skip_round2 =  cmp_and_merge_page_need_skip_new2;
	int valid_count_round2 = 0;
	int valid_idx_round2;

	struct page **page2 = cmp_and_merge_page_page_new2;
	struct ksm_rmap_item **rmap_item2 = cmp_and_merge_page_rmap_item_new2;

	struct ksm_rmap_item **tree_rmap_item =  cmp_and_merge_page_tree_rmap_item_new2;
	struct page **tree_page =  cmp_and_merge_page_tree_page_new2;
	unsigned int *checksum =  cmp_and_merge_page_checksum_new2;
	bool *need_put_skip =  cmp_and_merge_page_need_put_skip_new2;
	bool *need_stable_append =  cmp_and_merge_page_need_stable_append_new2;
	bool *need_stable_skip =  cmp_and_merge_page_need_stable_skip_new2;

	bool *need_skip_merge2 =  cmp_and_merge_page_need_skip_merge2_new2;
	bool *need_skip_merge2_1 =  cmp_and_merge_page_need_skip_merge2_1_new2;
	bool *need_skip_merge3 =  cmp_and_merge_page_need_skip_merge3_new2;

	struct ksm_stable_node *tmp_stable_node;
	int i, j, k;
	int n_cand;

	int start, end;

	ksm_debug_start(CMP_AND_MERGE);

/* ------------------------------------------ Round 0 --------------------------------------------*/

	for (i = 0; i < N_cand * candidate_batch_size; i++) {
		if (!rmap_item[i]) {
			need_skip_round1[i] = true;
		} else {
			mm[i] = rmap_item[i]->mm;
			need_skip_round1[i] = false;
			kpage[i] = NULL;
		}

		if (need_skip_round1[i])
			continue;

		stable_node[i] = page_stable_node(page[i]);
		if (stable_node[i] && 
			rmap_item[i]->head == stable_node[i]) {
			need_skip_round1[i] = true;
			put_page(page[i]);
			continue;
		}
	}
/* ------------------------------------------ Round 1 --------------------------------------------*/
	n_cand = 0;
	start = 0;
stable_tree_round:

while (true) {
	j = n_cand * candidate_batch_size;
	/* We first start with searching the page inside the stable tree */
	if (check_batch_mode(SPECULATIVE))
		stable_tree_search_candidate_spec(&page[j], &need_skip_round1[j], &rmap_item[j], &kpage[j]);
	else
		stable_tree_search_candidate(&page[j], &need_skip_round1[j], &rmap_item[j], &kpage[j]);
	
	for (i = 0; i < candidate_batch_size; i++) {
		k = j + i;
		need_skip_merge_round1[k] = true;
		if (need_skip_round1[k])
			continue;

		if (kpage[k] == page[k] && rmap_item[k]->head == stable_node[k]) {
			put_page(kpage[k]);
			need_skip_round1[k] = true;
			put_page(page[k]);
			continue;
		}

		remove_rmap_item_from_tree(rmap_item[k]);
		if (kpage[k]) {
			if (PTR_ERR(kpage[k]) == -EBUSY) {
				need_skip_round1[k] = true;
				put_page(page[k]);
				continue;
			}

			tmp_stable_node = page_stable_node(kpage[k]);
			if (!is_page_sharing_candidate(tmp_stable_node)) {
				put_page(kpage[k]);
				valid_count_round1++;
				continue;
			}
			need_skip_merge_round1[k] = false;
		} else {
			valid_count_round1++;
		}
	}

	try_to_merge_with_ksm_page_candidate(&rmap_item[j], &page[j], &kpage[j], &need_skip_merge_round1[j], &errors[j]);

	for (i = 0; i < candidate_batch_size; i++) {
		k = j + i;
		if (need_skip_merge_round1[k])
			continue;
		if (!errors[k]) {
			tmp_stable_node = page_stable_node(kpage[k]);
			lock_page(kpage[k]);
			stable_tree_append(rmap_item[k], tmp_stable_node, false);
			unlock_page(kpage[k]);
		} else {
			pr_info("fail to merge with kpage from stable tree\n");
		}
		put_page(kpage[k]);
		need_skip_round1[k] = true;
		put_page(page[k]);
	}

	n_cand++;
	if (valid_count_round1 >= candidate_batch_size || n_cand == N_cand) {
		end = n_cand * candidate_batch_size;
		break;
	}
}

/* ------------------------------------ Round 1 ->  Round 2 --------------------------------------*/
round2_start:
	valid_count_round2 = 0;

	ONE_ARRAY(need_skip_round2, candidate_batch_size);

	j = 0;
	for (i = start; i < end; i++) { 
		if (need_skip_round1[i]) {
			continue;
		}
		rmap_item2[j] = rmap_item[i];
		page2[j] = page[i];
		need_skip_round2[j] = false;
		valid_count_round2++;
		valid_idx_round2 = j;
		j++;

		if (valid_count_round2 == candidate_batch_size) {
			i++;
			break;
		}
	}
	
	valid_count_round1 -= valid_count_round2;
	start = i;

	ZERO_ARRAY(tree_page, candidate_batch_size);
	ZERO_ARRAY(need_put_skip, candidate_batch_size);

/* ------------------------------------------ Round 2 --------------------------------------------*/

	/*
	 * If the hash value of the page has changed from the last time
	 * we calculated it, this page is changing frequently: therefore we
	 * don't want to insert it in the unstable tree, and we don't want
	 * to waste our time searching for something identical to it there.
	 */
	if (valid_count_round2 == 0)
		goto out;

	if (use_dsa) {
		if (!use_dsa_for_hash)
			goto cpu_checksum;
		if (valid_count_round2 == 1)
			checksum[valid_idx_round2] = dsa_calc_checksum(page2[valid_idx_round2]);
		else
			dsa_calc_checksum_batch(page2, candidate_batch_size, need_skip_round2, checksum);

		goto skip_cpu_checksum;
	}
cpu_checksum:
	for (i = 0; i < candidate_batch_size; i++) {
		if (need_skip_round2[i])
			continue;

		checksum[i] = calc_checksum(page2[i]);
	}
skip_cpu_checksum:
	for (i = 0; i < candidate_batch_size; i++) {
		need_stable_append[i] = false;
		need_skip_merge2[i] = true;
		need_skip_merge2_1[i] = true;
		need_skip_merge3[i] = true;
		if (need_skip_round2[i])
			continue;

		if (rmap_item2[i]->oldchecksum != checksum[i]) {
			rmap_item2[i]->oldchecksum = checksum[i];
			need_skip_round2[i] = true;
			valid_count_round2--;

			put_page(page2[i]);
		}
	}

	if (valid_count_round2 == 0)
		goto out;

	if (check_batch_mode(SPECULATIVE))
		unstable_tree_search_insert_candidate_spec(rmap_item2, page2, tree_page, tree_rmap_item, need_skip_round2);
	else
		unstable_tree_search_insert_candidate(rmap_item2, page2, tree_page, tree_rmap_item, need_skip_round2, need_put_skip);
	
	
	for (i = 0; i < candidate_batch_size; i++) {
		need_stable_skip[i] = true;
		if (need_skip_round2[i])
			continue;
		
		if (!tree_rmap_item[i]) {
			continue;
		} else {
			for (j = i+1; j < candidate_batch_size; j++) {
				if (need_skip_round2[i])
					continue;
				if (i == j)
					continue;
				if (tree_page[i] != tree_page[j])
					continue;

				need_stable_append[i] = true;
				need_skip_merge3[i] = false;
			}
			if (need_stable_append[i])
				continue;

			if (!need_put_skip[i]) {
				tree_page[i] = get_mergeable_page(tree_rmap_item[i]);
				if (!tree_page[i])
					continue;
			}
			need_skip_merge2[i] = false;
			need_skip_merge2_1[i] = false;
		}
	}
	try_to_merge_two_pages_candidate(tree_rmap_item, tree_page, rmap_item2, page2, need_skip_merge2, kpage);

	for (i = 0; i < candidate_batch_size; i++) {
		bool split;
		if (need_stable_append[i]) {
			if (!PageKsm(tree_page[i])) {
				need_skip_merge3[i] = true;
				need_stable_append[i] = false;
			} else {
				if (!need_put_skip[i]) {
					tree_page[i] = get_mergeable_page(tree_rmap_item[i]);
					if (!tree_page[i]) {
						need_skip_merge3[i] = true;
						need_stable_append[i] = false;
					}
				}
			}
		}
		if (need_skip_merge2_1[i])
			continue;
		if (kpage[i] == NULL) {
			pr_info("fail to merge with tree page from unstable tree\n");
		}
		split = PageTransCompound(page2[i])
			&& compound_head(page2[i]) == compound_head(tree_page[i]);
		if (kpage[i]) {
			need_stable_skip[i] = false;
		} else if (split) {
			if (!trylock_page(page2[i]))
				continue;
			split_huge_page(page2[i]);
			unlock_page(page2[i]);
		}
	}

	for (i = 0; i < candidate_batch_size; i++) {
		if (need_stable_skip[i])
			continue;
		lock_page(kpage[i]);
	}
	stable_tree_insert_candidate(kpage, stable_node, need_stable_skip);
	for (i = 0; i < candidate_batch_size; i++) {
		if (need_stable_skip[i])
			continue;
		if (stable_node[i]) {
			stable_tree_append(tree_rmap_item[i], stable_node[i], false);
			stable_tree_append(rmap_item2[i], stable_node[i], false);
		}

		unlock_page(kpage[i]);
		
		if (!stable_node[i]) {
			break_cow(tree_rmap_item[i]);
			break_cow(rmap_item2[i]);
		}

		if (!need_put_skip[i]) {
			put_page(tree_page[i]);
		}
	}
	try_to_merge_with_ksm_page_candidate(rmap_item2, page2, tree_page, need_skip_merge3, errors);

	for (i = 0; i < candidate_batch_size; i++) {
		if (need_stable_append[i]) {
			if (!errors[i]) {
				lock_page(tree_page[i]);
				stable_tree_append(rmap_item2[i], page_stable_node(tree_page[i]),
						false);
				unlock_page(tree_page[i]);
			} else {
				pr_info("fail to merge with kpage from unstable tree\n");
			}
			if (!need_put_skip[i]) {
				put_page(tree_page[i]);
			}
		}
	}

	for (i = 0; i < candidate_batch_size; i++) {
		if (need_skip_round2[i])
			continue;

		put_page(page2[i]);
	}

out:
	if (n_cand < N_cand)
		goto stable_tree_round;
	if (valid_count_round1 > 0)
		goto round2_start;
	ksm_debug_end(CMP_AND_MERGE);
}

static struct ksm_rmap_item *get_next_rmap_item(struct ksm_mm_slot *mm_slot,
					    struct ksm_rmap_item **rmap_list,
					    unsigned long addr)
{
	struct ksm_rmap_item *rmap_item;
	
	while (*rmap_list) {
		rmap_item = *rmap_list;
		if ((rmap_item->address & PAGE_MASK) == addr)
			return rmap_item;
		if (rmap_item->address > addr)
			break;
		*rmap_list = rmap_item->rmap_list;
		remove_rmap_item_from_tree(rmap_item);
		free_rmap_item(rmap_item);
	}

	rmap_item = alloc_rmap_item();
	if (rmap_item) {
		/* It has already been zeroed */
		rmap_item->mm = mm_slot->slot.mm;
		rmap_item->mm->ksm_rmap_items++;
		rmap_item->address = addr;
		rmap_item->rmap_list = *rmap_list;
		*rmap_list = rmap_item;
	}
	return rmap_item;
}

static struct ksm_rmap_item *scan_get_next_rmap_item(struct page **page)
{
	struct mm_struct *mm;
	struct ksm_mm_slot *mm_slot;
	struct mm_slot *slot;
	struct vm_area_struct *vma;
	struct ksm_rmap_item *rmap_item;
	struct vma_iterator vmi;
	int nid;

	if (list_empty(&ksm_mm_head.slot.mm_node))
		return NULL;

	ksm_debug_start(SCAN_GET_NEXT_RMAP_ITEM);

	mm_slot = ksm_scan.mm_slot;
	if (mm_slot == &ksm_mm_head) {
		/*
		 * A number of pages can hang around indefinitely on per-cpu
		 * pagevecs, raised page count preventing write_protect_page
		 * from merging them.  Though it doesn't really matter much,
		 * it is puzzling to see some stuck in pages_volatile until
		 * other activity jostles them out, and they also prevented
		 * LTP's KSM test from succeeding deterministically; so drain
		 * them here (here rather than on entry to ksm_do_scan(),
		 * so we don't IPI too often when pages_to_scan is set low).
		 */
		lru_add_drain_all();

		for (nid = 0; nid < ksm_nr_node_ids; nid++)
			root_unstable_tree[nid] = RB_ROOT;

		spin_lock(&ksm_mmlist_lock);
		slot = list_entry(mm_slot->slot.mm_node.next,
				  struct mm_slot, mm_node);
		mm_slot = mm_slot_entry(slot, struct ksm_mm_slot, slot);
		ksm_scan.mm_slot = mm_slot;
		spin_unlock(&ksm_mmlist_lock);
		/*
		 * Although we tested list_empty() above, a racing __ksm_exit
		 * of the last mm on the list may have removed it since then.
		 */
		if (mm_slot == &ksm_mm_head)
			goto out;
next_mm:
		ksm_scan.address = 0;
		ksm_scan.rmap_list = &mm_slot->rmap_list;
	}

	slot = &mm_slot->slot;
	mm = slot->mm;
	vma_iter_init(&vmi, mm, ksm_scan.address);

	mmap_read_lock(mm);
	if (ksm_test_exit(mm))
		goto no_vmas;

	for_each_vma(vmi, vma) {
		if (!(vma->vm_flags & VM_MERGEABLE))
			continue;
		if (ksm_scan.address < vma->vm_start)
			ksm_scan.address = vma->vm_start;
		if (!vma->anon_vma)
			ksm_scan.address = vma->vm_end;

		while (ksm_scan.address < vma->vm_end) {
			if (ksm_test_exit(mm))
				break;
			*page = follow_page(vma, ksm_scan.address, FOLL_GET); 
			if (IS_ERR_OR_NULL(*page)) {
				ksm_scan.address += PAGE_SIZE;
				cond_resched();
				continue;
			}
			if (is_zone_device_page(*page))
				goto next_page;
			if (PageAnon(*page)) {
				flush_anon_page(vma, *page, ksm_scan.address);
				flush_dcache_page(*page);
				rmap_item = get_next_rmap_item(mm_slot,
					ksm_scan.rmap_list, ksm_scan.address);
				if (rmap_item) {
					ksm_scan.rmap_list =
							&rmap_item->rmap_list;
					ksm_scan.address += PAGE_SIZE;
				} else
					put_page(*page);
				mmap_read_unlock(mm);
				ksm_debug_end(SCAN_GET_NEXT_RMAP_ITEM);
				return rmap_item;
			}
next_page:
			put_page(*page);
			ksm_scan.address += PAGE_SIZE;
			cond_resched();
		}
	}

	if (ksm_test_exit(mm)) {
no_vmas:
		ksm_scan.address = 0;
		ksm_scan.rmap_list = &mm_slot->rmap_list;
	}
	/*
	 * Nuke all the rmap_items that are above this current rmap:
	 * because there were no VM_MERGEABLE vmas with such addresses.
	 */
	remove_trailing_rmap_items(ksm_scan.rmap_list);

	spin_lock(&ksm_mmlist_lock);
	slot = list_entry(mm_slot->slot.mm_node.next,
			  struct mm_slot, mm_node);
	ksm_scan.mm_slot = mm_slot_entry(slot, struct ksm_mm_slot, slot);
	if (ksm_scan.address == 0) {
		/*
		 * We've completed a full scan of all vmas, holding mmap_lock
		 * throughout, and found no VM_MERGEABLE: so do the same as
		 * __ksm_exit does to remove this mm from all our lists now.
		 * This applies either when cleaning up after __ksm_exit
		 * (but beware: we can reach here even before __ksm_exit),
		 * or when all VM_MERGEABLE areas have been unmapped (and
		 * mmap_lock then protects against race with MADV_MERGEABLE).
		 */
		hash_del(&mm_slot->slot.hash);
		list_del(&mm_slot->slot.mm_node);
		spin_unlock(&ksm_mmlist_lock);

		mm_slot_free(mm_slot_cache, mm_slot);
		clear_bit(MMF_VM_MERGEABLE, &mm->flags);
		mmap_read_unlock(mm);
		mmdrop(mm);
	} else {
		mmap_read_unlock(mm);
		/*
		 * mmap_read_unlock(mm) first because after
		 * spin_unlock(&ksm_mmlist_lock) run, the "mm" may
		 * already have been freed under us by __ksm_exit()
		 * because the "mm_slot" is still hashed and
		 * ksm_scan.mm_slot doesn't point to it anymore.
		 */
		spin_unlock(&ksm_mmlist_lock);
	}

	/* Repeat until we've completed scanning the whole list */
	mm_slot = ksm_scan.mm_slot;
	if (mm_slot != &ksm_mm_head)
		goto next_mm;

	ksm_scan.seqnr++;
out:
	ksm_debug_end(SCAN_GET_NEXT_RMAP_ITEM);
	return NULL;
}

/**
 * ksm_do_scan  - the ksm scanner main worker function.
 * @scan_npages:  number of pages we want to scan before we return.
 */
static void ksm_do_scan(unsigned int scan_npages)
{
	struct ksm_rmap_item *rmap_item;
	struct page *page;

	ksm_debug_start(KSM_DO_SCAN);

	while (scan_npages-- && likely(!freezing(current))) {
		cond_resched();
		rmap_item = scan_get_next_rmap_item(&page);
		if (!rmap_item) {
			ksm_debug_end(KSM_DO_SCAN);
			return;
		}
		
		cmp_and_merge_page(page, rmap_item);
		put_page(page);
	}
	ksm_debug_end(KSM_DO_SCAN);
}

static void ksm_do_scan_candidate(unsigned int scan_npages)
{
	struct ksm_rmap_item **rmap_item = ksm_do_scan_new_rmap_item;
	struct page **page = ksm_do_scan_new_page;
	int i;
	bool all_null;
	unsigned long curr_seqnr;
	bool seqnr_inc = false;

	ksm_debug_start(KSM_DO_SCAN);

	scan_npages /= (N_cand * candidate_batch_size);
	while (scan_npages-- && likely(!freezing(current))) {
		cond_resched();
		ZERO_ARRAY(rmap_item, N_cand * candidate_batch_size);
		ZERO_ARRAY(page, N_cand * candidate_batch_size);

		all_null = true;
		curr_seqnr = ksm_scan.seqnr;
		for (i = 0; i < N_cand * candidate_batch_size; i++) {
			rmap_item[i] = scan_get_next_rmap_item(&page[i]);
			if (rmap_item[i])
				all_null = false;
			if (curr_seqnr != ksm_scan.seqnr) {
				ksm_scan.seqnr = curr_seqnr;
				seqnr_inc = true;
				break;
			}
		}
		if (all_null) {
			if (seqnr_inc)
				ksm_scan.seqnr++;
			break;
		}
		cmp_and_merge_page_candidate(page, rmap_item);
		if (seqnr_inc) {
			ksm_scan.seqnr++;
			break;
		}
	}
	ksm_debug_end(KSM_DO_SCAN);
}
static int ksmd_should_run(void)
{
	return (ksm_run & KSM_RUN_MERGE) && !list_empty(&ksm_mm_head.slot.mm_node);
}

static int ksm_scan_thread(void *nothing)
{
	unsigned int sleep_ms;

	set_freezable();
	set_user_nice(current, 5);

	while (!kthread_should_stop()) {
		mutex_lock(&ksm_thread_mutex);
		wait_while_offlining();
		if (ksmd_should_run()) {
			if (check_batch_mode(CANDIDATE))
				ksm_do_scan_candidate(ksm_thread_pages_to_scan);
			else
				ksm_do_scan(ksm_thread_pages_to_scan);
		}
		mutex_unlock(&ksm_thread_mutex);

		try_to_freeze();

		if (ksmd_should_run()) {
			sleep_ms = READ_ONCE(ksm_thread_sleep_millisecs);
			wait_event_interruptible_timeout(ksm_iter_wait,
				sleep_ms != READ_ONCE(ksm_thread_sleep_millisecs),
				msecs_to_jiffies(sleep_ms));
		} else {
			wait_event_freezable(ksm_thread_wait,
				ksmd_should_run() || kthread_should_stop());
		}
	}
	return 0;
}

int ksm_madvise(struct vm_area_struct *vma, unsigned long start,
		unsigned long end, int advice, unsigned long *vm_flags)
{
	struct mm_struct *mm = vma->vm_mm;
	int err;

	switch (advice) {
	case MADV_MERGEABLE:
		/*
		 * Be somewhat over-protective for now!
		 */
		if (*vm_flags & (VM_MERGEABLE | VM_SHARED  | VM_MAYSHARE   |
				 VM_PFNMAP    | VM_IO      | VM_DONTEXPAND |
				 VM_HUGETLB | VM_MIXEDMAP))
			return 0;		/* just ignore the advice */

		if (vma_is_dax(vma))
			return 0;

#ifdef VM_SAO
		if (*vm_flags & VM_SAO)
			return 0;
#endif
#ifdef VM_SPARC_ADI
		if (*vm_flags & VM_SPARC_ADI)
			return 0;
#endif

		if (!test_bit(MMF_VM_MERGEABLE, &mm->flags)) {
			err = __ksm_enter(mm);
			if (err)
				return err;
		}

		*vm_flags |= VM_MERGEABLE;
		break;

	case MADV_UNMERGEABLE:
		if (!(*vm_flags & VM_MERGEABLE))
			return 0;		/* just ignore the advice */

		if (vma->anon_vma) {
			err = unmerge_ksm_pages(vma, start, end);
			if (err)
				return err;
		}

		*vm_flags &= ~VM_MERGEABLE;
		break;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(ksm_madvise);

int __ksm_enter(struct mm_struct *mm)
{
	struct ksm_mm_slot *mm_slot;
	struct mm_slot *slot;
	int needs_wakeup;

	mm_slot = mm_slot_alloc(mm_slot_cache);
	if (!mm_slot)
		return -ENOMEM;

	slot = &mm_slot->slot;

	/* Check ksm_run too?  Would need tighter locking */
	needs_wakeup = list_empty(&ksm_mm_head.slot.mm_node);

	spin_lock(&ksm_mmlist_lock);
	mm_slot_insert(mm_slots_hash, mm, slot);
	/*
	 * When KSM_RUN_MERGE (or KSM_RUN_STOP),
	 * insert just behind the scanning cursor, to let the area settle
	 * down a little; when fork is followed by immediate exec, we don't
	 * want ksmd to waste time setting up and tearing down an rmap_list.
	 *
	 * But when KSM_RUN_UNMERGE, it's important to insert ahead of its
	 * scanning cursor, otherwise KSM pages in newly forked mms will be
	 * missed: then we might as well insert at the end of the list.
	 */
	if (ksm_run & KSM_RUN_UNMERGE)
		list_add_tail(&slot->mm_node, &ksm_mm_head.slot.mm_node);
	else
		list_add_tail(&slot->mm_node, &ksm_scan.mm_slot->slot.mm_node);
	spin_unlock(&ksm_mmlist_lock);

	set_bit(MMF_VM_MERGEABLE, &mm->flags);
	mmgrab(mm);

	if (needs_wakeup)
		wake_up_interruptible(&ksm_thread_wait);

	return 0;
}

void __ksm_exit(struct mm_struct *mm)
{
	struct ksm_mm_slot *mm_slot;
	struct mm_slot *slot;
	int easy_to_free = 0;

	/*
	 * This process is exiting: if it's straightforward (as is the
	 * case when ksmd was never running), free mm_slot immediately.
	 * But if it's at the cursor or has rmap_items linked to it, use
	 * mmap_lock to synchronize with any break_cows before pagetables
	 * are freed, and leave the mm_slot on the list for ksmd to free.
	 * Beware: ksm may already have noticed it exiting and freed the slot.
	 */

	spin_lock(&ksm_mmlist_lock);
	slot = mm_slot_lookup(mm_slots_hash, mm);
	mm_slot = mm_slot_entry(slot, struct ksm_mm_slot, slot);
	if (mm_slot && ksm_scan.mm_slot != mm_slot) {
		if (!mm_slot->rmap_list) {
			hash_del(&slot->hash);
			list_del(&slot->mm_node);
			easy_to_free = 1;
		} else {
			list_move(&slot->mm_node,
				  &ksm_scan.mm_slot->slot.mm_node);
		}
	}
	spin_unlock(&ksm_mmlist_lock);

	if (easy_to_free) {
		mm_slot_free(mm_slot_cache, mm_slot);
		clear_bit(MMF_VM_MERGEABLE, &mm->flags);
		mmdrop(mm);
	} else if (mm_slot) {
		mmap_write_lock(mm);
		mmap_write_unlock(mm);
	}
}

struct page *ksm_might_need_to_copy(struct page *page,
			struct vm_area_struct *vma, unsigned long address)
{
	struct folio *folio = page_folio(page);
	struct anon_vma *anon_vma = folio_anon_vma(folio);
	struct page *new_page;

	if (PageKsm(page)) {
		if (page_stable_node(page) &&
		    !(ksm_run & KSM_RUN_UNMERGE))
			return page;	/* no need to copy it */
	} else if (!anon_vma) {
		return page;		/* no need to copy it */
	} else if (page->index == linear_page_index(vma, address) &&
			anon_vma->root == vma->anon_vma->root) {
		return page;		/* still no need to copy it */
	}
	if (!PageUptodate(page))
		return page;		/* let do_swap_page report the error */

	new_page = alloc_page_vma(GFP_HIGHUSER_MOVABLE, vma, address);
	if (new_page &&
	    mem_cgroup_charge(page_folio(new_page), vma->vm_mm, GFP_KERNEL)) {
		put_page(new_page);
		new_page = NULL;
	}
	if (new_page) {
		if (copy_mc_user_highpage(new_page, page, address, vma)) {
			put_page(new_page);
			memory_failure_queue(page_to_pfn(page), 0);
			return ERR_PTR(-EHWPOISON);
		}
		SetPageDirty(new_page);
		__SetPageUptodate(new_page);
		__SetPageLocked(new_page);
#ifdef CONFIG_SWAP
		count_vm_event(KSM_SWPIN_COPY);
#endif
	}

	return new_page;
}

void rmap_walk_ksm(struct folio *folio, struct rmap_walk_control *rwc)
{
	struct ksm_stable_node *stable_node;
	struct ksm_rmap_item *rmap_item;
	int search_new_forks = 0;

	VM_BUG_ON_FOLIO(!folio_test_ksm(folio), folio);

	/*
	 * Rely on the page lock to protect against concurrent modifications
	 * to that page's node of the stable tree.
	 */
	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);

	stable_node = folio_stable_node(folio);
	if (!stable_node)
		return;
again:
	hlist_for_each_entry(rmap_item, &stable_node->hlist, hlist) {
		struct anon_vma *anon_vma = rmap_item->anon_vma;
		struct anon_vma_chain *vmac;
		struct vm_area_struct *vma;

		cond_resched();
		if (!anon_vma_trylock_read(anon_vma)) {
			if (rwc->try_lock) {
				rwc->contended = true;
				return;
			}
			anon_vma_lock_read(anon_vma);
		}
		anon_vma_interval_tree_foreach(vmac, &anon_vma->rb_root,
					       0, ULONG_MAX) {
			unsigned long addr;

			cond_resched();
			vma = vmac->vma;

			/* Ignore the stable/unstable/sqnr flags */
			addr = rmap_item->address & PAGE_MASK;

			if (addr < vma->vm_start || addr >= vma->vm_end)
				continue;
			/*
			 * Initially we examine only the vma which covers this
			 * rmap_item; but later, if there is still work to do,
			 * we examine covering vmas in other mms: in case they
			 * were forked from the original since ksmd passed.
			 */
			if ((rmap_item->mm == vma->vm_mm) == search_new_forks)
				continue;

			if (rwc->invalid_vma && rwc->invalid_vma(vma, rwc->arg))
				continue;

			if (!rwc->rmap_one(folio, vma, addr, rwc->arg)) {
				anon_vma_unlock_read(anon_vma);
				return;
			}
			if (rwc->done && rwc->done(folio)) {
				anon_vma_unlock_read(anon_vma);
				return;
			}
		}
		anon_vma_unlock_read(anon_vma);
	}
	if (!search_new_forks++)
		goto again;
}

#ifdef CONFIG_MIGRATION
void folio_migrate_ksm(struct folio *newfolio, struct folio *folio)
{
	struct ksm_stable_node *stable_node;

	VM_BUG_ON_FOLIO(!folio_test_locked(folio), folio);
	VM_BUG_ON_FOLIO(!folio_test_locked(newfolio), newfolio);
	VM_BUG_ON_FOLIO(newfolio->mapping != folio->mapping, newfolio);

	stable_node = folio_stable_node(folio);
	if (stable_node) {
		VM_BUG_ON_FOLIO(stable_node->kpfn != folio_pfn(folio), folio);
		stable_node->kpfn = folio_pfn(newfolio);
		/*
		 * newfolio->mapping was set in advance; now we need smp_wmb()
		 * to make sure that the new stable_node->kpfn is visible
		 * to get_ksm_page() before it can see that folio->mapping
		 * has gone stale (or that folio_test_swapcache has been cleared).
		 */
		smp_wmb();
		set_page_stable_node(&folio->page, NULL);
	}
}
#endif /* CONFIG_MIGRATION */

#ifdef CONFIG_MEMORY_HOTREMOVE
static void wait_while_offlining(void)
{
	while (ksm_run & KSM_RUN_OFFLINE) {
		mutex_unlock(&ksm_thread_mutex);
		wait_on_bit(&ksm_run, ilog2(KSM_RUN_OFFLINE),
			    TASK_UNINTERRUPTIBLE);
		mutex_lock(&ksm_thread_mutex);
	}
}

static bool stable_node_dup_remove_range(struct ksm_stable_node *stable_node,
					 unsigned long start_pfn,
					 unsigned long end_pfn)
{
	if (stable_node->kpfn >= start_pfn &&
	    stable_node->kpfn < end_pfn) {
		/*
		 * Don't get_ksm_page, page has already gone:
		 * which is why we keep kpfn instead of page*
		 */
		remove_node_from_stable_tree(stable_node);
		return true;
	}
	return false;
}

static bool stable_node_chain_remove_range(struct ksm_stable_node *stable_node,
					   unsigned long start_pfn,
					   unsigned long end_pfn)
{
	struct ksm_stable_node *dup;
	struct hlist_node *hlist_safe;

	if (!is_stable_node_chain(stable_node)) {
		VM_BUG_ON(is_stable_node_dup(stable_node));
		return stable_node_dup_remove_range(stable_node, start_pfn,
						    end_pfn);
	}

	hlist_for_each_entry_safe(dup, hlist_safe,
				  &stable_node->hlist, hlist_dup) {
		VM_BUG_ON(!is_stable_node_dup(dup));
		stable_node_dup_remove_range(dup, start_pfn, end_pfn);
	}
	if (hlist_empty(&stable_node->hlist)) {
		free_stable_node_chain(stable_node);
		return true; /* notify caller that tree was rebalanced */
	} else
		return false;
}

static void ksm_check_stable_tree(unsigned long start_pfn,
				  unsigned long end_pfn)
{
	struct ksm_stable_node *stable_node;
	struct rb_node *node;
	int nid;

	for (nid = 0; nid < ksm_nr_node_ids; nid++) {
		node = rb_first(root_stable_tree + nid);
		while (node) {
			stable_node = rb_entry(node, struct ksm_stable_node, node);
			if (stable_node_chain_remove_range(stable_node,
						start_pfn, end_pfn))
				node = rb_first(root_stable_tree + nid);
			else
				node = rb_next(node);
			cond_resched();
		}
	}
}

static int ksm_memory_callback(struct notifier_block *self,
			       unsigned long action, void *arg)
{
	struct memory_notify *mn = arg;

	switch (action) {
	case MEM_GOING_OFFLINE:
		/*
		 * Prevent ksm_do_scan(), unmerge_and_remove_all_rmap_items()
		 * and remove_all_stable_nodes() while memory is going offline:
		 * it is unsafe for them to touch the stable tree at this time.
		 * But unmerge_ksm_pages(), rmap lookups and other entry points
		 * which do not need the ksm_thread_mutex are all safe.
		 */
		mutex_lock(&ksm_thread_mutex);
		ksm_run |= KSM_RUN_OFFLINE;
		mutex_unlock(&ksm_thread_mutex);
		break;

	case MEM_OFFLINE:
		/*
		 * Most of the work is done by page migration; but there might
		 * be a few stable_nodes left over, still pointing to struct
		 * pages which have been offlined: prune those from the tree,
		 * otherwise get_ksm_page() might later try to access a
		 * non-existent struct page.
		 */
		ksm_check_stable_tree(mn->start_pfn,
				      mn->start_pfn + mn->nr_pages);
		fallthrough;
	case MEM_CANCEL_OFFLINE:
		mutex_lock(&ksm_thread_mutex);
		ksm_run &= ~KSM_RUN_OFFLINE;
		mutex_unlock(&ksm_thread_mutex);

		smp_mb();	/* wake_up_bit advises this */
		wake_up_bit(&ksm_run, ilog2(KSM_RUN_OFFLINE));
		break;
	}
	return NOTIFY_OK;
}
#else
static void wait_while_offlining(void)
{
}
#endif /* CONFIG_MEMORY_HOTREMOVE */

#ifdef CONFIG_SYSFS
/*
 * This all compiles without CONFIG_SYSFS, but is a waste of space.
 */

#define KSM_ATTR_RO(_name) \
	static struct kobj_attribute _name##_attr = __ATTR_RO(_name)
#define KSM_ATTR(_name) \
	static struct kobj_attribute _name##_attr = __ATTR_RW(_name)

static ssize_t sleep_millisecs_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ksm_thread_sleep_millisecs);
}

static ssize_t sleep_millisecs_store(struct kobject *kobj,
				     struct kobj_attribute *attr,
				     const char *buf, size_t count)
{
	unsigned int msecs;
	int err;

	err = kstrtouint(buf, 10, &msecs);
	if (err)
		return -EINVAL;

	ksm_thread_sleep_millisecs = msecs;
	wake_up_interruptible(&ksm_iter_wait);

	return count;
}
KSM_ATTR(sleep_millisecs);

static ssize_t pages_to_scan_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ksm_thread_pages_to_scan);
}

static ssize_t pages_to_scan_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned int nr_pages;
	int err;

	err = kstrtouint(buf, 10, &nr_pages);
	if (err)
		return -EINVAL;

	ksm_thread_pages_to_scan = nr_pages;

	return count;
}
KSM_ATTR(pages_to_scan);

static ssize_t run_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	return sysfs_emit(buf, "%lu\n", ksm_run);
}

static ssize_t run_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	unsigned int flags;
	int err;

	err = kstrtouint(buf, 10, &flags);
	if (err)
		return -EINVAL;
	if (flags > KSM_RUN_UNMERGE)
		return -EINVAL;

	/*
	 * KSM_RUN_MERGE sets ksmd running, and 0 stops it running.
	 * KSM_RUN_UNMERGE stops it running and unmerges all rmap_items,
	 * breaking COW to free the pages_shared (but leaves mm_slots
	 * on the list for when ksmd may be set running again).
	 */

	mutex_lock(&ksm_thread_mutex);
	wait_while_offlining();
	if (ksm_run != flags) {
		ksm_run = flags;
		if (flags & KSM_RUN_UNMERGE) {
			set_current_oom_origin();
			err = unmerge_and_remove_all_rmap_items();
			clear_current_oom_origin();
			if (err) {
				ksm_run = KSM_RUN_STOP;
				count = err;
			}
		}
	}
	mutex_unlock(&ksm_thread_mutex);

	if (flags & KSM_RUN_MERGE)
		wake_up_interruptible(&ksm_thread_wait);

	return count;
}
KSM_ATTR(run);

#ifdef CONFIG_NUMA
static ssize_t merge_across_nodes_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ksm_merge_across_nodes);
}

static ssize_t merge_across_nodes_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int err;
	unsigned long knob;

	err = kstrtoul(buf, 10, &knob);
	if (err)
		return err;
	if (knob > 1)
		return -EINVAL;

	mutex_lock(&ksm_thread_mutex);
	wait_while_offlining();
	if (ksm_merge_across_nodes != knob) {
		if (ksm_pages_shared || remove_all_stable_nodes())
			err = -EBUSY;
		else if (root_stable_tree == one_stable_tree) {
			struct rb_root *buf;
			/*
			 * This is the first time that we switch away from the
			 * default of merging across nodes: must now allocate
			 * a buffer to hold as many roots as may be needed.
			 * Allocate stable and unstable together:
			 * MAXSMP NODES_SHIFT 10 will use 16kB.
			 */
			buf = kcalloc(nr_node_ids + nr_node_ids, sizeof(*buf),
				      GFP_KERNEL);
			/* Let us assume that RB_ROOT is NULL is zero */
			if (!buf)
				err = -ENOMEM;
			else {
				root_stable_tree = buf;
				root_unstable_tree = buf + nr_node_ids;
				/* Stable tree is empty but not the unstable */
				root_unstable_tree[0] = one_unstable_tree[0];
			}
		}
		if (!err) {
			ksm_merge_across_nodes = knob;
			ksm_nr_node_ids = knob ? 1 : nr_node_ids;
		}
	}
	mutex_unlock(&ksm_thread_mutex);

	return err ? err : count;
}
KSM_ATTR(merge_across_nodes);
#endif

static ssize_t use_zero_pages_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ksm_use_zero_pages);
}
static ssize_t use_zero_pages_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	int err;
	bool value;

	err = kstrtobool(buf, &value);
	if (err)
		return -EINVAL;

	ksm_use_zero_pages = value;

	return count;
}
KSM_ATTR(use_zero_pages);

static ssize_t max_page_sharing_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", ksm_max_page_sharing);
}

static ssize_t max_page_sharing_store(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      const char *buf, size_t count)
{
	int err;
	int knob;

	err = kstrtoint(buf, 10, &knob);
	if (err)
		return err;
	/*
	 * When a KSM page is created it is shared by 2 mappings. This
	 * being a signed comparison, it implicitly verifies it's not
	 * negative.
	 */
	if (knob < 2)
		return -EINVAL;

	if (READ_ONCE(ksm_max_page_sharing) == knob)
		return count;

	mutex_lock(&ksm_thread_mutex);
	wait_while_offlining();
	if (ksm_max_page_sharing != knob) {
		if (ksm_pages_shared || remove_all_stable_nodes())
			err = -EBUSY;
		else
			ksm_max_page_sharing = knob;
	}
	mutex_unlock(&ksm_thread_mutex);

	return err ? err : count;
}
KSM_ATTR(max_page_sharing);

static ssize_t pages_shared_show(struct kobject *kobj,
				 struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", ksm_pages_shared);
}
KSM_ATTR_RO(pages_shared);

static ssize_t pages_sharing_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", ksm_pages_sharing);
}
KSM_ATTR_RO(pages_sharing);

static ssize_t pages_unshared_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", ksm_pages_unshared);
}
KSM_ATTR_RO(pages_unshared);

static ssize_t pages_volatile_show(struct kobject *kobj,
				   struct kobj_attribute *attr, char *buf)
{
	long ksm_pages_volatile;

	ksm_pages_volatile = ksm_rmap_items - ksm_pages_shared
				- ksm_pages_sharing - ksm_pages_unshared;
	/*
	 * It was not worth any locking to calculate that statistic,
	 * but it might therefore sometimes be negative: conceal that.
	 */
	if (ksm_pages_volatile < 0)
		ksm_pages_volatile = 0;
	return sysfs_emit(buf, "%ld\n", ksm_pages_volatile);
}
KSM_ATTR_RO(pages_volatile);

static ssize_t stable_node_dups_show(struct kobject *kobj,
				     struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", ksm_stable_node_dups);
}
KSM_ATTR_RO(stable_node_dups);

static ssize_t stable_node_chains_show(struct kobject *kobj,
				       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", ksm_stable_node_chains);
}
KSM_ATTR_RO(stable_node_chains);

static ssize_t
stable_node_chains_prune_millisecs_show(struct kobject *kobj,
					struct kobj_attribute *attr,
					char *buf)
{
	return sysfs_emit(buf, "%u\n", ksm_stable_node_chains_prune_millisecs);
}

static ssize_t
stable_node_chains_prune_millisecs_store(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 const char *buf, size_t count)
{
	unsigned int msecs;
	int err;

	err = kstrtouint(buf, 10, &msecs);
	if (err)
		return -EINVAL;

	ksm_stable_node_chains_prune_millisecs = msecs;

	return count;
}
KSM_ATTR(stable_node_chains_prune_millisecs);

static ssize_t full_scans_show(struct kobject *kobj,
			       struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", ksm_scan.seqnr);
}
KSM_ATTR_RO(full_scans);

/* Sysfs interface for DSA */ 
static ssize_t dsa_on_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", use_dsa);
}

static ssize_t dsa_on_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;
	if (on > 1)
		return -EINVAL;

	if (on == use_dsa)
		return count;

	if (on)
		ksm_dsa_init();
	else
		ksm_dsa_exit();

	return count;
}
static struct kobj_attribute dsa_on_attr = __ATTR_RW(dsa_on);

static ssize_t dsa_cpu_hybrid_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", enable_dsa_hybrid);
}

static ssize_t dsa_cpu_hybrid_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;
	if (on > 1)
		return -EINVAL;

	if (on && !use_dsa) {
		pr_err("Should enable dsa first!\n");
		return -EINVAL;
	}

	enable_dsa_hybrid = on;

	return count;
}
static struct kobj_attribute dsa_cpu_hybrid_mode_attr = __ATTR_RW(dsa_cpu_hybrid_mode);

static ssize_t dsa_hash_on_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", use_dsa_for_hash);
}

static ssize_t dsa_hash_on_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;
	if (on > 1)
		return -EINVAL;

	use_dsa_for_hash = on;

	return count;
}
static struct kobj_attribute dsa_hash_on_attr = __ATTR_RW(dsa_hash_on);

static ssize_t dsa_completion_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", dsa_completion_mode);
}
static ssize_t dsa_completion_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;
	if (on >= NUM_DSA_COMPL)
		return -EINVAL;

	dsa_completion_mode = on;

	return count;
}
static struct kobj_attribute dsa_completion_mode_attr = __ATTR_RW(dsa_completion_mode);

static ssize_t dsa_polling_wait_ns_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", dsa_polling_wait_ns);
}
static ssize_t dsa_polling_wait_ns_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;

	dsa_polling_wait_ns = on;

	return count;
}
static struct kobj_attribute dsa_polling_wait_ns_attr = __ATTR_RW(dsa_polling_wait_ns);

static ssize_t dsa_sched_us_start_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", dsa_sched_us_start);
}
static ssize_t dsa_sched_us_start_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;

	dsa_sched_us_start = on;

	return count;
}
static struct kobj_attribute dsa_sched_us_start_attr = __ATTR_RW(dsa_sched_us_start);

static ssize_t dsa_sched_us_end_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", dsa_sched_us_end);
}
static ssize_t dsa_sched_us_end_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;

	dsa_sched_us_end = on;

	return count;
}
static struct kobj_attribute dsa_sched_us_end_attr = __ATTR_RW(dsa_sched_us_end);

static ssize_t batch_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", batch_mode);
}
static ssize_t batch_mode_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;

	if (ksm_run == KSM_RUN_MERGE) {
		pr_err("run is 1. it should be 0 or 2\n");
		return -EINVAL;
	}

	if (ksm_pages_shared != 0 || ksm_pages_unshared != 0) {
		pr_err("You should unmerge first\n");
		return -EINVAL;
	}
	/*
	 * bitmap
	 *   if 0-bit is set -> CANDIDATE mode is on
	 *   if 1-bit is set -> SPECULATIVE mode is on
	 *   
	 *   if any bit isn't set -> No batch
	 *
	 *   b'11  -> CANDIDATE + SPEC
	 *   b'10  -> SPECULATIVE only
	 */

	batch_mode = on;

	return count;
}
static struct kobj_attribute batch_mode_attr = __ATTR_RW(batch_mode);

static ssize_t batch_size_for_tree_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", tree_batch_size);
}
static ssize_t batch_size_for_tree_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int size;
	int err, i;
	int level;
	err = kstrtouint(buf, 10, &size);
	if (err)
		return -EINVAL;
	if (check_batch_mode(CANDIDATE) 
	     && (size * candidate_batch_size > MAX_KSM_BATCH_SIZE))
		return -EINVAL;

	if (ksm_run == KSM_RUN_MERGE) {
		pr_err("run is 1. it should be 0 or 2\n");
		return -EINVAL;
	}

	if (ksm_pages_shared != 0 || ksm_pages_unshared != 0) {
		pr_err("You should unmerge first\n");
		return -EINVAL;
	}

	tree_batch_size = size;

	//calculate spec_batch_level & spec_batch_size
	level = 1;
	i = 2;
	for (;;) {
		if ((1<<i)-1 > size)
			break;
		level = i;
		i++;
	}
	spec_batch_level = level;
	spec_batch_size = (1<<level) - 1;

	return count;
}
static struct kobj_attribute batch_size_for_tree_attr = __ATTR_RW(batch_size_for_tree);

static ssize_t batch_size_for_candidate_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", candidate_batch_size);
}
static ssize_t batch_size_for_candidate_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int size;
	int err;
	err = kstrtouint(buf, 10, &size);
	if (err)
		return -EINVAL;
	if (check_batch_mode(SPECULATIVE)
		&& (size * tree_batch_size > MAX_KSM_BATCH_SIZE))
		return -EINVAL;

	candidate_batch_size = size;

	return count;
}
static struct kobj_attribute batch_size_for_candidate_attr = __ATTR_RW(batch_size_for_candidate);

static ssize_t ksm_debug_on_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%lu\n", enable_ksm_debug);
}
static ssize_t ksm_debug_on_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	unsigned int on;
	int err;
	err = kstrtouint(buf, 10, &on);
	if (err)
		return -EINVAL;
	if (on > 4)
		return -EINVAL;

	/*
	 * 0: Disable KSM Debug
	 * 1: Enable KSM Debug
	 * 2: Reset KSM Debug stat
	 * 3: Show KSM Debug stat
	 * 4: Show CPU compare stat
	 */
	if (on == 2)
		ksm_debug_stat_reset();
	else if (on == 3)
		ksm_debug_stat_show();
	else if (on == 4)
		ksm_cpu_compare_stat_show();
	else
		enable_ksm_debug = on;

	return count;
}
static struct kobj_attribute ksm_debug_on_attr = __ATTR_RW(ksm_debug_on);

static struct attribute *ksm_attrs[] = {
	&sleep_millisecs_attr.attr,
	&pages_to_scan_attr.attr,
	&run_attr.attr,
	&pages_shared_attr.attr,
	&pages_sharing_attr.attr,
	&pages_unshared_attr.attr,
	&pages_volatile_attr.attr,
	&full_scans_attr.attr,
#ifdef CONFIG_NUMA
	&merge_across_nodes_attr.attr,
#endif
	&max_page_sharing_attr.attr,
	&stable_node_chains_attr.attr,
	&stable_node_dups_attr.attr,
	&stable_node_chains_prune_millisecs_attr.attr,
	&use_zero_pages_attr.attr,
	&dsa_on_attr.attr,
	&dsa_cpu_hybrid_mode_attr.attr,
	&dsa_completion_mode_attr.attr,
	&dsa_polling_wait_ns_attr.attr,
	&dsa_sched_us_start_attr.attr,
	&dsa_sched_us_end_attr.attr,
	&batch_mode_attr.attr,
	&batch_size_for_tree_attr.attr,
	&batch_size_for_candidate_attr.attr,
	&ksm_debug_on_attr.attr,
        &dsa_hash_on_attr.attr,
	NULL,
};

static const struct attribute_group ksm_attr_group = {
	.attrs = ksm_attrs,
	.name = "ksm",
};

static struct kobject *ksm_debug_subdirs[NUM_KSM_DEBUG_STAT];

static ssize_t ksm_debug_num_show(struct kobject *kobj, 
					struct kobj_attribute *attr, char *buf)
{
	int i;

	for (i = 0; i < NUM_KSM_DEBUG_STAT; i++) {
		if (ksm_debug_subdirs[i] == kobj) {
			break;
		}
	}

	return sprintf(buf, "%lu\n", ksm_debug_stat.num[i]);
}

static ssize_t ksm_debug_total_show(struct kobject *kobj, 
					struct kobj_attribute *attr, char *buf)
{
	int i;

	for (i = 0; i < NUM_KSM_DEBUG_STAT; i++) {
		if (ksm_debug_subdirs[i] == kobj) {
			break;
		}
	}

	return sprintf(buf, "%lu\n", ksm_debug_stat.total[i]);
}

static ssize_t ksm_debug_avg_show(struct kobject *kobj, 
					struct kobj_attribute *attr, char *buf)
{
	int i;

	for (i = 0; i < NUM_KSM_DEBUG_STAT; i++) {
		if (ksm_debug_subdirs[i] == kobj) {
			break;
		}
	}

	if (ksm_debug_stat.num[i] == 0)
		ksm_debug_stat.avg[i] = 0;
	else
		ksm_debug_stat.avg[i] = ksm_debug_stat.total[i] / ksm_debug_stat.num[i];

	return sprintf(buf, "%lu\n", ksm_debug_stat.avg[i]);
}

static struct kobj_attribute ksm_debug_num_attr = __ATTR(num, 0444, ksm_debug_num_show, NULL);
static struct kobj_attribute ksm_debug_total_attr = __ATTR(total_cycles, 0444, ksm_debug_total_show, NULL);
static struct kobj_attribute ksm_debug_avg_attr = __ATTR(avg_cycles, 0444, ksm_debug_avg_show, NULL);

static struct attribute *ksm_debug_attrs[] = {
	&ksm_debug_num_attr.attr,
	&ksm_debug_total_attr.attr,
	&ksm_debug_avg_attr.attr,
	NULL,
};

static struct attribute_group ksm_debug_attr_group = {
	.attrs = ksm_debug_attrs,
};
#endif /* CONFIG_SYSFS */

static int __init ksm_init(void)
{
	struct task_struct *ksm_thread;
	struct kobject *ksm_debug_sysfs;
	int err, i;

	/* The correct value depends on page size and endianness */
	zero_checksum = calc_checksum(ZERO_PAGE(0));
	/* Default to false for backwards compatibility */
	ksm_use_zero_pages = false;

	err = ksm_slab_init();
	if (err)
		goto out;

	ksm_thread = kthread_run(ksm_scan_thread, NULL, "ksmd");
	if (IS_ERR(ksm_thread)) {
		pr_err("ksm: creating kthread failed\n");
		err = PTR_ERR(ksm_thread);
		goto out_free;
	}

#ifdef CONFIG_SYSFS
	err = sysfs_create_group(mm_kobj, &ksm_attr_group);
	if (err) {
		pr_err("ksm: register sysfs failed\n");
		kthread_stop(ksm_thread);
		goto out_free;
	}
	
	ksm_debug_sysfs = kobject_create_and_add("ksm_debug", mm_kobj);
	if (!ksm_debug_sysfs) {
		pr_err("ksm_debug: register sysfs failed\n");
		kthread_stop(ksm_thread);
		goto out_free;
	}

	for (i = 0; i < NUM_KSM_DEBUG_STAT; i++) {
		ksm_debug_subdirs[i] = kobject_create_and_add(ksm_debug_stat_strs[i], ksm_debug_sysfs);
		if (!ksm_debug_subdirs[i]) {
			pr_err("ksm_debug: failed to create %s\n", ksm_debug_stat_strs[i]);
			kthread_stop(ksm_thread);
			goto out_free;
		}

		err = sysfs_create_group(ksm_debug_subdirs[i], &ksm_debug_attr_group);
		if (err) {
			pr_err("ksm_debug: failed to create files at %s\n", ksm_debug_stat_strs[i]);
			kthread_stop(ksm_thread);
			goto out_free;
		}
	}
#else
	ksm_run = KSM_RUN_MERGE;	/* no way for user to start it */

#endif /* CONFIG_SYSFS */

#ifdef CONFIG_MEMORY_HOTREMOVE
	/* There is no significance to this priority 100 */
	hotplug_memory_notifier(ksm_memory_callback, KSM_CALLBACK_PRI);
#endif
	return 0;

out_free:
	ksm_slab_free();
out:
	return err;
}
subsys_initcall(ksm_init);
