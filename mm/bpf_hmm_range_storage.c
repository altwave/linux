// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2019 Facebook  */
#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_hmm_range_storage.h>
#include <linux/hmm.h>
#include <linux/filter.h>
#include <uapi/linux/btf.h>

static atomic_t cache_idx;

#define HMM_RANGE_STORAGE_CREATE_FLAG_MASK					\
	(BPF_F_NO_PREALLOC | BPF_F_CLONE)


struct range_update {
	struct hmm_range range;
	unsigned long start;
	unsigned long end;
	unsigned long value;
};

struct bucket {
	struct hlist_head list;
	raw_spinlock_t lock;
};

/* Thp map is not the primary owner of a bpf_sk_storage_elem.
 * Instead, the sk->sk_bpf_storage is.
 *
 * The map (bpf_sk_storage_map) is for two purposes
 * 1. Define the size of the "sk local storage".  It is
 *    the map's value_size.
 *
 * 2. Maintain a list to keep track of all elems such
 *    that they can be cleaned up during the map destruction.
 *
 * When a bpf local storage is being looked up for a
 * particular sk,  the "bpf_map" pointer is actually used
 * as the "key" to search in the list of elem in
 * sk->sk_bpf_storage.
 *
 * Hence, consider sk->sk_bpf_storage is the mini-map
 * with the "bpf_map" pointer as the searching key.
 */
struct bpf_hmm_range_storage_map {
	struct bpf_map map;
	/* Lookup elem does not require accessing the map.
	 *
	 * Updating/Deleting requires a bucket lock to
	 * link/unlink the elem from the map.  Having
	 * multiple buckets to improve contention.
	 */
	struct bucket *buckets;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
};

struct bpf_hmm_range_storage_data {
	/* smap is used as the searching key when looking up
	 * from sk->sk_bpf_storage.
	 *
	 * Put it in the same cacheline as the data to minimize
	 * the number of cachelines access during the cache hit case.
	 */
	struct bpf_hmm_range_storage_map __rcu *smap;
	u8 data[] __aligned(8);
};

/* Linked to bpf_sk_storage and bpf_sk_storage_map */
struct bpf_hmm_range_storage_elem {
	struct hlist_node map_node;	/* Linked to bpf_sk_storage_map */
	struct hlist_node snode;	/* Linked to bpf_sk_storage */
	struct bpf_hmm_range_storage __rcu *hmm_range_storage;
	struct rcu_head rcu;
	/* 8 bytes hole */
	/* The data is stored in aother cacheline to minimize
	 * the number of cachelines access during a cache hit.
	 */
	struct bpf_hmm_range_storage_data sdata ____cacheline_aligned;
};

#define SELEM(_SDATA) container_of((_SDATA), struct bpf_hmm_range_storage_elem, sdata)
#define SDATA(_SELEM) (&(_SELEM)->sdata)
#define BPF_HMM_RANGE_STORAGE_CACHE_SIZE	16

struct bpf_hmm_range_storage {
	struct bpf_hmm_range_storage_data __rcu *cache[BPF_HMM_RANGE_STORAGE_CACHE_SIZE];
	struct hlist_head list;	/* List of bpf_sk_storage_elem */
	struct hmm_range *range;	/* The sk that owns the the above "list" of
				 * bpf_sk_storage_elem.
				 */
	struct rcu_head rcu;
	raw_spinlock_t lock;	/* Protect adding/removing from the "list" */
};

static struct bucket *select_bucket(struct bpf_hmm_range_storage_map *smap,
				    struct bpf_hmm_range_storage_elem *selem)
{
	return &smap->buckets[hash_ptr(selem, smap->bucket_log)];
}

static bool selem_linked_to_hmm_range(const struct bpf_hmm_range_storage_elem *selem)
{
	return !hlist_unhashed(&selem->snode);
}

static bool selem_linked_to_map(const struct bpf_hmm_range_storage_elem *selem)
{
	return !hlist_unhashed(&selem->map_node);
}

static struct bpf_hmm_range_storage_elem *selem_alloc(struct bpf_hmm_range_storage_map *smap,
					       struct hmm_range *range, void *value)
{
	struct bpf_hmm_range_storage_elem *selem;

	selem = kzalloc(smap->elem_size, GFP_ATOMIC | __GFP_NOWARN);
	if (selem) {
		if (value)
			memcpy(SDATA(selem)->data, value, smap->map.value_size);
		return selem;
	}

	return NULL;
}

/* sk_storage->lock must be held and selem->sk_storage == sk_storage.
 * The caller must ensure selem->smap is still valid to be
 * dereferenced for its smap->elem_size and smap->cache_idx.
 */
static bool __selem_unlink_hmm_range(struct bpf_hmm_range_storage *range_storage,
			      struct bpf_hmm_range_storage_elem *selem)
{
	struct bpf_hmm_range_storage_map *smap;
	bool free_hmm_range_storage;
	struct hmm_range *range;

	smap = rcu_dereference(SDATA(selem)->smap);
	range = range_storage->range;

	free_hmm_range_storage = hlist_is_singular_node(&selem->snode,
						 &range_storage->list);
	if (free_hmm_range_storage) {
		range_storage->range = NULL;
		/* After this RCU_INIT, sk may be freed and cannot be used */
		RCU_INIT_POINTER(range->hmm_range_bpf_storage, NULL);

		/* sk_storage is not freed now.  sk_storage->lock is
		 * still held and raw_spin_unlock_bh(&sk_storage->lock)
		 * will be done by the caller.
		 *
		 * Although the unlock will be done under
		 * rcu_read_lock(),  it is more intutivie to
		 * read if kfree_rcu(sk_storage, rcu) is done
		 * after the raw_spin_unlock_bh(&sk_storage->lock).
		 *
		 * Hence, a "bool free_sk_storage" is returned
		 * to the caller which then calls the kfree_rcu()
		 * after unlock.
		 */
	}
	hlist_del_init_rcu(&selem->snode);
	if (rcu_access_pointer(range_storage->cache[smap->cache_idx]) ==
	    SDATA(selem))
		RCU_INIT_POINTER(range_storage->cache[smap->cache_idx], NULL);

	kfree_rcu(selem, rcu);

	return free_hmm_range_storage;
}

static void selem_unlink_hmm_range(struct bpf_hmm_range_storage_elem *selem)
{
	struct bpf_hmm_range_storage *range_storage;
	bool free_hmm_range_storage = false;

	if (unlikely(!selem_linked_to_hmm_range(selem)))
		/* selem has already been unlinked from sk */
		return;

	range_storage = rcu_dereference(selem->hmm_range_storage);
	raw_spin_lock_bh(&range_storage->lock);
	if (likely(selem_linked_to_hmm_range(selem)))
		free_hmm_range_storage = __selem_unlink_hmm_range(range_storage, selem);
	raw_spin_unlock_bh(&range_storage->lock);

	if (free_hmm_range_storage)
		kfree_rcu(range_storage, rcu);
}

static void __selem_link_hmm_range(struct bpf_hmm_range_storage *range_storage,
			    struct bpf_hmm_range_storage_elem *selem)
{
	RCU_INIT_POINTER(selem->hmm_range_storage, range_storage);
	hlist_add_head(&selem->snode, &range_storage->list);
}

static void selem_unlink_map(struct bpf_hmm_range_storage_elem *selem)
{
	struct bpf_hmm_range_storage_map *smap;
	struct bucket *b;

	if (unlikely(!selem_linked_to_map(selem)))
		/* selem has already be unlinked from smap */
		return;

	smap = rcu_dereference(SDATA(selem)->smap);
	b = select_bucket(smap, selem);
	raw_spin_lock_bh(&b->lock);
	if (likely(selem_linked_to_map(selem)))
		hlist_del_init_rcu(&selem->map_node);
	raw_spin_unlock_bh(&b->lock);
}

static void selem_link_map(struct bpf_hmm_range_storage_map *smap,
			   struct bpf_hmm_range_storage_elem *selem)
{
	struct bucket *b = select_bucket(smap, selem);

	raw_spin_lock_bh(&b->lock);
	RCU_INIT_POINTER(SDATA(selem)->smap, smap);
	hlist_add_head_rcu(&selem->map_node, &b->list);
	raw_spin_unlock_bh(&b->lock);
}

static void selem_unlink(struct bpf_hmm_range_storage_elem *selem)
{
	/* Always unlink from map before unlinking from sk_storage
	 * because selem will be freed after successfully unlinked from
	 * the sk_storage.
	 */
	selem_unlink_map(selem);
	selem_unlink_hmm_range(selem);
}

static struct bpf_hmm_range_storage_data *
__hmm_range_storage_lookup(struct bpf_hmm_range_storage *range_storage,
		    struct bpf_hmm_range_storage_map *smap,
		    bool cacheit_lockit)
{
	struct bpf_hmm_range_storage_data *sdata;
	struct bpf_hmm_range_storage_elem *selem;

	/* Fast path (cache hit) */
	sdata = rcu_dereference(range_storage->cache[smap->cache_idx]);
	if (sdata && rcu_access_pointer(sdata->smap) == smap)
		return sdata;

	/* Slow path (cache miss) */
	hlist_for_each_entry_rcu(selem, &range_storage->list, snode)
		if (rcu_access_pointer(SDATA(selem)->smap) == smap)
			break;

	if (!selem)
		return NULL;

	sdata = SDATA(selem);
	if (cacheit_lockit) {
		/* spinlock is needed to avoid racing with the
		 * parallel delete.  Otherwise, publishing an already
		 * deleted sdata to the cache will become a use-after-free
		 * problem in the next __sk_storage_lookup().
		 */
		raw_spin_lock_bh(&range_storage->lock);
		if (selem_linked_to_hmm_range(selem))
			rcu_assign_pointer(range_storage->cache[smap->cache_idx],
					   sdata);
		raw_spin_unlock_bh(&range_storage->lock);
	}

	return sdata;
}

static struct bpf_hmm_range_storage_data *
hmm_range_storage_lookup(struct hmm_range *range, struct bpf_map *map, bool cacheit_lockit)
{
	struct bpf_hmm_range_storage *range_storage;
	struct bpf_hmm_range_storage_map *smap;

	range_storage = rcu_dereference(range->hmm_range_bpf_storage);
	if (!range_storage)
		return NULL;

	smap = (struct bpf_hmm_range_storage_map *)map;
	return __hmm_range_storage_lookup(range_storage, smap, cacheit_lockit);
}

static int check_flags(const struct bpf_hmm_range_storage_data *old_sdata,
		       u64 map_flags)
{
	if (old_sdata && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		/* elem already exists */
		return -EEXIST;

	if (!old_sdata && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		/* elem doesn't exist, cannot update it */
		return -ENOENT;

	return 0;
}

static int hmm_range_storage_alloc(struct hmm_range *range,
			    struct bpf_hmm_range_storage_map *smap,
			    struct bpf_hmm_range_storage_elem *first_selem)
{
	struct bpf_hmm_range_storage *prev_range_storage, *range_storage;
	int err;

	//printk(KERN_INFO "Called hmm_range_storage_alloc\n");

	range_storage = kzalloc(sizeof(*range_storage), GFP_ATOMIC | __GFP_NOWARN);
	if (!range_storage) {
		//printk(KERN_INFO "storage_alloc err 0\n");
		err = -ENOMEM;
		goto uncharge;
	}
	INIT_HLIST_HEAD(&range_storage->list);
	raw_spin_lock_init(&range_storage->lock);
	range_storage->range = range;

	__selem_link_hmm_range(range_storage, first_selem);
	selem_link_map(smap, first_selem);
	/* Publish sk_storage to sk.  sk->sk_lock cannot be acquired.
	 * Hence, atomic ops is used to set sk->sk_bpf_storage
	 * from NULL to the newly allocated sk_storage ptr.
	 *
	 * From now on, the sk->sk_bpf_storage pointer is protected
	 * by the sk_storage->lock.  Hence,  when freeing
	 * the sk->sk_bpf_storage, the sk_storage->lock must
	 * be held before setting sk->sk_bpf_storage to NULL.
	 */
	prev_range_storage = cmpxchg((struct bpf_hmm_range_storage **)&range->hmm_range_bpf_storage,
				  NULL, range_storage);
	if (unlikely(prev_range_storage)) {
		selem_unlink_map(first_selem);
		err = -EAGAIN;
		goto uncharge;

		/* Note that even first_selem was linked to smap's
		 * bucket->list, first_selem can be freed immediately
		 * (instead of kfree_rcu) because
		 * bpf_sk_storage_map_free() does a
		 * synchronize_rcu() before walking the bucket->list.
		 * Hence, no one is accessing selem from the
		 * bucket->list under rcu_read_lock().
		 */
	}

	return 0;

uncharge:
	//printk(KERN_INFO "storage_alloc err uncharge\n");
	kfree(range_storage);
	return err;
}

/* sk cannot be going away because it is linking new elem
 * to sk->sk_bpf_storage. (i.e. sk->sk_refcnt cannot be 0).
 * Otherwise, it will become a leak (and other memory issues
 * during map destruction).
 */
static struct bpf_hmm_range_storage_data *hmm_range_storage_update(struct hmm_range *range,
						     struct bpf_map *map,
						     void *value,
						     u64 map_flags)
{
	struct bpf_hmm_range_storage_data *old_sdata = NULL;
	struct bpf_hmm_range_storage_elem *selem;
	struct bpf_hmm_range_storage *range_storage;
	struct bpf_hmm_range_storage_map *smap;
	int err;
	//printk(KERN_INFO "Called storage_update\n");

	/* BPF_EXIST and BPF_NOEXIST cannot be both set */
	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST) ||
	    /* BPF_F_LOCK can only be used in a value with spin_lock */
	    unlikely((map_flags & BPF_F_LOCK) && !map_value_has_spin_lock(map))) {
		//printk(KERN_INFO "storage update err 1\n"); 
		return ERR_PTR(-EINVAL);
	}

	smap = (struct bpf_hmm_range_storage_map *)map;
	range_storage = rcu_dereference(range->hmm_range_bpf_storage);
	if (!range_storage || hlist_empty(&range_storage->list)) {
		//printk(KERN_INFO "storage update first elem\n"); 
		/* Very first elem for this sk */
		err = check_flags(NULL, map_flags);
		if (err) {
			//printk(KERN_INFO "storage update err 2\n"); 
			return ERR_PTR(err);
		}

		selem = selem_alloc(smap, range, value);
		if (!selem) {
			//printk(KERN_INFO "storage update err 3\n"); 
			return ERR_PTR(-ENOMEM);
		}

		err = hmm_range_storage_alloc(range, smap, selem);
		if (err) {
			//printk(KERN_INFO "storage update err 4\n"); 
			kfree(selem);
			return ERR_PTR(err);
		}

		return SDATA(selem);
	}

	if ((map_flags & BPF_F_LOCK) && !(map_flags & BPF_NOEXIST)) {
		/* Hoping to find an old_sdata to do inline update
		 * such that it can avoid taking the sk_storage->lock
		 * and changing the lists.
		 */
		//printk(KERN_INFO "storage update check 2\n"); 
		old_sdata = __hmm_range_storage_lookup(range_storage, smap, false);
		err = check_flags(old_sdata, map_flags);
		if (err)
			return ERR_PTR(err);
		if (old_sdata && selem_linked_to_hmm_range(SELEM(old_sdata))) {
			//printk(KERN_INFO "Going to copy map value 1\n");
			copy_map_value_locked(map, old_sdata->data,
					      value, false);
			return old_sdata;
		}
	}

	raw_spin_lock_bh(&range_storage->lock);

	/* Recheck sk_storage->list under sk_storage->lock */
	if (unlikely(hlist_empty(&range_storage->list))) {
		/* A parallel del is happening and sk_storage is going
		 * away.  It has just been checked before, so very
		 * unlikely.  Return instead of retry to keep things
		 * simple.
		 */
		//printk(KERN_INFO "storage update list empty\n"); 
		err = -EAGAIN;
		goto unlock_err;
	}

	old_sdata = __hmm_range_storage_lookup(range_storage, smap, false);
	err = check_flags(old_sdata, map_flags);
	if (err) {
		//printk(KERN_INFO "storage update err 5\n"); 
		goto unlock_err;
	}

	if (old_sdata && (map_flags & BPF_F_LOCK)) {
		//printk(KERN_INFO "Going to copy map value 2\n");
		copy_map_value_locked(map, old_sdata->data, value, false);
		selem = SELEM(old_sdata);
		goto unlock;
	}

	/* sk_storage->lock is held.  Hence, we are sure
	 * we can unlink and uncharge the old_sdata successfully
	 * later.  Hence, instead of charging the new selem now
	 * and then uncharge the old selem later (which may cause
	 * a potential but unnecessary charge failure),  avoid taking
	 * a charge at all here (the "!old_sdata" check) and the
	 * old_sdata will not be uncharged later during __selem_unlink_sk().
	 */
	selem = selem_alloc(smap, range, value);
	if (!selem) {
	//	printk(KERN_INFO "storage update err 6\n"); 
		err = -ENOMEM;
		goto unlock_err;
	}

	/* First, link the new selem to the map */
	selem_link_map(smap, selem);

	/* Second, link (and publish) the new selem to sk_storage */
	__selem_link_hmm_range(range_storage, selem);

	/* Third, remove old selem, SELEM(old_sdata) */
	if (old_sdata) {
		selem_unlink_map(SELEM(old_sdata));
		__selem_unlink_hmm_range(range_storage, SELEM(old_sdata));
	}

unlock:
//	printk(KERN_INFO "storage update unlock\n"); 
	raw_spin_unlock_bh(&range_storage->lock);
	return SDATA(selem);

unlock_err:
//	printk(KERN_INFO "storage update unlock err\n"); 
	raw_spin_unlock_bh(&range_storage->lock);
	return ERR_PTR(err);
}

static int hmm_range_storage_delete(struct hmm_range *range, struct bpf_map *map)
{
	struct bpf_hmm_range_storage_data *sdata;

	sdata = hmm_range_storage_lookup(range, map, false);
	if (!sdata)
		return -ENOENT;

	selem_unlink(SELEM(sdata));

	return 0;
}

/* Called by __sk_destruct() & bpf_sk_storage_clone() */
void bpf_hmm_range_storage_free(struct hmm_range *range)
{
	struct bpf_hmm_range_storage_elem *selem;
	struct bpf_hmm_range_storage *range_storage;
	bool free_hmm_range_storage = false;
	struct hlist_node *n;

	rcu_read_lock();
	range_storage = rcu_dereference(range->hmm_range_bpf_storage);
	if (!range_storage) {
		rcu_read_unlock();
		return;
	}

	/* Netiher the bpf_prog nor the bpf-map's syscall
	 * could be modifying the sk_storage->list now.
	 * Thus, no elem can be added-to or deleted-from the
	 * sk_storage->list by the bpf_prog or by the bpf-map's syscall.
	 *
	 * It is racing with bpf_sk_storage_map_free() alone
	 * when unlinking elem from the sk_storage->list and
	 * the map's bucket->list.
	 */
	raw_spin_lock_bh(&range_storage->lock);
	hlist_for_each_entry_safe(selem, n, &range_storage->list, snode) {
		/* Always unlink from map before unlinking from
		 * sk_storage.
		 */
		selem_unlink_map(selem);
		free_hmm_range_storage = __selem_unlink_hmm_range(range_storage, selem);
	}
	raw_spin_unlock_bh(&range_storage->lock);
	rcu_read_unlock();

	if (free_hmm_range_storage)
		kfree_rcu(range_storage, rcu);
}

static void bpf_hmm_range_storage_map_free(struct bpf_map *map)
{
	struct bpf_hmm_range_storage_elem *selem;
	struct bpf_hmm_range_storage_map *smap;
	struct bucket *b;
	unsigned int i;

	smap = (struct bpf_hmm_range_storage_map *)map;

	/* Note that this map might be concurrently cloned from
	 * bpf_sk_storage_clone. Wait for any existing bpf_sk_storage_clone
	 * RCU read section to finish before proceeding. New RCU
	 * read sections should be prevented via bpf_map_inc_not_zero.
	 */
	synchronize_rcu();

	/* bpf prog and the userspace can no longer access this map
	 * now.  No new selem (of this map) can be added
	 * to the sk->sk_bpf_storage or to the map bucket's list.
	 *
	 * The elem of this map can be cleaned up here
	 * or
	 * by bpf_sk_storage_free() during __sk_destruct().
	 */
	for (i = 0; i < (1U << smap->bucket_log); i++) {
		b = &smap->buckets[i];

		rcu_read_lock();
		/* No one is adding to b->list now */
		while ((selem = hlist_entry_safe(rcu_dereference_raw(hlist_first_rcu(&b->list)),
						 struct bpf_hmm_range_storage_elem,
						 map_node))) {
			selem_unlink(selem);
			cond_resched_rcu();
		}
		rcu_read_unlock();
	}

	/* bpf_sk_storage_free() may still need to access the map.
	 * e.g. bpf_sk_storage_free() has unlinked selem from the map
	 * which then made the above while((selem = ...)) loop
	 * exited immediately.
	 *
	 * However, the bpf_sk_storage_free() still needs to access
	 * the smap->elem_size to do the uncharging in
	 * __selem_unlink_sk().
	 *
	 * Hence, wait another rcu grace period for the
	 * bpf_sk_storage_free() to finish.
	 */
	synchronize_rcu();

	kvfree(smap->buckets);
	kfree(map);
}

/* U16_MAX is much more than enough for sk local storage
 * considering a tcp_sock is ~2k.
 */
#define MAX_VALUE_SIZE							\
	min_t(u32,							\
	      (KMALLOC_MAX_SIZE - MAX_BPF_STACK - sizeof(struct bpf_hmm_range_storage_elem)), \
	      (U16_MAX - sizeof(struct bpf_hmm_range_storage_elem)))

static int bpf_hmm_range_storage_map_alloc_check(union bpf_attr *attr)
{
	if (attr->map_flags & ~HMM_RANGE_STORAGE_CREATE_FLAG_MASK ||
	    !(attr->map_flags & BPF_F_NO_PREALLOC) ||
	    attr->max_entries ||
	    attr->key_size != sizeof(int) || !attr->value_size ||
	    /* Enforce BTF for userspace sk dumping */
	    !attr->btf_key_type_id || !attr->btf_value_type_id)
		return -EINVAL;

	if (!bpf_capable())
		return -EPERM;

	if (attr->value_size > MAX_VALUE_SIZE)
		return -E2BIG;

	return 0;
}

static struct bpf_map *bpf_hmm_range_storage_map_alloc(union bpf_attr *attr)
{
	struct bpf_hmm_range_storage_map *smap;
	unsigned int i;
	u32 nbuckets;
	u64 cost;
	int ret;

	smap = kzalloc(sizeof(*smap), GFP_USER | __GFP_NOWARN);
	if (!smap)
		return ERR_PTR(-ENOMEM);
	bpf_map_init_from_attr(&smap->map, attr);

	nbuckets = roundup_pow_of_two(num_possible_cpus());
	/* Use at least 2 buckets, select_bucket() is undefined behavior with 1 bucket */
	nbuckets = max_t(u32, 2, nbuckets);
	smap->bucket_log = ilog2(nbuckets);
	cost = sizeof(*smap->buckets) * nbuckets + sizeof(*smap);

	ret = bpf_map_charge_init(&smap->map.memory, cost);
	if (ret < 0) {
		kfree(smap);
		return ERR_PTR(ret);
	}

	smap->buckets = kvcalloc(sizeof(*smap->buckets), nbuckets,
				 GFP_USER | __GFP_NOWARN);
	if (!smap->buckets) {
		bpf_map_charge_finish(&smap->map.memory);
		kfree(smap);
		return ERR_PTR(-ENOMEM);
	}

	for (i = 0; i < nbuckets; i++) {
		INIT_HLIST_HEAD(&smap->buckets[i].list);
		raw_spin_lock_init(&smap->buckets[i].lock);
	}

	smap->elem_size = sizeof(struct bpf_hmm_range_storage_elem) + attr->value_size;
	smap->cache_idx = (unsigned int)atomic_inc_return(&cache_idx) %
		BPF_HMM_RANGE_STORAGE_CACHE_SIZE;

	return &smap->map;
}

static int notsupp_get_next_key(struct bpf_map *map, void *key,
				void *next_key)
{
	return -ENOTSUPP;
}

static int bpf_hmm_range_storage_map_check_btf(const struct bpf_map *map,
					const struct btf *btf,
					const struct btf_type *key_type,
					const struct btf_type *value_type)
{
	u32 int_data;

	if (BTF_INFO_KIND(key_type->info) != BTF_KIND_INT)
		return -EINVAL;

	int_data = *(u32 *)(key_type + 1);
	if (BTF_INT_BITS(int_data) != 32 || BTF_INT_OFFSET(int_data))
		return -EINVAL;

	return 0;
}

static struct hmm_range *mm_walk_range_lookup(unsigned long addr) {
	struct mm_walk *walk;
	struct hmm_vma_walk *hmm_vma_walk;
	struct hmm_range *range = NULL;
	//printk(KERN_INFO "Called mm_walk_range_lookup\n");
	
	walk = (struct mm_walk *)addr;
	if (walk && walk->private) {
		hmm_vma_walk = (struct hmm_vma_walk *)walk->private;
		if (hmm_vma_walk) {
			range = hmm_vma_walk->range;
	//		printk(KERN_INFO "Found hmm_vma_walk\n");
			if (range) {
	//			printk(KERN_INFO "Found range, range->start=%lu\n", range->start);
			}
		}
	}
	
	return range;
}

static void *bpf_mm_walk_hmm_range_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_hmm_range_storage_data *sdata;
	struct hmm_range *range;
	struct hmm_range *range2;
	unsigned long addr = *(unsigned long *)key;
	int err = 0;
	//printk(KERN_INFO "Lookup_elem called\n");

	range = mm_walk_range_lookup(addr);
	if (range) {
	//	printk(KERN_INFO "Found range, range->start=%lu\n", range->start);
		sdata = hmm_range_storage_lookup(range, map, true);
		//sockfd_put(sock);
		
		return sdata ? sdata->data : NULL;
	}

	return ERR_PTR(err);
}

static int storage_hmm_pfns_fill(unsigned long addr, unsigned long end,
			 struct hmm_range *range, unsigned long cpu_flags)
{
	//printk(KERN_INFO "storage_hmm_pfns_fill called....\n");
	unsigned long i = (addr - range->start) >> PAGE_SHIFT;
	//printk(KERN_INFO "storage_hmm_pfns_fill, i=%lu, addr=%lu, end=%lu, range->start=%lu\n", i, addr, end, range->start);

	for (; addr < end; addr += PAGE_SIZE, i++)
		range->hmm_pfns[i] = cpu_flags;
	
	//printk(KERN_INFO "storage_hmm_pfns_fill done!\n");
	return 0;
}


static int bpf_mm_walk_hmm_range_storage_update_elem(struct bpf_map *map, void *key,
					 void *value1, u64 map_flags)
{
	struct bpf_hmm_range_storage_data *sdata;
	struct range_update *update;
	struct hmm_range *range;
	struct hmm_range *value;
	unsigned long addr;
	int err = 0;
	int map_fd;

	//printk(KERN_INFO "Called bpf_mm_walk_hmm_range_storage_update_elem\n");
	addr = *(unsigned long *)key;
	//printk(KERN_INFO "Addr=%lu\n", addr);	
	
	range = mm_walk_range_lookup(addr);
	if (range) {
	//	printk(KERN_INFO "Update elem found range\n");
		
		if (map_flags == BPF_NOEXIST) {
	//		printk(KERN_INFO "Elem does not yet exist in map -add it plz\n");
			
			update = (struct range_update *)value1;
			value = &update->range;

			memcpy(&value->start, &range->start, sizeof(value->start));
			memcpy(&value->end, &range->end, sizeof(value->end));
			memcpy(&value->default_flags, &range->default_flags, sizeof(value->default_flags));
			memcpy(&value->pfn_flags_mask, &range->pfn_flags_mask, sizeof(value->pfn_flags_mask));
			
			unsigned long npages = (range->end - range->start) >> PAGE_SHIFT;
			size_t pfns_size = (sizeof(unsigned long)) * npages;
				
			value->hmm_pfns = kzalloc(pfns_size, GFP_USER);
			memcpy(value->hmm_pfns, range->hmm_pfns, pfns_size);

			sdata = hmm_range_storage_update(range, map, value, map_flags);
//			map_fd = bpf_create_map(BPF_MAP_TYPE_ARRAY, sizeof(unsigned long), sizeof(int), npages, 0);
		
		}
		else if (map_flags ==  BPF_EXIST) {
	//		printk(KERN_INFO "Elem aready exists in map! Do update based on value\n");
			
			update = (struct range_update *)value1;
			value = &update->range;

			//memcpy(&value->start, &range->start, sizeof(value->start));
			//memcpy(&value->end, &range->end, sizeof(value->end));
			//memcpy(&value->default_flags, &range->default_flags, sizeof(value->default_flags));
			//memcpy(&value->pfn_flags_mask, &range->pfn_flags_mask, sizeof(value->pfn_flags_mask));
			
			storage_hmm_pfns_fill(update->start, update->end, value, update->value);
			
			//unsigned long npages = (range->end - range->start) >> PAGE_SHIFT;
			//size_t pfns_size = (sizeof(unsigned long)) * npages;
				
			//value->hmm_pfns = kzalloc(pfns_size, GFP_USER);
			//memcpy(value->hmm_pfns, range->hmm_pfns, pfns_size);


			sdata = hmm_range_storage_update(range, map, value, map_flags);
			
	//		printk(KERN_INFO "Done updating elem\n");
			//TODO: THis more efficiently
		/*	update = (struct range_update *)value1;
			value = &update->range;

			memcpy(&value->start, &range->start, sizeof(value->start));
			memcpy(&value->end, &range->end, sizeof(value->end));
			memcpy(&value->default_flags, &range->default_flags, sizeof(value->default_flags));
			memcpy(&value->pfn_flags_mask, &range->pfn_flags_mask, sizeof(value->pfn_flags_mask));
			
			unsigned long npages = (range->end - range->start) >> PAGE_SHIFT;
			size_t pfns_size = (sizeof(unsigned long)) * npages;

			// Actually change the kern range hmm_pfns
			hmm_pfns_fill(update->start, update->end, range, update->value);
				
			value->hmm_pfns = kzalloc(pfns_size, GFP_USER);
			memcpy(value->hmm_pfns, range->hmm_pfns, pfns_size);

			
			sdata = hmm_range_storage_update(range, map, value, map_flags);
		*/	
		}

		
		//sockfd_put(sock);
		err = PTR_ERR_OR_ZERO(sdata);
	//	printk(KERN_INFO "storage_update_elem err is %d\n", err);
	}

	return err;
}

static int bpf_mm_walk_hmm_range_storage_delete_elem(struct bpf_map *map, void *key)
{
	struct hmm_range *range;
	int err = 0;

	unsigned long addr = *(unsigned long *)key;

	range = mm_walk_range_lookup(addr);
	if (range) {
		err = hmm_range_storage_delete(range, map);
	//	sockfd_put(sock);
		return err;
	}

	return err;
}

static struct bpf_hmm_range_storage_elem *
bpf_hmm_range_storage_clone_elem(struct hmm_range *newrange,
			  struct bpf_hmm_range_storage_map *smap,
			  struct bpf_hmm_range_storage_elem *selem)
{
	struct bpf_hmm_range_storage_elem *copy_selem;

	copy_selem = selem_alloc(smap, newrange, NULL);
	if (!copy_selem)
		return NULL;

	if (map_value_has_spin_lock(&smap->map))
		copy_map_value_locked(&smap->map, SDATA(copy_selem)->data,
				      SDATA(selem)->data, true);
	else
		copy_map_value(&smap->map, SDATA(copy_selem)->data,
			       SDATA(selem)->data);

	return copy_selem;
}

int bpf_hmm_range_storage_clone(const struct hmm_range *range, struct hmm_range *newrange)
{
	struct bpf_hmm_range_storage *new_range_storage = NULL;
	struct bpf_hmm_range_storage *range_storage;
	struct bpf_hmm_range_storage_elem *selem;
	int ret = 0;

	RCU_INIT_POINTER(newrange->hmm_range_bpf_storage, NULL);

	rcu_read_lock();
	range_storage = rcu_dereference(range->hmm_range_bpf_storage);

	if (!range_storage || hlist_empty(&range_storage->list))
		goto out;

	hlist_for_each_entry_rcu(selem, &range_storage->list, snode) {
		struct bpf_hmm_range_storage_elem *copy_selem;
		struct bpf_hmm_range_storage_map *smap;
		struct bpf_map *map;

		smap = rcu_dereference(SDATA(selem)->smap);
		if (!(smap->map.map_flags & BPF_F_CLONE))
			continue;

		/* Note that for lockless listeners adding new element
		 * here can race with cleanup in bpf_sk_storage_map_free.
		 * Try to grab map refcnt to make sure that it's still
		 * alive and prevent concurrent removal.
		 */
		map = bpf_map_inc_not_zero(&smap->map);
		if (IS_ERR(map))
			continue;

		copy_selem = bpf_hmm_range_storage_clone_elem(newrange, smap, selem);
		if (!copy_selem) {
			ret = -ENOMEM;
			bpf_map_put(map);
			goto out;
		}

		if (new_range_storage) {
			selem_link_map(smap, copy_selem);
			__selem_link_hmm_range(new_range_storage, copy_selem);
		} else {
			ret = hmm_range_storage_alloc(newrange, smap, copy_selem);
			if (ret) {
				kfree(copy_selem);
				bpf_map_put(map);
				goto out;
			}

			new_range_storage = rcu_dereference(copy_selem->hmm_range_storage);
		}
		bpf_map_put(map);
	}

out:
	rcu_read_unlock();

	/* In case of an error, don't free anything explicitly here, the
	 * caller is responsible to call bpf_sk_storage_free.
	 */

	return ret;
}

BPF_CALL_4(bpf_hmm_range_storage_get, struct bpf_map *, map, struct hmm_range *, range,
	   void *, value, u64, flags)
{
	struct bpf_hmm_range_storage_data *sdata;

	if (flags > BPF_SK_STORAGE_GET_F_CREATE)
		return (unsigned long)NULL;

	sdata = hmm_range_storage_lookup(range, map, true);
	if (sdata)
		return (unsigned long)sdata->data;

	if (flags == BPF_SK_STORAGE_GET_F_CREATE) { //&&
	    /* Cannot add new elem to a going away sk.
	     * Otherwise, the new elem may become a leak
	     * (and also other memory issues during map
	     *  destruction).
	     */
	   // refcount_inc_not_zero(&range->hmm_range_refcnt)) {
		sdata = hmm_range_storage_update(range, map, value, BPF_NOEXIST);
		/* sk must be a fullsock (guaranteed by verifier),
		 * so sock_gen_put() is unnecessary.
		 */
		////sock_put(sk);
		return IS_ERR(sdata) ?
			(unsigned long)NULL : (unsigned long)sdata->data;
	}

	return (unsigned long)NULL;
}

BPF_CALL_2(bpf_hmm_range_storage_delete, struct bpf_map *, map, struct hmm_range *, range)
{
//	if (refcount_inc_not_zero(&range->hmm_range_refcnt)) {
		int err;

		err = hmm_range_storage_delete(range, map);
//		sock_put(sk);
		return err;
//	}

	return err;
//	return -ENOENT;
}

const struct bpf_map_ops hmm_range_storage_map_ops = {
	.map_alloc_check = bpf_hmm_range_storage_map_alloc_check,
	.map_alloc = bpf_hmm_range_storage_map_alloc,
	.map_free = bpf_hmm_range_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_mm_walk_hmm_range_storage_lookup_elem,
	.map_update_elem = bpf_mm_walk_hmm_range_storage_update_elem,
	.map_delete_elem = bpf_mm_walk_hmm_range_storage_delete_elem,
	//.map_update_batch = bpf_mm_walk_hmm_range_storage_update_batch,
	.map_check_btf = bpf_hmm_range_storage_map_check_btf,
};

const struct bpf_func_proto bpf_hmm_range_storage_get_proto = {
	.func		= bpf_hmm_range_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_HMM_RANGE,
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_hmm_range_storage_delete_proto = {
	.func		= bpf_hmm_range_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_HMM_RANGE,
};
