#include "hash.h"
#include "common.h"

typedef struct hash_node {
	void *key;
	void *value;
	struct hash_node *prev;
	struct hash_node *next;
} hash_node_t;

struct hash {
	unsigned int buckets;
	hashfunc_t hash_func;
	hash_node_t **nodes;
};

static hash_node_t **hash_get_bucket(hash_t *hash, void *key);
static hash_node_t *hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size);

hash_t *hash_alloc(unsigned int buckets, hashfunc_t hash_func) {
	hash_t *hash = (hash_t *)malloc(sizeof(hash_t));
	hash->buckets = buckets;
	hash->hash_func = hash_func;
	int size = buckets * sizeof(hash_node_t *);
	hash->nodes = (hash_node_t **)malloc(size);
	memset(hash->nodes, 0, size);
	return hash;
}
void *hash_lookup_entry(hash_t *hash, void *key, unsigned int key_size) {
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if (node == NULL) {
		return NULL;
	}

	return node->value;
}
void hash_add_entry(hash_t *hash, void *key, unsigned int key_size, void *value, unsigned int value_size) {
	if (hash_lookup_entry(hash, key, key_size)) {
		fprintf(stderr, "duplicate hash key\n");
		return;
	}

	hash_node_t *node = (hash_node_t *)malloc(sizeof(hash_node_t));
	node->prev = NULL;
	node->next = NULL;

	node->key = malloc(key_size);
	memcpy(node->key, key, key_size);

	node->value = malloc(value_size);
	memcpy(node->value, value, value_size);

	hash_node_t **bucket = hash_get_bucket(hash, key);
	if (*bucket == NULL) {
		*bucket = node;
	} else {
		node->next = *bucket;
		(*bucket)->prev = node;
		*bucket = node;
	}
}
void hash_free_entry(hash_t *hash, void *key, unsigned int key_size) {
	hash_node_t *node = hash_get_node_by_key(hash, key, key_size);
	if (node == NULL) {
		return;
	}

	free(node->key);
	free(node->value);

	if (node->prev) {
		node->prev->next = node->next;
	} else {
		hash_node_t **bucket = hash_get_bucket(hash, key);
		*bucket = node->next;
	}

	if (node->next) {
		node->next->prev = node->prev;
	}

	free(node);
	node = NULL;
}

static hash_node_t **hash_get_bucket(hash_t *hash, void *key) {
	unsigned int bucket = hash->hash_func(hash->buckets, key);
	if (bucket >= hash->buckets) {
		fprintf(stderr, "bad bucket lookup\n");
		exit(EXIT_FAILURE);
	}

	return &(hash->nodes[bucket]);
}
static hash_node_t *hash_get_node_by_key(hash_t *hash, void *key, unsigned int key_size) {
	hash_node_t **bucket = hash_get_bucket(hash, key);
	hash_node_t *node = *bucket;

	if (node == NULL) {
		return NULL;
	}

	while (node != NULL && memcmp(node->key, key, key_size) != 0) {
		node = node->next;
	}

	return node;
}