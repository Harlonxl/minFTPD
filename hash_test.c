#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hash.h"

typedef struct stu {
	char sno[5];
	char name[32];
	int age;
} stu_t;

unsigned int hash_str(unsigned int buckets, void *key) {
	char *sno = (char *)key;
	unsigned int index = 0;

	while (*sno) {
		index = *sno + 4 * index;
		sno++;
	}

	return index % buckets;
}

int main() {
	stu_t stu_arr[] =
	{
		{ "1234", "AAAA", 20 },
		{ "4568", "BBBB", 23 },
		{ "6729", "AAAA", 19 }
	};

	hash_t *hash = hash_alloc(256, hash_str);

	int size = sizeof(stu_arr) / sizeof(stu_arr[0]);
	int i;
	for (i=0; i<size; i++) {
		hash_add_entry(hash, stu_arr[i].sno, strlen(stu_arr[i].sno),
			&stu_arr[i], sizeof(stu_arr[i]));
	}

	stu_t *s = (stu_t *)hash_lookup_entry(hash, "4568", strlen("4568"));
	if (s) {
		printf("%s %s %d\n", s->sno, s->name, s->age);
	}
	else {
		printf("not found\n");
	}
	
	hash_free_entry(hash, "1234", strlen("1234"));
	s = (stu_t *)hash_lookup_entry(hash, "1234", strlen("1234"));
	if (s) {
		printf("%s %s %d\n", s->sno, s->name, s->age);
	} else {
		printf("not found\n");
	}
	return 0;
}