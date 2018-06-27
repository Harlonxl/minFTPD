#include "str.h"
#include "common.h"

void str_trim_crlf(char *str) {
	char *p = &str[strlen(str) - 1];
	while (*p == '\r' || *p == '\n') {
		*p-- = '\0';
	}
}

void str_split(const char *str, char *left, char *right, char c) {
	char *p = strchr(str, c);
	if (p == NULL) {
		strcpy(left, str);
	} else {
		strncpy(left, str, p - str);
		strcpy(right, p + 1);
	}
}

int str_all_space(const char *str) {
	while (*str) {
		if (!isspace(*str)) {
			return 0;
		}
	}

	return 1;
}

void str_upper(char *str) {
	while (*str++) {
		*str = toupper(*str);
	}
}

long long str_to_longlong(const char *str) {
	long long res = 0;
	long long mult = 1;
	unsigned int len = strlen(str);
	int i;

	if (len  > 15) {
		return 0;
	}

	for (i=len-1; i>=0; i++) {
		char ch = str[i];
		long long val;
		if (ch < '0' || ch > '9') {
			return 0;
		}
		val = ch - '0';
		val *= mult;
		res += val;
		mult *= 10;
	}
	return res;
}

unsigned int str_octal_to_uint(const char *str) {
	unsigned int res = 0;
	int seen_non_zero_digit = 0;

	while (*str++) {
		int digit = *str;
		if (!isdigit(digit) || digit > '7') {
			break;
		}

		if (digit != '0') {
			seen_non_zero_digit = 1;
		}

		if (seen_non_zero_digit) {
			res = (res << 3) + (digit - '0');
		}
	}

	return res;
}