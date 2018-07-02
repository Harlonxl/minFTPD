#include "common.h"

int list_common(void) {
	DIR *dir = opendir(".");
	if (dir == NULL) {
		return 0;
	}

	struct dirent *dt;
	struct stat sbuf;
	while ((dt = readdir(dir)) != NULL) {
		if (lstat(dt->d_name, &sbuf) < 0) {
			continue;
		}

		if (dt->d_name[0] == '.') {
			continue;
		}

		char perms[] = "----------";
		perms[0] = '?';

		mode_t mode = sbuf.st_mode;
		switch (mode & S_IFMT) {
		case S_IFREG:
			perms[0] = '-';
			break;
		case S_IFDIR:
			perms[0] = 'd';
			break;
		case S_IFLNK:
			perms[0] = 'l';
			break;
		case S_IFIFO:
			perms[0] = 'p';
			break;
		case S_IFSOCK:
			perms[0] = 's';
			break;
		case S_IFCHR:
			perms[0] = 'c';
			break;
		case S_IFBLK:
			perms[0] = 'b';
			break;
		}

		if (mode & S_IRUSR) {
			perms[1] = 'r';
		}
		if (mode & S_IWUSR) {
			perms[2] = 'w';
		}
		if (mode & S_IXUSR) {
			perms[3] = 'x';
		}

		if (mode & S_IRGRP) {
			perms[4] = 'r';
		}
		if (mode & S_IWGRP) {
			perms[5] = 'w';
		}
		if (mode & S_IXGRP) {
			perms[6] = 'x';
		}

		if (mode & S_IROTH) {
			perms[7] = 'r';
		}
		if (mode & S_IWOTH) {
			perms[8] = 'w';
		}
		if (mode & S_IXOTH) {
			perms[9] = 'x';
		}

		if (mode & S_ISUID) {
			perms[3] = (perms[3] == 'x') ? 's' : 'S';
		}

		if (mode & S_ISGID) {
			perms[6] = (perms[6] == 'x') ? 's' : 'S';
		}

		if (mode & S_ISVTX) {
			perms[9] = (perms[9] == 'x') ? 't' : 'T';
		}

		char buf[1024] = {0};
		int off = 0;

		off += sprintf(buf, "%s ", perms);
		off += sprintf(buf + off, "%3d %-8d %-8d ", (int)sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
		off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);

		const char *p_data_format = "%b %e %H:%M";
		struct timeval tv;
		gettimeofday(&tv, NULL);
		long local_time = tv.tv_sec;
		if (sbuf.st_mtime > local_time || (local_time - sbuf.st_mtime) > 60 * 60 * 24 * 182) {
			p_data_format = "%b %e %Y";
		}

		char datebuf[64] = {0};
		struct tm *p_tm = localtime(&local_time);
		strftime(datebuf, sizeof(datebuf), p_data_format, p_tm);
		off += sprintf(buf + off, "%s ", datebuf);
		if (S_ISLNK(sbuf.st_mode)) {
			char tmp[1024] = {0};
			readlink(dt->d_name, tmp, sizeof(tmp));
			off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
		} else {
			sprintf(buf + off, "%s\r\n", dt->d_name);
		}

		printf("%s", buf);
	}

	closedir(dir);
	return 1;
}

int main() {
	list_common();
	return 0;
}