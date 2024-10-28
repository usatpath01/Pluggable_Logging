#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

const int required_syscalls[] = {0, 1, 2};
const int not_required_syscalls[] = {3, 4, 5};

int main() {
    int fd = open("/tmp/required_syscalls", O_WRONLY);
    if (fd == -1) {
        perror("Error: Could not open the required syscalls file");
        return 1;
    }
    char buffer[2048];
    int len1 = sizeof(required_syscalls) / sizeof(required_syscalls[0]);
    int len2 = sizeof(not_required_syscalls) / sizeof(not_required_syscalls[0]);
    for (int i = 0; i < len1; i++) {
        int syscall_num = required_syscalls[i];
        char syscall_flag = 1;
        memcpy(buffer + i * 5, &syscall_num, sizeof(syscall_num));
        memcpy(buffer + i * 5 + 4, &syscall_flag, sizeof(syscall_flag));
    }
    for (int i = 0; i < len2; i++) {
        int syscall_num = not_required_syscalls[i];
        char syscall_flag = 0;
        memcpy(buffer + (len1 + i) * 5, &syscall_num, sizeof(syscall_num));
        memcpy(buffer + (len1 + i) * 5 + 4, &syscall_flag, sizeof(syscall_flag));
    }
    memcpy(buffer + (len1 + len2) * 5, "\n", 1);
    write(fd, buffer, (len1 + len2) * 5 + 1);
    close(fd);
    return 0;
}