CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2

all: systrace test_workload child_demo

systrace: systrace.c
	$(CC) $(CFLAGS) -o systrace systrace.c

test_workload: test_workload.c
	$(CC) $(CFLAGS) -o test_workload test_workload.c

child_demo: child_demo.c
	$(CC) $(CFLAGS) -o child_demo child_demo.c

clean:
	rm -f systrace test_workload child_demo
