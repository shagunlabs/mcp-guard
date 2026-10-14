#define _GNU_SOURCE
#include <stdarg.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/syscall.h>
long syscall(long n, ...){ va_list a; va_start(a,n); long x[6]; for(int i=0;i<6;i++) x[i]=va_arg(a,long); va_end(a);
 if(n==SYS_arch_prctl && (x[0]==0x1023||x[0]==0x1022)){ errno=EPERM; return -1; }
 static long (*r)(long,...)=0; if(!r) r=dlsym(RTLD_NEXT,"syscall"); return r(n,x[0],x[1],x[2],x[3],x[4],x[5]); }
