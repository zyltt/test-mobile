/*
程序的主入口，用来循环调用模糊测试主流程，并输出相应的提示信息。
*/

#define AFL_MAIN
#define MESSAGES_TO_STDOUT

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#ifdef __cplusplus
extern "C" {
#endif
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <fcntl.h>

#include <string.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#ifdef __cplusplus
}
#endif

#include <vector>
#include <string>
#include <iostream>

static char in_dir[256];
static char out_dir[256];
static int max_trials;
static long long start_time;

struct queue_entry {
  u8 fname[256];                          /* 文件名      */
  u32 len;                            /* 输入的位数                    */

  u8  cal_failed,                     /* 程序搭建的是否正确              */
      trim_done,                      /* 是否剪枝               */
      was_fuzzed,                     /* 模糊测试是否完成        */
      passed_det,                     /* 突变因子的选择是否完成     */
      has_new_cov,                    /* 是否达到了新的覆盖率           */
      var_behavior,                   /* 变量的行为             */
      favored,                        /* 该突变因子是否更加重要               */
      fs_redundant;                   /* 测试用例是否冗余   */

  u32 bitmap_size,                    /* 覆盖率的比特表     */
      exec_cksum;                     /* 执行轨迹的检查结果  */

  u64 exec_us,                        /* 执行时间              */
      handicap,                       /* 循环依赖数    */
      depth;                          /* 路径深度                       */

  u8* trace_mini;                     /* 是否保存了路径             */
  u32 tc_ref;                         /* 路径中的引用数目            */

  struct queue_entry *next,           /* 下一个元素             */
                     *next_100;       /* 下100个元素               */

};

static std::vector<queue_entry*> input_queue; /* 执行模糊测试的主题流程*/

static u8* trace_bits;                /* 构建程序比特表的哈希值  */
static int child_pid = -1;            /* 模糊测试程序的pid   */
static int shm_id;                    /* SHM ID */
static u16 count_class_lookup16[65536];
static FILE* plot_file; 

static s32 out_fd,
           dev_urandom_fd = -1,
           out_dir_fd = -1,
           dev_null_fd = -1;

static u8 *out_file;

/* 输出相关提示信息 */

static void usage(char* argv0) {

  SAYF("Usage: \n%s input_dir output_dir max_trials /path/to/fuzzed_app \n\n", argv0);

  exit(1);

}

/* 把现有命令拷贝一个副本，以防止命令的篡改 */

static void save_cmdline(u32 argc, char** argv) {

  u32 len = 1, i;
  char* buf;

  for (i = 0; i < argc; i++)
    len += strlen(argv[i]) + 1;
  
  buf = ck_alloc(len);

  for (i = 0; i < argc; i++) {

    u32 l = strlen(argv[i]);
//    printf("%s\n", argv[i]);
    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';

  }

  *buf = 0;

}

void fuzzing(char* app){

}


#ifdef __x86_64__

static inline void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (unlikely(*mem)) {

      u16* mem16 = (u16*)mem;

      mem16[0] = count_class_lookup16[mem16[0]];
      mem16[1] = count_class_lookup16[mem16[1]];
      mem16[2] = count_class_lookup16[mem16[2]];
      mem16[3] = count_class_lookup16[mem16[3]];

    }

    mem++;

  }

}

#else

#endif /* ^__x86_64__ */

/* 运行初始测试输入，以判断程序是否正确运行 */

void perform_dry_run(char* app){
  ACTF("Attempting dry run with '%s'...", app);

  int status = 0;
  int st_pipe[2], ctl_pipe[2];
  memset(trace_bits, 0, MAP_SIZE);

  char* argv[] = {app, "", NULL};
  pid_t pid;
  printf("Before wait %d\n",*(u32*)trace_bits);
  child_pid = fork();

  if(child_pid < 0){
    perror("fork error.");
    exit(EXIT_FAILURE);
  }
  
  if(!child_pid){ // This is child process
    printf("This is the child process");
    struct rlimit r;

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* 忽略报错信息 */

    }

    /* 报错是由于垃圾回收进行太慢导致的 */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* 忽略报错信息 */


    setsid();

    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* 抛弃不需要的初始种子，建立数据和控制的流水线 */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
    close(dev_urandom_fd);
    close(fileno(plot_file));

    /* 关闭post-fork的额外工作会提升性能*/

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* 为sane赋初值 */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* 报错信息是笼统的，因此其并不总是可信，因此需要特殊处理 */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    execv(app, argv);
    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);
  }

  pid_t ret;
  ret = waitpid(child_pid, &status, 0);
  if(ret < 0){
    perror("wait error");
    exit(EXIT_FAILURE);
  }
  

  int tb4 = *(u32*)trace_bits;

  printf("after wait %d\n",*(u32*)trace_bits);
  u32 ck1 = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  SAYF("aaaa %d\n", ck1);

  if (!WIFSTOPPED(status)) child_pid = 0;

  #ifdef __x86_64__
    classify_counts((u64*)trace_bits);
  #else
    classify_counts((u32*)trace_bits);  
  #endif /* ^__x86_64__ */
  
  u32 ck2 = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  SAYF("bbbbbb %d\n", ck2);

  if (WIFEXITED(status))
        printf("child exited normal exit status= %d\n", WEXITSTATUS(status));

    else if (WIFSIGNALED(status))
        printf("child exited abnormal signal number= %d \n", WTERMSIG(status));
    else if (WIFSTOPPED(status))
        printf("child stoped signal number=%d\n", WSTOPSIG(status));

}

static void list_dir(const char *path)
{
    struct dirent *entry;

    DIR *dir = opendir(path);
    if (dir == NULL) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        if(entry->d_name[0]=='.')
            continue;
        struct queue_entry *q = (struct queue_entry *)malloc(sizeof(queue_entry));
        //q->fname = entry->d_name;
        memcpy(q->fname, entry->d_name, strlen(entry->d_name));
        input_queue.push_back(q);
    }

    closedir(dir);
}

static void setup_shm(){

  printf("setup_shm enter!\n");
  u8* shm_str;

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  
  if (shm_id < 0) PFATAL("Fialed to creat a shared memory");
  
  shm_str = alloc_printf("%d", shm_id);
  
  trace_bits = shmat(shm_id, NULL, 0);
  if (!trace_bits) PFATAL("shmat() failed");

  printf("setup_shm Successfully!\n");
}

/* Main entry point */

int main(int argc, char** argv) {

  SAYF(cCYA "random-fuzz " cBRI VERSION cRST " by\n");

  if(argc < 5)  usage(argv[0]);
  memcpy(in_dir, argv[1], strlen(argv[1]));
  memcpy(out_dir, argv[2], strlen(argv[2]));
  max_trials = atoi(argv[3]);


  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");
  
  setup_shm();
  OKF("Shared memory is ready.");
  u32 ck1 = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  SAYF("main cksum %d\n", ck1);
  
  list_dir(in_dir);
  OKF("Input queue initialized with %d seeds.", input_queue.size());


  save_cmdline(argc, argv);
  OKF("Command line saved.");

  
//  start_time = get_cur_time();
//  SAYF("The start time is: %lld", start_time);

  OKF("Perform dry run!");
  perform_dry_run(argv[4]);
  
  OKF("Start fuzzing!");
  fuzzing(argv[4]);

  OKF("We're done here. Have a nice day!\n");

//  FILE* f = fopen("1.dat", "w");
//  for(int i = 0; i < MAP_SIZE; i++)
//  {
//    fprintf(f, "%d ", trace_bits[i]);
//  }
//  fclose(f);

  exit(0);

}
