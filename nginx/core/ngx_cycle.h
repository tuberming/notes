
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CYCLE_H_INCLUDED_
#define _NGX_CYCLE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef NGX_CYCLE_POOL_SIZE
#define NGX_CYCLE_POOL_SIZE     NGX_DEFAULT_POOL_SIZE
#endif


#define NGX_DEBUG_POINTS_STOP   1
#define NGX_DEBUG_POINTS_ABORT  2


typedef struct ngx_shm_zone_s  ngx_shm_zone_t;

typedef ngx_int_t (*ngx_shm_zone_init_pt) (ngx_shm_zone_t *zone, void *data);

struct ngx_shm_zone_s {
    void                     *data;
    ngx_shm_t                 shm;
    ngx_shm_zone_init_pt      init;
    void                     *tag;
    void                     *sync;
    ngx_uint_t                noreuse;  /* unsigned  noreuse:1; */
};


/* Nginx�����Χ����ngx_cycle_t�ṹ�������ƽ������е� */
struct ngx_cycle_s {
    /*����������ģ��洢������Ľṹ���ָ��, ��������һ������, 
    ÿ�������Ա����һ��ָ��, ���ָ��ָ����һ���洢��ָ�������, ��˻ῴ��void*/
    void                  ****conf_ctx;
    
    //�ڴ��
    ngx_pool_t               *pool;

    /*��־ģ�����ṩ�����ɻ���ngx_log_t��־����Ĺ���, 
    �����logʵ�������ڻ�û��ִ��ngx_init_cycle����ǰ, Ҳ
    ���ǻ�û�н�������ǰ, �������Ϣ��Ҫ�������־, �ͻ���ʱʹ��log����, 
    �����������Ļ����ngx_init_cycle����ִ�к�, �������nginx.conf�����ļ��е�������, 
    �������ȷ����־�ļ�, ��ʱ���log���¸�ֵ*/
    ngx_log_t                *log;

    /*��nginx.conf�����ļ���ȡ����־�ļ�·����, ����ʼ��ʼ��error_log��־�ļ�, 
    ����log���������������־����Ļ, ��ʱ����new_log������ʱ�Ե����log��־, 
    ����ʼ���ɹ���, ����new_log�ĵ�ַ���������logָ��*/
    ngx_log_t                 new_log;

    ngx_uint_t                log_use_stderr;  /* unsigned  log_use_stderr:1; */
    
    /*����poll��rtsig�������¼�ģ��, ������Ч�ļ��������Ԥ�Ƚ�����Щngx_connection_t�ṹ��, 
    �Լ����¼����ռ����ַ�����ʱfiles�ͻᱣ������ngx_connection_t��ָ����ɵ�����, 
    files_n����ָ�������, ���ļ������ֵ��������files�����Ա*/
    ngx_connection_t        **files;
    
    //�������ӳ�, ��free_connection_n���ʹ��
    ngx_connection_t         *free_connections;
    //�������ӳ������ӵ�����
    ngx_uint_t                free_connection_n;

    ngx_module_t            **modules;
    ngx_uint_t                modules_n;
    ngx_uint_t                modules_used;    /* unsigned  modules_used:1; */

    /*˫����������, Ԫ��������ngx_connection_t�ṹ��, ��ʾ���ظ�ʹ�����Ӷ���*/
    ngx_queue_t               reusable_connections_queue;
    ngx_uint_t                reusable_connections_n;

    /*��̬����, ÿ������Ԫ�ش洢��ngx_listening_t��Ա, ��ʾ�����˿ڼ���صĲ���*/
    ngx_array_t               listening;

    /*��̬��������, ��������Nginx����Ҫ������Ŀ¼�������Ŀ¼������, �����ͼ����,
    ������Ŀ¼ʧ�ܽ��ᵼ��Nginx����ʧ�ܡ�����, �ϴ��ļ�����ʱĿ¼Ҳ��pathes��, 
    ���û��Ȩ�޴���, ��ᵼ��Nginx�޷�����*/
    ngx_array_t               paths;

    ngx_array_t               config_dump;
    ngx_rbtree_t              config_dump_rbtree;
    ngx_rbtree_node_t         config_dump_sentinel;

    /*����������, Ԫ��������ngx_open_file_t�ṹ��, ����ʾNginx�Ѿ��򿪵������ļ���
    ��ʵ��, Nginx��ܲ�����open_files����������ļ�, �����ɶԴ˸���Ȥ��ģ������������ļ�·����,
    Nginx��ܻ���ngx_init_cycle�����д���Щ�ļ�*/
    ngx_list_t                open_files;

    /*����������, Ԫ�ص�������ngx_shm_zone_t�ṹ��, 
    ÿ��Ԫ�ر�ʾһ�鹲���ڴ�, �����ڴ潫�ڵ�14�½���*/
    ngx_list_t                shared_memory;

    //��ǰ�������������Ӷ��������, �������connections��Ա���ʹ��
    ngx_uint_t                connection_n;
    ngx_uint_t                files_n;

    //ָ��ǰ�����е��������Ӷ���, ��connection_n���ʹ��
    ngx_connection_t         *connections;

    //ָ��ǰ�����е����ж��¼�����, connection_nͬʱ��ʾ���ж��¼�������
    ngx_event_t              *read_events;

    //ָ��ǰ�����е�����д�¼�����, connection_nͬʱ��ʾ����д�¼�������
    ngx_event_t              *write_events;

    /*�ɵ�ngx_cycle_t��������������һ��ngx_cycle_t�����еĳ�Ա��
    ����ngx_init_cycle����, ����������, ��Ҫ����һ����ʱ��ngx_cycle_t���󱣴�һЩ����, 
    �ٵ���ngx_init_cycle����ʱ�Ϳ��԰Ѿɵ�ngx_cycle_t���󴫽�ȥ, 
    ����ʱold_cycle����ͻᱣ�����ǰ�ڵ�ngx_cycle_t����*/
    ngx_cycle_t              *old_cycle;

    //�����ļ�����ڰ�װĿ¼��·������
    ngx_str_t                 conf_file;

    /*Nginx���������ļ�ʱ��Ҫ���⴦�����������Я���Ĳ���, һ����-gѡ��Я���Ĳ���*/
    ngx_str_t                 conf_param;
    //Nginx�����ļ�����Ŀ¼��·��
    ngx_str_t                 conf_prefix;

    //Nginx��װĿ¼��·��
    ngx_str_t                 prefix;
    //���ڽ��̼�ͬ�����ļ�������
    ngx_str_t                 lock_file;
    //ʹ��gethostnameϵͳ���õõ���������
    ngx_str_t                 hostname;
};


typedef struct {
    ngx_flag_t                daemon;
    ngx_flag_t                master;

    ngx_msec_t                timer_resolution;
    ngx_msec_t                shutdown_timeout;

    ngx_int_t                 worker_processes;
    ngx_int_t                 debug_points;

    ngx_int_t                 rlimit_nofile;
    off_t                     rlimit_core;

    int                       priority;

    ngx_uint_t                cpu_affinity_auto;
    ngx_uint_t                cpu_affinity_n;
    ngx_cpuset_t             *cpu_affinity;

    char                     *username;
    ngx_uid_t                 user;
    ngx_gid_t                 group;

    ngx_str_t                 working_directory;
    ngx_str_t                 lock_file;

    ngx_str_t                 pid;
    ngx_str_t                 oldpid;

    ngx_array_t               env;
    char                    **environment;

    ngx_uint_t                transparent;  /* unsigned  transparent:1; */
} ngx_core_conf_t;


#define ngx_is_init_cycle(cycle)  (cycle->conf_ctx == NULL)


ngx_cycle_t *ngx_init_cycle(ngx_cycle_t *old_cycle);
ngx_int_t ngx_create_pidfile(ngx_str_t *name, ngx_log_t *log);
void ngx_delete_pidfile(ngx_cycle_t *cycle);
ngx_int_t ngx_signal_process(ngx_cycle_t *cycle, char *sig);
void ngx_reopen_files(ngx_cycle_t *cycle, ngx_uid_t user);
char **ngx_set_environment(ngx_cycle_t *cycle, ngx_uint_t *last);
ngx_pid_t ngx_exec_new_binary(ngx_cycle_t *cycle, char *const *argv);
ngx_cpuset_t *ngx_get_cpu_affinity(ngx_uint_t n);
ngx_shm_zone_t *ngx_shared_memory_add(ngx_conf_t *cf, ngx_str_t *name,
    size_t size, void *tag);
void ngx_set_shutdown_timer(ngx_cycle_t *cycle);


extern volatile ngx_cycle_t  *ngx_cycle;
extern ngx_array_t            ngx_old_cycles;
extern ngx_module_t           ngx_core_module;
extern ngx_uint_t             ngx_test_config;
extern ngx_uint_t             ngx_dump_config;
extern ngx_uint_t             ngx_quiet_mode;


#endif /* _NGX_CYCLE_H_INCLUDED_ */
