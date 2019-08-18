
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    //socket�׽���
    ngx_socket_t        fd;
    //����sockaddr�ĵ�ַ
    struct sockaddr    *sockaddr;
    //sockaddr�ĳ���
    socklen_t           socklen;    /* size of sockaddr */
    //�洢ip��ַ�ַ�������󳤶ȣ�����ָ����addr_text�������ڴ�Ĵ�С
    size_t              addr_text_max_len;
    //���ַ�������ʽ�洢IP
    ngx_str_t           addr_text;
    //�׽������ͣ���stream==>TCP
    int                 type;
    
    /*TCPʵ�ּ���ʱ��backlog����, ����ʾ��������ͨ����������
    ����TCP���ӵ���û���κν��̿�ʼ���������������*/
    int                 backlog;
    
    //�ں��ж�������׽��ֵĽ��ջ�������С
    int                 rcvbuf;
    
     //�ں��ж�������׽��ֵķ��ͻ�������С
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    //���µ�TCP���ӳɹ�������Ĵ�����
    ngx_connection_handler_pt   handler; /* �ڼ����˿ڽ���TCP���ӵ�ʱ�򣬾ͻ�ص��÷��� */

    /*ʵ���Ͽ�ܲ���ʹ��serversָ��, ����������Ϊһ������ָ��, 
    Ŀǰ��Ҫ����HTTP����mail��ģ��, ���ڱ��浱ǰ�����˿ڶ�Ӧ�ŵ�����������*/
    void               *servers;  /* array of ngx_http_in_addr_t, for example */
    //log��logp���ǿ��õ���־�����ָ��
    ngx_log_t           log;
    ngx_log_t          *logp;
    
    //���Ϊ�µ�TCP���Ӵ����ڴ��, ���ڴ�صĳ�ʼ��СӦ����pool_size
    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    /*TCP_DEFER_ACCEPTѡ��ڽ���TCP���ӳɹ��ҽ��յ��û����������ݺ�, 
    ����Լ����׽��ָ���Ȥ�Ľ��̷����¼�֪ͨ, �����ӽ����ɹ���, 
    ���post_accept_timeout�����Ȼû���յ����û�����, ���ں�ֱ�Ӷ�������*/
    ngx_msec_t          post_accept_timeout;

    /*ǰһ��ngx_listening_t�ṹ, ���ngx_listening_t�ṹ��֮����previousָ����ɵ�����*/
    ngx_listening_t    *previous;

    //��ǰ���������Ӧ�ŵ�ngx_connection_t�ṹ��
    ngx_connection_t   *connection;

    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;

    ngx_uint_t          worker;

    /*��־λ, Ϊ1���ʾ�ڵ�ǰ���������Ч, 
    ��ִ��ngx_init_cycleʱ���رռ����˿�, 
    Ϊ0ʱ�������رա��ñ�־λ��ܴ�����Զ�����*/
    unsigned            open:1;

    /*��־λ, Ϊ1��ʾʹ�����е�ngx_cycle_t����ʼ���µ�ngx_cycle_t�ṹ��ʱ, 
    ���ر�ԭ�ȴ򿪵ļ����˿�, ����������������������, remainΪ0ʱ, 
    ��ʾ�����ر������򿪵ļ����˿ڡ��ñ�־λ��ܴ�
    ����Զ�����, �μ�ngx_init_cycle����*/
    unsigned            remain:1;

    /*��־λ, Ϊ1ʱ��ʾ�������õ�ǰngx_listening_t�ṹ���е��׽���, 
    Ϊ0ʱ������ʼ���׽��֡��ñ�־λ��ܴ�����Զ�����*/
    unsigned            ignore:1;

    //��ʾ�Ƿ��Ѿ��󶨡�ʵ����Ŀǰ�ñ�־λû��ʹ��
    unsigned            bound:1;       /* already bound */
    /*�Ѿ���*/
    /*��ʾ��ǰ��������Ƿ�����ǰһ������(������Nginx����), ���Ϊ1, 
    ���ʾ����ǰһ�����̡�һ��ᱣ��֮ǰ�Ѿ����úõ��׽���, �����ı�*/
    unsigned            inherited:1;   /*����ǰһ������*/ /* inherited from previous process */

    //Ŀǰδʹ��
    unsigned            nonblocking_accept:1;
    
    //��־λ, Ϊ1ʱ��ʾ��ǰ�ṹ���Ӧ���׽����Ѿ�����
    unsigned            listen:1;
    //��ʾ�׽����Ƿ�����, Ŀǰ�ñ�־λû������
    unsigned            nonblocking:1;
    //Ŀǰ�ñ�־λû������
    unsigned            shared:1;    /* shared between threads or processes */

    //��־λ, Ϊ1ʱ��ʾNginx�Ὣ�����ַת��Ϊ�ַ�����ʽ�ĵ�ַ
    unsigned            addr_ntop:1;
    unsigned            wildcard:1;

#if (NGX_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;

    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02


struct ngx_connection_s {
    void               *data;
    ngx_event_t        *read;
    ngx_event_t        *write;

    ngx_socket_t        fd;

    ngx_recv_pt         recv;
    ngx_send_pt         send;
    ngx_recv_chain_pt   recv_chain;
    ngx_send_chain_pt   send_chain;

    ngx_listening_t    *listening;

    off_t               sent;

    ngx_log_t          *log;

    ngx_pool_t         *pool;

    int                 type;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;
    ngx_str_t           addr_text;

    ngx_str_t           proxy_protocol_addr;
    in_port_t           proxy_protocol_port;

#if (NGX_SSL || NGX_COMPAT)
    ngx_ssl_connection_t  *ssl;
#endif

    ngx_udp_connection_t  *udp;

    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    ngx_buf_t          *buffer;

    ngx_queue_t         queue;

    ngx_atomic_uint_t   number;

    ngx_uint_t          requests;

    unsigned            buffered:8;

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;

    unsigned            idle:1;
    unsigned            reusable:1;
    unsigned            close:1;
    unsigned            shared:1;

    unsigned            sendfile:1;
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    unsigned            need_last_buf:1;

#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_cycle_t *cycle, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_tcp_nodelay(ngx_connection_t *c);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
