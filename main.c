/* mattows.c  
 * msbethke 2006  
 * A quick'n'dirty HTTP server that can deliver HTML, GIF, JPEG,  
 * PNG and CSS, and executes CGI files ending in ".cgi"  
 *  
 * NEW: goes daemon on `-d' argument; default port is 28001  
 *   
 * TODO: support POST method (only GET and HEAD so far); proper commandline  
 * parsing  
 *  
 * $Id: mattows.c,v 1.8 2006/07/04 21:55:46 mb Exp mb $  
 */   
   
#include <stdio.h>   
#include <stdlib.h>   
#include <string.h>   
#include <strings.h>   
#include <ctype.h>   
#include <stdarg.h>   
#include <unistd.h>   
#include <fcntl.h>   
#include <errno.h>   
#include <signal.h>   
#include <sys/types.h>   
#include <sys/socket.h>   
#include <sys/stat.h>   
#include <sys/wait.h>   
#include <arpa/inet.h>   
#include <netinet/in.h>   
#include <netdb.h>   
#include <dirent.h>   
   
#define _STRINGIFY(x) #x   
   
#define LOGFILENAME "mattows.log"   
#define PORT 28001   
#define PORTSTR _STRINGIFY(PORT)   
   
/* write an HTTP message (or any string) to a file descriptor */   
#define HTTPMSG(fh,msg) fputs((msg),(fh))   
   
/* Determine elements in an array */   
#define NELEMS(x) (sizeof(x)/sizeof(*x))   
   
/* some HTML stuff for dir listings */   
#define DIR_DOCTYPE "<!DOCTYPE HTML PUBLIC /"-//W3C//DTD HTML 4.01//EN/" /"http://www.w3.org/TR/html4/strict.dtd/">/n"   
#define DIR_HEAD1 "<html>/n<head><title>"   
#define DIR_HEAD2 "</title></head>/n<body>/n<ul style="/" mce_style="/""list-style-type:none/">/n"   
#define DIR_FOOT  "</ul>/n</body>/n</html>"   
#define DIR_ENT1  "<li><a href="/" mce_href="/"""   
#define DIR_ENT2  "/">"   
#define DIR_ENT3  "</a></li>/n"   
#define DIR_DIRMARK "[DIR] "   
   
typedef enum {false=0,true} bool;   
enum {ENVSIZE=20};   
typedef struct MYENV {   
    int nenv;   
    char *ptrs[ENVSIZE];   
} myenv;   
   
typedef struct EXT2MIME {   
    const char *type;   
    const char* const ext[];   
} ext2mime;   
typedef enum {M_INVALID=0, M_GET=1, M_HEAD=2} reqtype;   
   
static const ext2mime ext_html = {"text/html",{"html","htm",NULL}};   
static const ext2mime ext_gif  = {"image/gif",{"gif",NULL}};   
static const ext2mime ext_png  = {"image/png",{"png",NULL}};   
static const ext2mime ext_jpeg = {"image/jpeg",{"jpg","jpeg","jfif",NULL}};   
static const ext2mime ext_css  = {"text/css",{"css",NULL}};   
static const ext2mime* const extensions[] = {   
    &ext_html, &ext_gif, &ext_png, &ext_jpeg, &ext_css, NULL   
};   
static const char* const cgiext[] = {"cgi","pl","sh"};   
static const char MIME_GENERIC[] = "application/ocet-stream";   
   
static char *method_strings[3];   
static char *progname, *addrstr, *portstr = PORTSTR;   
static in_addr_t addr;   
static short port = PORT;   
static myenv cgienv = {   
    3,{   
        "SERVER_SOFTWARE=mattows",   
        "GATEWAY_INTERFACE=CGI/1.2",   
        "SERVER_PROTOCOL=HTTP/1.0"   
    }   
};   
static bool daemonize = false;   
   
/* HTTP codes */   
const char HTTPV[] = "HTTP/1.0 ";   
const char M200[] = "200 OK/r/n";   
const char E400[] = "400 Bad request/r/n";   
const char E404[] = "404 Not found/r/n";   
const char E403[] = "403 Forbidden/r/n";   
const char E501[] = "501 Not implemented/r/n";   
   
#ifdef REALLYTINY /* avoid use of printf */   
   
/* program usage */   
static void usage(void)   
{   
    fputs("Usage: ",stderr);   
    fputs(progname,stderr);   
    fputs("[-d] <ip> [port]/n",stderr);   
    exit(EXIT_FAILURE);   
}   
   
static void mywarn(char *s, ...) { }   
static void myerror(int code, char *s, ...)   
{   
    fputs("ABEND/n",stderr);   
    exit(code);   
}   
#else   
/* program usage */   
static void usage(void)   
{   
    fprintf(stderr,"Usage: %s [-d] [ip] <port>/n",progname);   
    exit(EXIT_FAILURE);   
}   
   
/* print message in arglist */   
static void vmywarn(char *s, va_list ap)   
{   
    fprintf(stderr,"%s [%d]: ",progname,(int)getpid());   
    vfprintf(stderr,s,ap);   
}   
   
/* print message in varargs */   
static void mywarn(char *s, ...)   
{   
    va_list ap;   
    va_start(ap,s);   
    vmywarn(s,ap);   
    va_end(ap);   
}   
   
/* print message in varargs and exit with error code */   
static void myerror(int code, char *s, ...)   
{   
    va_list ap;   
    va_start(ap,s);   
    vmywarn(s,ap);   
    va_end(ap);   
    exit(code);   
}   
#endif /* REALLYTINY */   
   
/* get hostname for an IP4 address in network byte order */   
static char *getmyhostname(in_addr_t addr)   
{   
    enum {AUXBUFSIZE=1024};   
    struct in_addr ad;   
    struct hostent he, *hp;   
    int err;   
    char *auxbuf;   
       
    ad.s_addr = addr;   
    /* auxbuf is unused anyway, so ignore ERANGE */   
    if(!(auxbuf=alloca(AUXBUFSIZE)) ||   
            /* this will probably break on Solaris */   
            gethostbyaddr_r((void*)&ad,sizeof(ad),AF_INET,   
                &he,auxbuf,AUXBUFSIZE,&hp,&err) ||   
            !hp)   
        return "(no-hostname)";   
    return he.h_name;   
}   
   
/* evaluate arguments to global vars  
 * TODO: this is getting big. might as well do it properly...  
 */   
static void eval_args(int c, char *v[])   
{   
    int n=1;   
   
    while(1) {   
        if(c <= n)   
            usage();   
        if('-' != v[n][0])   
            break;   
        switch(v[n][1]) {   
            case 'h' :   
                usage();   
            case 'd' :   
                daemonize = true;   
                break;   
            default :   
                myerror(EXIT_FAILURE,"unknown option %s/n",v[n]);   
        }   
        ++n;   
    }   
       
    addr = inet_addr(v[n]);   
    if(INADDR_NONE == addr) {   
        /* address parsing failed, assume it's a port */   
        addr = INADDR_ANY;   
        addrstr = getmyhostname(htonl(0x7f000001));   
    } else {   
        ++n;   
        addrstr = getmyhostname(addr);   
    }   
    if(c <= n)   
        return;   
    port = atoi(portstr = v[n]);   
    mywarn("ADDR: %s; PORT: %hd/n",addrstr,port);   
    if(!port)   
        usage();   
}   
   
static void send_ok_mime(FILE *to, const char *mimetype)   
{   
    HTTPMSG(to,M200);   
    HTTPMSG(to,"Content-Type: ");   
    HTTPMSG(to,mimetype);   
    HTTPMSG(to,"/r/n/r/n");   
}   
   
static int entrymode(char *path)   
{   
    struct stat st;   
   
    if(0 != stat(path,&st))   
        return 0;   
    return st.st_mode;   
}   
   
/* send <dir> in primitive HTML to <to> */   
static int send_dir(char *dir, FILE *to)   
{   
    int ret = EXIT_FAILURE;   
    DIR *dh = opendir(dir);   
    struct dirent *de;   
    if(NULL == dh) {   
        /* diretory failed to open */   
        HTTPMSG(to,E404);   
        return ret;   
    }   
    send_ok_mime(to,ext_html.type);   
    HTTPMSG(to,DIR_DOCTYPE DIR_HEAD1);   
    HTTPMSG(to,dir);   
    HTTPMSG(to,DIR_HEAD2);   
    errno = 0;   
    while(NULL != (de = readdir(dh))) {   
        int type;   
        char *name = de->d_name;   
        if(('.' == name[0]) && ('/0' == name[1]))   
            continue;   
        type = entrymode(name);   
        if(!(S_ISDIR(type) || S_ISREG(type)))   
            continue;    /* ignore stuff that isn't regular file or dir */   
        HTTPMSG(to,DIR_ENT1);   
        HTTPMSG(to,name);   
        if(S_ISDIR(type))   
            HTTPMSG(to,"/");   
        HTTPMSG(to,DIR_ENT2);   
        if(S_ISDIR(type))   
                HTTPMSG(to,DIR_DIRMARK);   
        HTTPMSG(to,name);   
        HTTPMSG(to,DIR_ENT3);   
    }   
    HTTPMSG(to,DIR_FOOT);   
    if(errno)   
        mywarn("Could not send dir: %s/n",strerror(errno));   
    else   
        ret = EXIT_SUCCESS;   
    return ret;   
}   
   
/* Read from file named <from>, write to FH <to> adding MIME header */   
static int send_file(char *from, FILE *to, const char *mimetype)   
{   
    char buf[4096];   
    int writing=1, file, rdsize,ret = EXIT_FAILURE;   
       
    file = open(from,O_RDONLY);   
    /* check if file opened, 403 if not */   
    if(-1 != file) {   
        mywarn("Sending %s/n",from);   
        HTTPMSG(to,M200);   
        HTTPMSG(to,"Content-Type: ");   
        HTTPMSG(to,mimetype);   
        HTTPMSG(to,"/r/n/r/n");   
        while(writing) {   
            switch(rdsize = read(file,buf,sizeof(buf))) {   
                case -1:   
                    mywarn("read error on %s: %s/n",from,strerror(errno));   
                    ret = EXIT_FAILURE;   
                    /* fallthru */   
                case 0:   
                    writing = 0;   
                    break;   
                default :   
                    fwrite(buf,1,rdsize,to);   
            }   
        }   
        close(file);   
    } else {   
        mywarn("error opening /"%s/": %s/n",from,strerror(errno));   
        HTTPMSG(to,E403);   
    }   
    return ret;   
}   
   
/* enter a new string for a KEY=VALUE environment entry into  
 * the env array  
 */   
static void addenv(myenv *env, char *key, char *val)   
{   
    char *s;   
    int keylen = strlen(key);   
    int vallen = strlen(val);   
    if((s = malloc(keylen + 1 + vallen + 1))) {   
        strcpy(s,key);   
        s[keylen] = '=';   
        strcpy(s+keylen+1,val);   
        env->ptrs[env->nenv++] = s;   
    }   
}   
   
/* build an env array for CGIs */   
static char **buildenv(myenv *env,   
        reqtype method,   
        char *scriptname,   
        char *query,   
        char *peer)   
{   
    addenv(env,"REQUEST_METHOD",method_strings[method]);   
    // addenv(env,"PATH_INFO","");   
    // addenv(env,"PATH_TRANSLATED","");   
    addenv(env,"SCRIPT_NAME",scriptname);   
    // addenv(env,"REMOTE_HOST","");   
    addenv(env,"REMOTE_ADDR",peer);   
    if(query)   
        addenv(env,"QUERY_STRING",query);   
    return env->ptrs;   
}   
   
static reqtype check_reqtype(char *req)   
{   
    if(!strncmp("GET",req,3)) return M_GET;   
    if(!strncmp("HEAD",req,4)) return M_HEAD;   
    return M_INVALID;   
}   
   
static void handle_cgi(char *prog, char *query, reqtype method,   
        FILE *out, struct  sockaddr_in *peer)   
{   
    char *args[2] = {0};   
    int pid;   
    int pipefds[2];   
    FILE *pipefh;   
    mywarn("Executing %s/n",prog);   
    args[0] = prog;   
    HTTPMSG(out,M200);   
    fflush(out);   
    buildenv(&cgienv,method,prog,query,inet_ntoa(peer->sin_addr));   
    switch(method) {   
        case M_HEAD :   
            if(0 != pipe(pipefds)) {   
                myerror(EXIT_FAILURE,"pipe(): %s",strerror(errno));   
                break;   
            }   
            switch(pid = fork()) {   
                char buf[4096];   
   
                case -1 :   
                    myerror(EXIT_FAILURE,   
                            "error forking CGI process: %s/n",strerror(errno));   
                    break;   
                case 0 :   
                    dup2(pipefds[1],1);   
                    execve(prog,args,cgienv.ptrs);   
                    break; /* yeah right... */   
                default :   
                    pipefh = fdopen(pipefds[0],"r");   
                    while(fgets(buf,sizeof(buf),pipefh)) {   
                        fputs(buf,out);   
                        if('/r' == buf[0] && '/n' == buf[1])   
                            break;   
                    }   
                    fclose(pipefh);   
            }   
            break;   
   
        case M_GET:   
        default:   
            dup2(fileno(out),1);   
            execve(prog,args,cgienv.ptrs);   
            break;   
    }   
}   
   
static const char *find_mime_type(char *buf)   
{   
    const ext2mime *e2m;   
    int i,j;   
    for(i=0; (e2m=extensions[i]); ++i)   
        for(j=0; e2m->ext[j]; ++j)   
            if(!strcasecmp(buf,e2m->ext[j]))   
                return e2m->type;   
    return MIME_GENERIC;   
}   
   
/* read HTTP request and respond */   
static int handle_connection(int fd, struct sockaddr_in *peer)   
{   
    char buf[4096];   
    char *uri, *doc, *t, *query=NULL;   
    struct stat st;   
    int ret = EXIT_FAILURE;   
    reqtype method;   
    FILE *fh = fdopen(fd,"r+");   
   
    if(!fh) return ret;        /* very bad, don't bother with messages */   
       
   
    /* check for valid request: fgets() ok && 5<=req<=sizeof(buf) */   
    if(fgets(buf,sizeof(buf),fh) && strlen(buf) >= 5 &&   
            !(strlen(buf) >= sizeof(buf)-2 && '/0' != buf[sizeof(buf)-1])) {   
   
        /* ignore rest of request for now */   
        do {   
            char dummy[4096];   
            while(fgets(dummy,sizeof(dummy),fh)) {   
                if('/r' == dummy[0] && '/n' == dummy[1])   
                    break;   
            }   
        } while(0);   
   
        /* write HTTP version for reply */   
        fputs(HTTPV,fh);   
       
        switch(method = check_reqtype(buf)) {   
            case M_GET :   
                uri = buf + 4;   
                break;   
            case M_HEAD:   
                uri = buf + 5;   
                break;   
            default :   
                HTTPMSG(fh,E501);   
                goto leave;   
        }   
        doc = uri;   
        /* skip leading '/' */   
        *doc == '/' && ++doc;   
        /* zero-terminate document name, get optional query string */   
        for(t=doc; *t && !isspace(*t); ++t) {   
            if('?' == *t) {   
                query = t+1;   
                break;   
            }   
        }   
        *t = '/0';   
        /* if a query part is present, it still needs to be terminated */   
        if(query) {   
            for(++t; *t && !isspace(*t); ++t) /* just loop */ ;   
            *t = '/0';   
        }   
        /* top dir must be "." */   
        if(!strlen(doc))   
            doc = ".";   
        /* check if requested file/script exists, 404 if not */   
        if(0 == stat(doc,&st)) {   
            char const *mimetype = MIME_GENERIC;   
            /* check for directory */   
            if(S_ISDIR(st.st_mode)) {   
                ret = send_dir(doc,fh);   
                goto leave;   
            }   
            /* find file extension and infer MIME type */   
            char *ext = strrchr(doc,'.');   
            if(ext) {   
                int i;   
                /* check for CGI script */   
                ++ext;   
                for(i=0; i<NELEMS(cgiext); ++i) {   
                    if(!strcasecmp(cgiext[i],ext)) {   
                        handle_cgi(doc,query,method,fh,peer);   
                        return EXIT_SUCCESS;        /* we only get back here for HEAD! */   
                    }   
                }   
                /* delivery only */   
                mimetype = find_mime_type(ext);   
            }   
            /* can only use GET on plain files */   
            if(M_GET == method) ret = send_file(doc,fh,mimetype);   
            else HTTPMSG(fh,E400);   
        } else {   
            mywarn("File not found: '%s'/n",doc);   
            HTTPMSG(fh,E404);   
        }   
    } else {   
        fputs(HTTPV,fh);   
        HTTPMSG(fh,E400);   
    }   
leave:   
    fclose(fh);   
    return ret;   
}   
   
/* clean up dead children */   
static void child_reaper(int sig)   
{   
    int status, pid;   
   
    while(0 < (pid = waitpid(-1,&status,WNOHANG)))   
        mywarn("Child process %d exited with status %d/n",pid,status);   
}   
   
/* do some work */   
int main(int argc, char *argv[])   
{   
    int sock,as,sockopt=1;   
    struct sockaddr_in bindaddr, peer;   
    struct sigaction sa = {   
        .sa_handler = &child_reaper,   
        .sa_flags = SA_NOCLDSTOP   
    };   
   
    /* basename($0) */   
    progname = argv[0] + strlen(argv[0]);   
    while((progname > argv[0]) && (progname[-1] != '/'))   
        --progname;   
    eval_args(argc,argv);   
    port = htons(port);   
   
    /* set up method-to-string translation table */   
    method_strings[M_INVALID]    = "INVALID";   
    method_strings[M_GET]        = "GET";   
    method_strings[M_HEAD]        = "HEAD";   
       
    sock = socket(AF_INET,SOCK_STREAM,0);   
    if(-1 == sock)   
        myerror(EXIT_FAILURE,"socket: %s/n",strerror(errno));       
    setsockopt(sock,getprotobyname("tcp")->p_proto,   
            SO_REUSEADDR,&sockopt,sizeof(sockopt));   
    bindaddr.sin_family = PF_INET;   
    bindaddr.sin_port = port;   
    bindaddr.sin_addr.s_addr = addr;   
    if(-1 == bind(sock,(struct sockaddr*)&bindaddr,sizeof(bindaddr)))   
        myerror(EXIT_FAILURE,"bind: %s/n",strerror(errno));   
       
    if(daemonize) {   
        pid_t daemon = fork();   
        if(-1 == daemon)   
            myerror(EXIT_FAILURE,"cannot daemonize: %s/n",strerror(errno));   
        /* forked successfully, exit parent */   
        if(daemon)   
            exit(EXIT_SUCCESS);   
        /* child continues */   
        umask(0);   
        stderr = freopen(LOGFILENAME,"a+",stderr);   
        setlinebuf(stderr);   
        if(0 == stderr)   
            myerror(EXIT_FAILURE,"cannot open log /"%s/": %s/n",   
                    LOGFILENAME,strerror(errno));   
        close(STDIN_FILENO);   
        close(STDOUT_FILENO);   
        setsid(); /* should always succeed in child */   
    }   
       
    listen(sock,10);   
   
    sigaction(SIGCHLD,&sa,NULL);   
   
    /* fill constant elements in CGI's env array already */   
    addenv(&cgienv,"SERVER_NAME",addrstr);   
    addenv(&cgienv,"SERVER_PORT",portstr);   
       
    while(1) {   
        int pid;   
        socklen_t peerlen=sizeof(peer);   
           
        mywarn("Waiting for connections on port %d/n",ntohs(port));   
        as = accept(sock,(struct sockaddr*)&peer,&peerlen);   
        if(-1 == as) {   
            if(EINTR != errno)   
                mywarn("accept: %s/n",strerror(errno));   
            continue;   
        }   
        switch(pid = fork()) {   
            case -1 :   
                mywarn("error forking connection handler: %s/n",strerror(errno));   
                break;   
            case 0 :   
                close(sock);   
                mywarn("Accepted connection from %s:%d/n",   
                        inet_ntoa(peer.sin_addr),ntohs(peer.sin_port));   
                exit(handle_connection(as,&peer));   
            default :   
                close(as);   
        }   
    }   
    close(sock);   
    return EXIT_SUCCESS;   
}   
   
/* vi: set ts=3 sw=3 noet cindent: */   
[c-sharp] view plain copy
   
/*  
 * cheetah.c  
 *  
 * Copyright (C) 2003 Luke Reeves (luke@neuro-tech.net)  
 * http://www.neuro-tech.net/  
 *  
 * This program is free software; you can redistribute it and/or modify it  
 * under the terms of the GNU General Public License as published by the  
 * Free Software Foundation; either version 2, or (at your option) any  
 * later version.  
 *  
 * This program is distributed in the hope that it will be useful, but  
 * WITHOUT ANY WARRANTY; without even the implied warranty of  
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  
 * General Public License for more details.  
 *  
 */   
  
#include "config.h"   
  
#ifdef HAVE_SYS_SENDFILE_H   
#include <sys/sendfile.h>   
#endif   
#include <sys/wait.h>   
#include <string.h>   
#include <stdio.h>   
#include <time.h>   
#include <stdlib.h>   
#include <unistd.h>   
#include <sys/mman.h>   
#include <dirent.h>   
#include <signal.h>   
#include <sys/stat.h>   
#include <fcntl.h>   
#include <sys/socket.h>   
#include <time.h>   
#include <netdb.h>   
#include <arpa/inet.h>   
#include <netinet/in.h>   
#include <errno.h>   
  
#define METHOD_GET 0   
#define METHOD_HEAD 1   
#define METHOD_UNSUPPORTED -1   
#define SERVER_NAME "Cheetah"   
   
/* Globals */   
char * default_type = "text/plain";   
int generate_index = 0;   
int verbose = 0;   
int background = 0;   
int sockfd = -1;   
int print_headers = 0; /* Print headers to screen. */   
int loglevel = 0;   
int links = 0;   
   
/* Linked list of files being shared. This is much slower than simply opening  
 * files off disk (and I'm too lazy to write a hashtable), but this is a much  
 * more safe and secure way. */   
typedef struct FSTRUCT {   
     char * filename;   
     char * fullpath;   
     void * next;   
   
     /* Only for internal files */   
     char * content;   
     int content_length;   
     char * content_type;   
     char * last_modified;   
} servable;   
servable * files = NULL;   
servable * index_page = NULL;   
   
static void help() {   
     printf("Usage: cheetah [OPTIONS] [DIRECTORY]/n");   
     printf("Serves up the files listed in the specified directory using HTTP./n");   
     printf("Note that the list of files is scanned on startup only - to rescan the files/n");   
     printf("for additions, you must restart cheetah./n/n");   
     printf("-d, --default-type   default mime-type if file isn't found in the database,/n");   
     printf("                       defaults to text/plain/n");   
     printf("-b                   background mode (disables console output, and allows/n");   
     printf("                       multiple requests to be served simultaneously)/n");   
     printf("-g                   generate indices for the root directory when no index.html/n");   
     printf("                       is found/n");   
     printf("    --headers        print out all client request headers/n");   
     printf("-l, --log            log (in combined log format) all requests to standard/n");   
     printf("                       output/n");   
     printf("-p, --port           port to listen for requests on, defaults to 8000/n");   
     printf("-s                   follow symbolic links/n");   
     printf("-v                   verbose output/n");   
     printf("-V                   print version and exit/n");   
     printf("-h, --help           display this message and exit/n");   
     printf("/n");   
     printf("Please see http://www.neuro-tech.net/cheetah for updates and bug reporting./n");   
}   
   
char * msg404 = "<html><head><title>404 Not Found</title></head><body>/   
<h1>404 Not Found</h1><h2>The document requested was not found.</h2></body></html>/n";   
   
/* SIGHUP handler */   
static void sigcatch(int signal);   
   
/* Prototypes */   
static void handle_request(int fd, struct sockaddr_in * remote);   
static servable * gen_index();   
static void handle_connection(int fd, struct sockaddr_in * remote);   
static int get_method(char * req);   
static servable * match_request(char * req);   
static int safesend(int fd, char * out);   
static char * get_mimetype(char * file);   
static void crit(char * message);   
static void warn(char * message);   
static void * smalloc(size_t size);   
   
int main(int argc, char *argv[]) {   
     int port = 8000;   
     struct sockaddr_in my_addr;   
     struct sockaddr_in remote_addr;   
     int sin_size;   
     int flength;   
     char * fullpath = NULL;   
     char * dir = NULL;   
     DIR * dirpnt;   
     struct dirent * curdir = NULL;   
     struct stat curstat;   
     servable * curfile = NULL;   
     servable * lastfile = NULL;   
     int newfd;   
     int i, fr, rv;   
   
     /* Parse options */   
     if(argc < 2) { help(); exit(0); }   
   
     for(i = 1; i < argc; i++) {   
           if(strcmp(argv[i], "-V") == 0) {   
                 printf("You are using %s./n", SERVER_NAME);   
                 exit(0);   
           } else if((strcmp(argv[i], "--help") == 0) || (strcmp(argv[i], "-h") == 0)) {   
                 help();   
                 exit(0);   
           } else if((strcmp(argv[i], "--default-type") == 0) || (strcmp(argv[i], "-d") == 0)) {   
                 default_type = argv[i+1]; i++;   
           } else if((strcmp(argv[i], "--headers") == 0) || (strcmp(argv[i], "-h") == 0)) {   
                 print_headers = 1;   
           } else if((strcmp(argv[i], "-p") == 0) || (strcmp(argv[i], "--port") == 0)) {   
                 port = atoi(argv[i + 1]); i++;   
           } else if((strcmp(argv[i], "-l") == 0) || (strcmp(argv[i], "--log") == 0)) {   
                 loglevel = 1;   
           } else if(strcmp(argv[i], "-v") == 0) { verbose++;   
           } else if(strcmp(argv[i], "-g") == 0) { generate_index = 1;   
           } else if(strcmp(argv[i], "-s") == 0) { links = 1;   
           } else if(strcmp(argv[i], "-b") == 0) { background = 1; }   
     }   
   
     dir = argv[argc - 1];   
     dirpnt = opendir(dir);   
     if(dirpnt == NULL) {   
           printf("Invalid directory - %s./n", dir); help(); exit(1);   
     }   
   
     if(background) {   
           verbose = 0;   
           rv = fork();   
           if(rv == -1) {   
                 crit("Error forking");   
           } else if(rv > 0) {   
                 /* Exit if this is the parent */   
                 _exit(0);   
           }   
           if(setsid() == -1) crit("Couldn't create SID session.");   
           if(signal(SIGCHLD, SIG_IGN) == SIG_ERR) {   
                 crit("Couldn't initialize signal handlers.");   
           }   
           if( (close(0) == -1) || (close(1) == -1) || (close(2) == -1)) {   
                 crit("Couldn't close streams.");   
           }   
     }   
   
     while((curdir = readdir(dirpnt))) {   
           flength = strlen(curdir->d_name) + strlen(dir) + 4;   
           fullpath = (char *)smalloc(flength);   
           snprintf(fullpath, flength + 2, "%s/%s", dir, curdir->d_name);   
           if(links == 1) {   
                 rv = lstat(fullpath, &curstat);   
           } else {   
                 rv = stat(fullpath, &curstat);   
           }   
   
           if(rv != 0) {   
                 fprintf(stderr, "Error statting file %s/%s/n", dir, curdir->d_name);   
                 continue;   
           }   
   
           /* Only use this file if it's not a link, directory, etc. */   
           if(S_ISREG(curstat.st_mode) && ( curdir->d_name[0] != '.' )) {   
                 if(files == NULL) {   
                       curfile = files = (void *)smalloc(sizeof(servable) + 2);   
                 } else {   
                       curfile = (void *)smalloc(sizeof(servable) + 2);   
                 }   
   
                 flength = strlen(curdir->d_name);   
                 curfile->filename = (void *)smalloc(flength + 2);   
                 strncpy(curfile->filename, curdir->d_name, flength + 1);   
                 curfile->fullpath = fullpath;   
                 curfile->next = NULL;   
                 curfile->content = NULL;   
   
                 if(lastfile == NULL) {   
                       lastfile = curfile;   
                 } else {   
                       lastfile->next = curfile;   
                       lastfile = curfile;   
                 }   
   
                 if(verbose) printf("Parsed %s as %s./n", fullpath, curfile->filename);   
           } else {   
                 free(fullpath);   
           }   
     }   
   
     /* Generate index */   
     if(generate_index == 1) index_page = gen_index();   
  
#ifdef HAVE_SYS_SENDFILE_H   
     if(verbose) printf("Using system's sendfile functionality./n");   
#endif   
   
     /* Trap signals */   
     if( (signal(SIGTERM, sigcatch) == SIG_ERR) || (signal(SIGINT, sigcatch) == SIG_ERR)) {   
           crit("Couldn't setup signal traps.");   
     }   
   
     sockfd = socket (AF_INET, SOCK_STREAM, 0);   
     if(sockfd == -1) crit("Couldn't create socket.");   
   
     my_addr.sin_family = AF_INET;   
     my_addr.sin_port = htons (port);   
     my_addr.sin_addr.s_addr = INADDR_ANY;   
     bzero (&(my_addr.sin_zero), 8);   
   
     if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof (struct sockaddr)) == -1)   
           crit("Couldn't bind to specified port.");   
   
     sin_size = sizeof(struct sockaddr_in);   
   
     if(listen(sockfd, 25) == -1) crit("Couldn't listen on specified port.");   
   
     if(verbose) printf("Listening for connections on port %d.../n", port);   
     while(1) {   
           newfd = accept(sockfd, (struct sockaddr *)&remote_addr, &sin_size);   
           if(newfd == -1) crit("Couldn't accept connection!");   
   
           if(verbose) printf("Connected, handling request./n");   
   
           if(background) {   
                 fr = fork();   
                 if(fr != 0) continue;   
                 handle_connection(newfd, (struct sockaddr_in *)&remote_addr);   
                 _exit(0);   
           }   
           handle_connection(newfd, (struct sockaddr_in *)&remote_addr);   
     }   
}   
   
/* Cygwin doesn't like my time structures. It's on my todo list. */   
#ifndef __CYGWIN__   
static char * last_modified(time_t * stmtime) {   
     struct tm * gmt;   
     char * rv = (char *)smalloc(100);   
     if((gmt = gmtime(stmtime)) == NULL) crit("gmtime() error.");   
     if((strftime(rv, 95, "%a, %d %b %Y %T GMT", gmt)) == 0)   
           crit("strftime() error.");   
     return rv;   
}   
   
static char * curtime() {   
     struct tm * gmt;   
     char * rv = (char *)smalloc(100);   
     time_t t = time(NULL);   
     if((gmt = gmtime(&t)) == NULL) crit("gmtime() error.");   
     if((strftime(rv, 95, "%d/%b/%Y:%T +0000", gmt)) == 0)   
           crit("strftime() error.");   
     return rv;   
}   
#else   
static char * last_modified(int mtime) { return NULL; }   
static char * curtime() { return "-"; }   
#endif   
   
static void handle_connection(int fd, struct sockaddr_in * remote) {   
     handle_request(fd, remote);   
   
     /* Shutdown socket */   
     if(shutdown(fd, SHUT_RDWR) == -1) {   
           warn("Error shutting down client socket.");   
           return;   
     }   
   
     if(close(fd) == -1) warn("Error closing client socket.");   
}   
   
static void loghit(char * req, char *referrer, char *ua, int code, int size, struct sockaddr_in * remote) {   
     char * t = curtime(); char *i;   
     if( (i = strchr(referrer, ' ')) == NULL) referrer = "-";   
     else referrer = i + 1;   
     if( (i = strchr(ua, ' ')) == NULL) ua = "-";   
     else ua = i + 1;   
     printf("%s - - [%s] - /"%s/" %d %d /"%s/" /"%s/"/n",   
           inet_ntoa(remote->sin_addr), t, req, code, size, referrer, ua);   
     fflush(stdout);   
     if(t[0] != '-') free(t);   
}   
   
static void handle_request(int fd, struct sockaddr_in * remote) {   
     int flength;   
     int method;   
     struct stat curstat;   
     int rv, c, infd, h = 0;   
     char inbuffer[2048];   
     char *out;   
     char *lastmod;   
     char outb[1024];   
     char * referrer = "-"; char * ua = ""; char * request = NULL;   
     char * header; /* newline terminated header. */   
     int content_length = 0;   
     servable * file;   
   
     rv = recv(fd, inbuffer, sizeof(inbuffer), 0);   
     if(rv == -1) {   
           warn("Error receiving request from client.");   
           return;   
     }   
   
     /** Read headers and request line. */   
     for(c = 0; c < rv; c++) {   
           if(inbuffer[c] == '/n') {   
                 inbuffer[c] = '/0';   
                 if((c > 1) && (inbuffer[c - 1] == '/r')) inbuffer[c-1] = '/0';   
                 if(h != 0) {   
                       header = inbuffer + h;   
                       if(print_headers) printf("%s/n", header);   
                       if(strncmp(header, "Referer:", 8) == 0) referrer = header;   
                       if(strncmp(header, "User-Agent:", 11) == 0) ua = header;   
                 } else {   
                       request = inbuffer;   
                       if(print_headers) printf("%s/n", request);   
                 }   
   
                 h = c + 1;   
           }   
     }   
   
     if(request == NULL) { return; /* TODO: Return error */ }   
     if(verbose) printf("REQ: %s/n", request);   
     method = get_method(request);   
   
     /* Find file in linked list */   
     file = match_request(request);   
   
     if(file == NULL) {   
           out = "HTTP/1.0 404 Not Found/r/n";   
           if(safesend(fd, out) == -1) return;   
              
           snprintf(outb, sizeof(outb), "Server: %s/%s/r/n",   
                       SERVER_NAME, VERSION);   
           if(safesend(fd, outb) == -1) return;   
   
           if(method = METHOD_GET) {   
                 out = "Content-Type: text/html; charset=iso-8859-1/r/n";   
                 if(safesend(fd, out) == -1) return;   
   
                 snprintf(outb, sizeof(outb), "Content-Length: %d/r/n",   
                             strlen(msg404));   
                 if(safesend(fd, outb) == -1) return;   
              
                 // Send error response   
                 c = strlen(msg404);   
                 if(safesend(fd, msg404) == -1) return;   
           }   
   
           snprintf(outb, sizeof(outb), "/r/n");   
           if(safesend(fd, outb) == -1) return;   
   
           if(loglevel) loghit(request, referrer, ua, 404, c, remote);   
           return;   
     }   
   
     /* Response status line */   
     out = "HTTP/1.0 200 OK/r/n";   
     if(safesend(fd, out) == -1) return;   
   
     if(file->filename != NULL) {   
           /* Get file stats */   
           if(lstat(file->fullpath, &curstat) == -1) {   
                 warn("Error checking file."); return;   
           }   
   
           /* Response headers */   
           snprintf(outb, sizeof(outb), "Content-Type: %s/r/n", get_mimetype(file->filename));   
           if(safesend(fd, outb) == -1) return;   
   
           lastmod = last_modified(&curstat.st_mtime);   
           if(lastmod != NULL) {   
                 snprintf(outb, sizeof(outb), "Last-modified: %s/r/n", lastmod);   
                 if(safesend(fd, outb) == -1) return;   
                 free(lastmod);   
           }   
   
           if(method == METHOD_GET) {   
                 snprintf(outb, sizeof(outb), "Content-Length: %d/r/n",   
                       (int)curstat.st_size);   
                 if(safesend(fd, outb) == -1) return;   
           }   
              
           snprintf(outb, sizeof(outb), "Server: %s/%s/r/n/r/n",    
                       SERVER_NAME, VERSION);   
           if(safesend(fd, outb) == -1) return;   
   
           /* Response content */   
           if(method == METHOD_GET) {   
                 infd = open(file->fullpath, O_RDONLY);   
                 if(infd == -1) {   
                       printf("Couldn't open %s, error %d/n",   
                                   file->fullpath, errno);   
                       return;   
                 }   
#ifdef HAVE_SYS_SENDFILE_H   
                 if(sendfile(fd, infd, 0, curstat.st_size) == -1) {   
                       warn("Error sending response to client."); return;   
                 }   
#else   
                 while((rv = read(infd, outb, sizeof(outb)) ) != 0) {   
                       if(write(fd, outb, rv) == -1) {   
                             warn("Error sending response to client."); return;   
                       }   
                 }   
#endif   
                 close(infd);   
           }   
   
           if(loglevel) loghit(request, referrer, ua, 200, curstat.st_size, remote);   
     } else {   
           /* Use our internal file */   
           content_length = 0;   
           if(method == METHOD_GET) {   
                 content_length = file->content_length;   
           }   
              
           if(file->last_modified != 0) {   
                 snprintf(outb, sizeof(outb), "Last-Modified: %s/r/n",   
                             file->last_modified);   
                 if(safesend(fd, outb) == -1) return;   
           }   
              
           snprintf(outb, sizeof(outb), "Content-Type: %s/r/nContent-Length: %d/r/n/r/n",   
                             file->content_type, content_length);   
           if(safesend(fd, outb) == -1) return;   
   
           if(loglevel) loghit(request, referrer, ua, 200, file->content_length, remote);   
           if(method == METHOD_GET) {   
                 if(safesend(fd, file->content) == -1) return;   
           }   
     }   
}   
   
static int get_method(char * req) {   
     if(strncasecmp(req, "GET",  3) == 0) { return METHOD_GET; }   
     if(strncasecmp(req, "HEAD", 4) == 0) { return METHOD_HEAD; }   
     return METHOD_UNSUPPORTED;   
}   
   
static servable * gen_index() {   
     servable * myi = NULL;   
     servable * ptr = files;   
     char * content = NULL;   
   
     /* Big ass embedded string. I know, it be ugly. */   
     char * st = "<!DOCTYPE html PUBLIC /"-//W3C//DTD XHTML 1.0 Transitional//EN/" /"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd/">/r/n/r/n<html><head><title>Index of /</title></head><body><h2>Index of /</h2><ul>/n";   
     char * en = "</ul><p><i>Powered by <a href="/" mce_href="/""http://www.neuro-tech.net/cheetah/">Cheetah</a></i>.</body></html>/n";   
     int sz = 0;   
     myi = smalloc(sizeof(servable) + 2);   
     myi->filename = NULL;   
     myi->fullpath = NULL;   
   
     sz = strlen(st) + strlen(en);   
     content = smalloc(sz + 2);   
   
     strncpy(content, st, sz + 1);   
   
     /* Might be slow, but it's only run once. */   
     while(ptr != NULL) {   
           sz += (strlen(ptr->filename)) * 2;   
           sz += 40;   
           if(!realloc(content, sz)) { printf("Memory allocation error./n"); exit(0); }   
           strcat(content, "<li><a href="/" mce_href="/""");   
           strcat(content, ptr->filename);   
           strcat(content, "/">");   
           strcat(content, ptr->filename);   
           strcat(content, "</a></li>/n");   
           ptr = ptr->next;   
     }   
   
     strcat(content, en);   
     myi->content = content;   
     myi->content_length = strlen(content);   
     myi->content_type = "text/html";   
     myi->last_modified = NULL;   
   
     return myi;   
}   
   
static servable * match_request(char * req) {   
     servable * rv = NULL;   
     char uri[1024]; char * u;   
     int c; int in = 0; int ptr = 0;   
   
     /* Parse filename */   
     for(c = 0; c < strlen(req); c++) {   
           if(in == 1) uri[ptr++] = req[c];   
           if((in == 2) || (ptr > 1000)) break;   
           if(req[c] == ' ') in++;   
     }   
     uri[ptr] = '/0'; u = uri;   
   
     if(strcmp(uri, "/ ") == 0) {   
           if(generate_index == 1) { return index_page; }   
           else { strncpy(uri, "/index.html", sizeof(uri)); }   
     }   
     if(uri[0] == '/') u++;   
     if(verbose) printf("Checking for /"%s/"/n", u);   
     if(files == NULL) { return NULL; }   
   
     rv = files;   
     while(1) {   
           if(strncmp(u, rv->filename, strlen(rv->filename)) == 0) return rv;   
           if(rv->next == NULL) return NULL;   
           rv = rv->next;   
     }   
   
     return NULL;   
}   
   
static int safesend(int fd, char * out) {   
     int rv;   
        
     if((rv = send(fd, out, strlen(out), 0)) == -1) {   
           warn("Error sending data to client.");   
     }   
   
     return rv;   
}   
   
static void sigcatch(int signal) {   
     if(verbose) printf("Signal caught, exiting./n");   
     if(sockfd != -1) {   
           close(sockfd);   
           exit(0);   
     }   
}   
   
static char * get_mimetype(char * file) {   
     char * comp;   
   
     for(comp = file + strlen(file); comp > file; comp--) {   
           if(comp[0] == '.') {   
                 comp++;   
                 if(strcasecmp(comp, "html") == 0) return "text/html";   
                 if(strcasecmp(comp, "gif") == 0) return "image/gif";   
                 if(strcasecmp(comp, "jpg") == 0) return "image/jpeg";   
                 if(strcasecmp(comp, "png") == 0) return "image/png";   
                 if(strcasecmp(comp, "css") == 0) return "text/css";   
                 return default_type;   
           }   
     }   
   
     return default_type;   
}   
   
static void crit(char * message) {   
     fprintf(stderr, "%s/n", message);   
     exit(1);   
}   
   
static void warn(char * message) {   
     fprintf(stderr, "%s/n", message);   
}   
   
static void * smalloc(size_t size) {   
     void * rv = malloc(size);   
     if(rv == NULL) crit("Memory allocation error.");   
     return rv;   
}   
