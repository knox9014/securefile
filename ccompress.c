/*
 * ccompress.c - mycompress.py 와 동일한 알고리즘의 C 구현
 *   LZ77 + 산술 부호화 + 블록 store 모드
 *   파이썬 버전과 출력 포맷 호환 (C로 압축 -> 파이썬으로 복원 가능)
 *
 * 사용법:  ccompress c <입력> <출력>   (압축)
 *          ccompress d <입력> <출력>   (해제)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define TOP       (1u<<24)
#define BOT       (1u<<16)
#define MAX_TOTAL (1<<16)

#define WINDOW    (1<<20)
#define MIN_MATCH 3
#define MAX_MATCH 258
#define CHAIN_CAP 128
#define BLOCK     (1<<20)
#define HSIZE     (1<<16)

/* ---------- 가변 버퍼 ---------- */
typedef struct { uint8_t *buf; size_t len, cap; } Buf;
static void buf_init(Buf *b){ b->cap=1024; b->buf=malloc(b->cap); b->len=0; }
static void buf_push(Buf *b, uint8_t v){
    if(b->len>=b->cap){ b->cap*=2; b->buf=realloc(b->buf,b->cap); }
    b->buf[b->len++]=v;
}
static void buf_append(Buf *b, const uint8_t *d, size_t n){
    while(b->len+n>b->cap){ b->cap*=2; b->buf=realloc(b->buf,b->cap); }
    memcpy(b->buf+b->len, d, n); b->len+=n;
}

/* ---------- 적응형 빈도 모델 ---------- */
typedef struct { int nsym; uint32_t freq[257]; uint32_t total; } FM;
static void fm_init(FM *m,int n){ m->nsym=n; m->total=(uint32_t)n; for(int i=0;i<n;i++) m->freq[i]=1; }
static void fm_cum(FM *m,int sym,uint32_t *lo,uint32_t *hi){
    uint32_t s=0; for(int i=0;i<sym;i++) s+=m->freq[i]; *lo=s; *hi=s+m->freq[sym];
}
static int fm_find(FM *m,uint32_t value,uint32_t *clo,uint32_t *chi){
    uint32_t lo=0;
    for(int i=0;i<m->nsym;i++){ uint32_t f=m->freq[i];
        if(lo+f>value){ *clo=lo; *chi=lo+f; return i; } lo+=f; }
    return -1;
}
static void fm_update(FM *m,int sym){
    m->freq[sym]+=32; m->total+=32;
    if(m->total>=MAX_TOTAL){ m->total=0;
        for(int i=0;i<m->nsym;i++){ m->freq[i]=(m->freq[i]+1)>>1; m->total+=m->freq[i]; } }
}

/* ---------- range coder (바이트 단위, carryless / Subbotin) ---------- */
typedef struct { Buf *out; uint32_t low, rng; } RC;
static void rc_init(RC *e,Buf *out){ e->out=out; e->low=0; e->rng=0xFFFFFFFFu; }
static void rc_encode(RC *e,FM *m,int sym){
    uint32_t clo,chi; fm_cum(m,sym,&clo,&chi);
    uint32_t r=e->rng/m->total;
    e->low += clo*r;
    e->rng  = r*(chi-clo);
    while( (e->low ^ (e->low+e->rng)) < TOP || (e->rng<BOT && ((e->rng = -e->low & (BOT-1)),1)) ){
        buf_push(e->out, (uint8_t)(e->low>>24)); e->low<<=8; e->rng<<=8;
    }
    fm_update(m,sym);
}
static void rc_finish(RC *e){
    for(int i=0;i<4;i++){ buf_push(e->out,(uint8_t)(e->low>>24)); e->low<<=8; }
}

typedef struct { const uint8_t *data; size_t len,pos; uint32_t low,rng,code; } RD;
static uint8_t rd_byte(RD *d){ uint8_t b = d->pos<d->len? d->data[d->pos]:0; d->pos++; return b; }
static void rd_init(RD *d,const uint8_t *p,size_t len){
    d->data=p; d->len=len; d->pos=0; d->low=0; d->rng=0xFFFFFFFFu; d->code=0;
    for(int i=0;i<4;i++) d->code=(d->code<<8)|rd_byte(d);
}
static int rd_decode(RD *d,FM *m){
    uint32_t r=d->rng/m->total;
    uint32_t value=(d->code-d->low)/r;
    if(value>=m->total) value=m->total-1;
    uint32_t clo,chi; int sym=fm_find(m,value,&clo,&chi);
    d->low += clo*r;
    d->rng  = r*(chi-clo);
    while( (d->low ^ (d->low+d->rng)) < TOP || (d->rng<BOT && ((d->rng = -d->low & (BOT-1)),1)) ){
        d->code=(d->code<<8)|rd_byte(d); d->low<<=8; d->rng<<=8;
    }
    fm_update(m,sym);
    return sym;
}

static uint32_t hash3(const uint8_t *p){
    return (((uint32_t)p[0]*65599u + p[1])*65599u + p[2]) & (HSIZE-1);
}

/* 위치 pos에서 최선의 매치를 찾아 길이를 반환, 거리는 *outdist */
static int find_match(const uint8_t *d,int n,int pos,int *head,int *prev,int *outdist){
    int best_len=0,best_dist=0;
    if(pos+MIN_MATCH<=n){
        uint32_t h=hash3(d+pos); int j=head[h], chain=0;
        int maxl=n-pos; if(maxl>MAX_MATCH) maxl=MAX_MATCH;
        while(j>=0 && chain<CHAIN_CAP){
            if(pos-j>WINDOW) break;
            int l=0; while(l<maxl && d[j+l]==d[pos+l]) l++;
            if(l>best_len){ best_len=l; best_dist=pos-j; if(l>=maxl) break; }
            j=prev[j]; chain++;
        }
    }
    *outdist=best_dist; return best_len;
}

/* ---------- 한 블록 압축 (LZ77 lazy matching + AC) ---------- */
static void compress_block(const uint8_t *d,int n,Buf *out){
    FM flag,len,dh,dm,dl;
    FM *lit_ctx=malloc(256*sizeof(FM));               /* order-1: 문맥(앞 글자)별 리터럴 모델 */
    fm_init(&flag,3); fm_init(&len,256); fm_init(&dh,256); fm_init(&dm,256); fm_init(&dl,256);
    for(int k=0;k<256;k++) fm_init(&lit_ctx[k],256);
    RC e; rc_init(&e,out);
    int *head=malloc(HSIZE*sizeof(int)); for(int x=0;x<HSIZE;x++) head[x]=-1;
    int *prev=malloc((n>0?n:1)*sizeof(int));
    int pb=0;                                          /* 직전 출력 바이트(문맥) */

    #define INSERT(p) do{ if((p)+MIN_MATCH<=n){ uint32_t _h=hash3(d+(p)); prev[(p)]=head[_h]; head[_h]=(p); } }while(0)
    #define EMIT_LIT(B) do{ rc_encode(&e,&flag,0); rc_encode(&e,&lit_ctx[pb],(B)); pb=(B); }while(0)
    #define EMIT_MATCH(L,D,LASTPOS) do{ rc_encode(&e,&flag,1); rc_encode(&e,&len,(L)-MIN_MATCH); \
        int _dd=(D)-1; rc_encode(&e,&dh,(_dd>>16)&0xFF); rc_encode(&e,&dm,(_dd>>8)&0xFF); rc_encode(&e,&dl,_dd&0xFF); \
        pb=d[(LASTPOS)]; }while(0)

    int i=0, have_prev=0, prev_len=0, prev_dist=0, prev_pos=0;
    while(i<n){
        int cur_dist, cur_len=find_match(d,n,i,head,prev,&cur_dist);
        INSERT(i);                       /* 자기 자신 매칭 방지 위해 탐색 후 삽입 */
        if(have_prev){
            if(cur_len>prev_len){        /* i+1이 더 김 -> 이전 시작 바이트는 리터럴 */
                EMIT_LIT(d[prev_pos]);
                prev_len=cur_len; prev_dist=cur_dist; prev_pos=i; i++;
            } else {                     /* 이전 매치 확정 */
                EMIT_MATCH(prev_len,prev_dist,prev_pos+prev_len-1);
                int end=prev_pos+prev_len;
                for(int p=i+1;p<end;p++) INSERT(p);
                i=end; have_prev=0;
            }
        } else {
            if(cur_len>=MIN_MATCH){ have_prev=1; prev_len=cur_len; prev_dist=cur_dist; prev_pos=i; i++; }
            else { EMIT_LIT(d[i]); i++; }
        }
    }
    if(have_prev) EMIT_MATCH(prev_len,prev_dist,prev_pos+prev_len-1);
    rc_encode(&e,&flag,2);
    rc_finish(&e);
    #undef INSERT
    #undef EMIT_LIT
    #undef EMIT_MATCH
    free(head); free(prev); free(lit_ctx);
}

/* ---------- 한 블록 해제 ---------- */
static void decompress_block(const uint8_t *p,int plen,Buf *out){
    FM flag,len,dh,dm,dl;
    FM *lit_ctx=malloc(256*sizeof(FM));
    fm_init(&flag,3); fm_init(&len,256); fm_init(&dh,256); fm_init(&dm,256); fm_init(&dl,256);
    for(int k=0;k<256;k++) fm_init(&lit_ctx[k],256);
    RD d; rd_init(&d,p,(size_t)plen);
    int pb=0;
    for(;;){
        int f=rd_decode(&d,&flag);
        if(f==2) break;
        if(f==0){
            int b=rd_decode(&d,&lit_ctx[pb]); buf_push(out,(uint8_t)b); pb=b;
        }
        else{
            int l=rd_decode(&d,&len)+MIN_MATCH;
            int dd=(rd_decode(&d,&dh)<<16)|(rd_decode(&d,&dm)<<8)|rd_decode(&d,&dl);
            size_t start=out->len-(size_t)(dd+1);
            for(int k=0;k<l;k++){ uint8_t v=out->buf[start+k]; buf_push(out,v); }
            pb=out->buf[out->len-1];
        }
    }
    free(lit_ctx);
}

/* ---------- 전체 압축/해제 (블록 framing) ---------- */
static void put_be32(Buf *b,uint32_t v){
    buf_push(b,(v>>24)&0xFF); buf_push(b,(v>>16)&0xFF); buf_push(b,(v>>8)&0xFF); buf_push(b,v&0xFF);
}
static void compress_all(const uint8_t *data,size_t n,Buf *out){
    for(size_t off=0; off<n; off+=BLOCK){
        int blen=(int)((n-off<BLOCK)?(n-off):BLOCK);
        Buf comp; buf_init(&comp);
        compress_block(data+off,blen,&comp);
        if(comp.len < (size_t)blen){
            buf_push(out,1); put_be32(out,(uint32_t)comp.len); buf_append(out,comp.buf,comp.len);
        } else {
            buf_push(out,0); put_be32(out,(uint32_t)blen); buf_append(out,data+off,blen);
        }
        free(comp.buf);
    }
}
static void decompress_all(const uint8_t *data,size_t n,Buf *out){
    size_t i=0;
    while(i<n){
        int mode=data[i++];
        uint32_t ln=((uint32_t)data[i]<<24)|((uint32_t)data[i+1]<<16)|((uint32_t)data[i+2]<<8)|data[i+3]; i+=4;
        if(mode==1) decompress_block(data+i,(int)ln,out);
        else        buf_append(out,data+i,ln);
        i+=ln;
    }
}

static uint8_t* read_file(const char *path,size_t *len){
    FILE *f=fopen(path,"rb"); if(!f){ perror("open"); exit(1); }
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t *b=malloc(sz>0?sz:1); fread(b,1,sz,f); fclose(f); *len=(size_t)sz; return b;
}
static void write_file(const char *path,const uint8_t *d,size_t n){
    FILE *f=fopen(path,"wb"); if(!f){ perror("write"); exit(1); }
    fwrite(d,1,n,f); fclose(f);
}

int main(int argc,char **argv){
    if(argc!=4 || (argv[1][0]!='c' && argv[1][0]!='d')){
        fprintf(stderr,"usage: %s c|d <in> <out>\n",argv[0]); return 1;
    }
    size_t n; uint8_t *data=read_file(argv[2],&n);
    Buf out; buf_init(&out);
    if(argv[1][0]=='c') compress_all(data,n,&out);
    else                decompress_all(data,n,&out);
    write_file(argv[3],out.buf,out.len);
    free(data); free(out.buf);
    return 0;
}
