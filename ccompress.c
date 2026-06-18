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

#define PREC      32
#define HALF      (1ULL<<31)
#define QUARTER   (1ULL<<30)
#define THREE_Q   (3ULL<<30)
#define MASKV     0xFFFFFFFFULL
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

/* ---------- 비트 입출력 (MSB first) ---------- */
typedef struct { Buf *out; uint8_t acc; int nbits; } BW;
static void bw_bit(BW *w,int bit){
    w->acc=(uint8_t)((w->acc<<1)|(bit&1));
    if(++w->nbits==8){ buf_push(w->out,w->acc); w->acc=0; w->nbits=0; }
}
static void bw_finish(BW *w){
    if(w->nbits){ w->acc=(uint8_t)(w->acc<<(8-w->nbits)); buf_push(w->out,w->acc); w->acc=0; w->nbits=0; }
}
typedef struct { const uint8_t *data; size_t len,pos; uint8_t acc; int nbits; } BR;
static int br_bit(BR *r){
    if(r->nbits==0){ r->acc = (r->pos<r->len)? r->data[r->pos]:0; r->pos++; r->nbits=8; }
    r->nbits--; return (r->acc>>r->nbits)&1;
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

/* ---------- 산술 부호화기 ---------- */
typedef struct { uint64_t low,high,pending; BW *bw; } AE;
static void ae_emit(AE *e,int bit){
    bw_bit(e->bw,bit);
    while(e->pending>0){ bw_bit(e->bw,bit^1); e->pending--; }
}
static void ae_encode(AE *e,FM *m,int sym){
    uint32_t clo,chi; fm_cum(m,sym,&clo,&chi); uint64_t total=m->total;
    uint64_t rng=e->high-e->low+1;
    e->high=e->low+(rng*chi)/total-1;
    e->low =e->low+(rng*clo)/total;
    for(;;){
        if(e->high<HALF) ae_emit(e,0);
        else if(e->low>=HALF){ ae_emit(e,1); e->low-=HALF; e->high-=HALF; }
        else if(e->low>=QUARTER && e->high<THREE_Q){ e->pending++; e->low-=QUARTER; e->high-=QUARTER; }
        else break;
        e->low=(e->low<<1)&MASKV; e->high=((e->high<<1)|1)&MASKV;
    }
    fm_update(m,sym);
}
static void ae_finish(AE *e){ e->pending++; ae_emit(e, e->low<QUARTER?0:1); }

typedef struct { uint64_t low,high,code; BR *br; } AD;
static void ad_init(AD *d,BR *br){
    d->low=0; d->high=MASKV; d->br=br; d->code=0;
    for(int i=0;i<PREC;i++) d->code=(d->code<<1)|br_bit(br);
}
static int ad_decode(AD *d,FM *m){
    uint64_t rng=d->high-d->low+1, total=m->total;
    uint64_t value=((d->code-d->low+1)*total-1)/rng;
    uint32_t clo,chi; int sym=fm_find(m,(uint32_t)value,&clo,&chi);
    d->high=d->low+(rng*chi)/total-1;
    d->low =d->low+(rng*clo)/total;
    for(;;){
        if(d->high<HALF){}
        else if(d->low>=HALF){ d->low-=HALF; d->high-=HALF; d->code-=HALF; }
        else if(d->low>=QUARTER && d->high<THREE_Q){ d->low-=QUARTER; d->high-=QUARTER; d->code-=QUARTER; }
        else break;
        d->low=(d->low<<1)&MASKV; d->high=((d->high<<1)|1)&MASKV;
        d->code=((d->code<<1)|br_bit(d->br))&MASKV;
    }
    fm_update(m,sym);
    return sym;
}

static uint32_t hash3(const uint8_t *p){
    return (((uint32_t)p[0]*65599u + p[1])*65599u + p[2]) & (HSIZE-1);
}

/* ---------- 한 블록 압축 (LZ77 + AC) ---------- */
static void compress_block(const uint8_t *d,int n,Buf *out){
    BW bw={out,0,0};
    FM flag,lit,len,dh,dm,dl;
    fm_init(&flag,3); fm_init(&lit,256); fm_init(&len,256); fm_init(&dh,256); fm_init(&dm,256); fm_init(&dl,256);
    AE e={0,MASKV,0,&bw};
    int *head=malloc(HSIZE*sizeof(int)); for(int i=0;i<HSIZE;i++) head[i]=-1;
    int *prev=malloc((n>0?n:1)*sizeof(int));
    int i=0;
    while(i<n){
        int best_len=0,best_dist=0;
        if(i+MIN_MATCH<=n){
            uint32_t h=hash3(d+i); int j=head[h], chain=0;
            int maxl=n-i; if(maxl>MAX_MATCH) maxl=MAX_MATCH;
            while(j>=0 && chain<CHAIN_CAP){
                if(i-j>WINDOW) break;
                int l=0; while(l<maxl && d[j+l]==d[i+l]) l++;
                if(l>best_len){ best_len=l; best_dist=i-j; if(l>=maxl) break; }
                j=prev[j]; chain++;
            }
        }
        int advance;
        if(best_len>=MIN_MATCH){
            ae_encode(&e,&flag,1);
            ae_encode(&e,&len,best_len-MIN_MATCH);
            int dd=best_dist-1;                  /* 거리 = 3바이트(24비트) */
            ae_encode(&e,&dh,(dd>>16)&0xFF);
            ae_encode(&e,&dm,(dd>>8)&0xFF);
            ae_encode(&e,&dl,dd&0xFF);
            advance=best_len;
        } else {
            ae_encode(&e,&flag,0);
            ae_encode(&e,&lit,d[i]);
            advance=1;
        }
        int end=i+advance;
        while(i<end){
            if(i+MIN_MATCH<=n){ uint32_t h=hash3(d+i); prev[i]=head[h]; head[h]=i; }
            i++;
        }
    }
    ae_encode(&e,&flag,2);
    ae_finish(&e); bw_finish(&bw);
    free(head); free(prev);
}

/* ---------- 한 블록 해제 ---------- */
static void decompress_block(const uint8_t *p,int plen,Buf *out){
    BR br={p,(size_t)plen,0,0,0};
    FM flag,lit,len,dh,dm,dl;
    fm_init(&flag,3); fm_init(&lit,256); fm_init(&len,256); fm_init(&dh,256); fm_init(&dm,256); fm_init(&dl,256);
    AD d; ad_init(&d,&br);
    for(;;){
        int f=ad_decode(&d,&flag);
        if(f==2) break;
        if(f==0){ buf_push(out,(uint8_t)ad_decode(&d,&lit)); }
        else{
            int l=ad_decode(&d,&len)+MIN_MATCH;
            int dd=(ad_decode(&d,&dh)<<16)|(ad_decode(&d,&dm)<<8)|ad_decode(&d,&dl);
            size_t start=out->len-(size_t)(dd+1);
            for(int k=0;k<l;k++){ uint8_t v=out->buf[start+k]; buf_push(out,v); }
        }
    }
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
