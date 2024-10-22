/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "Jungle",
    /* First member's full name */
    "RBH",
    /* First member's email address */
    "grabisu@gmail.com",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~0x7)

// 매크로 정의
#define WSIZE 4             // Word Size
#define DSIZE 8             // Double Word Size
#define CHUNKSIZE (1 << 12) // 4096바이트 (힙 확장 시에 사용되는 크기 = 아 청크)

#define MAX(x, y) ((x) > (y) ? (x) : (y)) // 최대 값 반환

#define PACK(size, alloc)   ((size) | (alloc))     // 주소 연산을 통해서 Size와 Alloc(가용 상태) 상태를 합친다.

#define GET(p) (*(unsigned int *)(p))              // 주소 P에서 4바이트 값을 읽음
#define PUT(p, val) (*(unsigned int *)(p) = (val)) // 주소 P에 4바이트 값을 작성

#define GET_SIZE(p) (GET(p) & ~0x7) // 하위 3비트(헤더)를 제외한 크기를 얻음
#define GET_ALLOC(p) (GET(p) & 0x1) // 할당 여부 확인 ( 마지막 비트가 1인가? )

#define HDRP(bp) ((char *)(bp) - WSIZE)                      // 블럭 포인터로부터 헤더 위치를 계산한다.
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) // 블럭 포인터로부터 푸터 위치 계산

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE))) // 다음 블록의 포인터를 계산
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE))) // 이전 블록의 포인터를 계산

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

static void *extend_heap(size_t);
static void *coalesce(void *);
static void *find_fit(size_t);
static void place(void *, size_t);

static char *heap_listp;

/*
 * mm_init - initialize the malloc package.
 */
int mm_init(void)   // 초기 힙 생성
{
    // 초기 힙 공간 요청
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1)
        return -1;

    PUT(heap_listp, 0);                             // 패딩
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1));  // 프롤로그 블록 헤더
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1));  // 프롤로그 블록 푸터
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1));      // 에필로그 블록 헤더

    heap_listp += (2 * WSIZE);                      // 포인터를 프롤로그 블록 푸터로 이동.

    if (extend_heap(CHUNKSIZE / WSIZE) == NULL)     // 할당 실패 시, -1 반환
        return -1;
    return 0;
}

static void *extend_heap(size_t words)  // 힙 확장
{
    char *bp;       // 새로운 블록을 가리키는 포인터
    size_t size;    // 할당할 Size

    // 2의 배수로 정렬한다. -> 메모리 접근 효율성 향상
    // words % 2 == 1일 경우, 홀수가 된다. + 1을 더해서 짝수로 만든다.
    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;

    // 힙을 Size만큼 확장.
    // 성공하면 새로운 블록의 시작 주소를 bp에 저장한다.
    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;

    // 헤더와 푸터 초기화.
    // 0은 가용 상태를 의미한다.
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));

    // 에필로그 헤더를 배치한다.
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));

    // 인접한 가용 블록이 있다면 병합한다.
    return coalesce(bp);
}

/*
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */
void *mm_malloc(size_t size)
{
    size_t asize;
    size_t extendsize;
    char *bp;

    // Size가 0이면 처리할 필요가 없음.
    if (size == 0)
        return NULL;

    // Size가 Double Word Size보다 작을 경우.
    if (size <= DSIZE)
        asize = 2 * DSIZE;
    else
    // Size가 Double Word Size보다 클 경우.
        asize = DSIZE * ((size + (DSIZE) + (DSIZE - 1)) / DSIZE);

    // 공간을 찾았는데 NULL을 반환하지 않았다면 ? -> 적당한 가용 공간을 찾았다.
    // NULL이면 공간 확장.
    if ((bp = find_fit(asize)) != NULL)
    {
        place(bp, asize);
        return bp;
    }

    extendsize = MAX(asize, CHUNKSIZE);
    if ((bp = extend_heap(extendsize / WSIZE)) == NULL)
        return NULL;
    place(bp, asize);
    return bp;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    size_t size = GET_SIZE(HDRP(ptr));

    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    coalesce(ptr);
}

static void *coalesce(void *bp)
{
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    size_t size = GET_SIZE(HDRP(bp));

    if (prev_alloc && next_alloc)
        return bp;
    else if (prev_alloc && !next_alloc)
    {
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }
    else if (!prev_alloc && next_alloc)
    {
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
    else
    {
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
    return bp;
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    if (size <= 0)
    {
        mm_free(ptr);
        return 0;
    }
    if (ptr == NULL)
        return mm_malloc(size);

    void *newp = mm_malloc(size);
    if (newp == NULL)
        return 0;

    size_t oldsize = GET_SIZE(HDRP(ptr));

    if (size < oldsize)
        oldsize = size;

    memcpy(newp, ptr, oldsize);
    mm_free(ptr);

    return newp;
}

static void *find_fit(size_t asize)
{
    void *bp;
    for(bp = heap_listp; GET_SIZE(HDRP(bp)) > 0; bp = NEXT_BLKP(bp))
    {
        if(!GET_ALLOC(HDRP(bp)) && (asize <= GET_SIZE(HDRP(bp))))
            return bp;
    }
    return NULL;
}

static void place(void *bp, size_t asize)
{
    size_t csize = GET_SIZE(HDRP(bp));
    if((csize- asize) >= (2*DSIZE)){
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize-asize, 0));
        PUT(FTRP(bp), PACK(csize-asize, 0));
    }
    else
    {
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}