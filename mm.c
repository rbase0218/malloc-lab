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

team_t team = {
    /* 팀 이름 */
    "Jungle",
    /* 멤버1 이름 */
    "RBH",
    /* 멤버1 이메일 */
    "grabisu@gmail.com",
    /* 멤버2 이름 */
    "",
    /* 멤버2 이메일 */
    ""};

// 매크로 정의
#define WSIZE 4                                              // 1 Word
#define DSIZE 8                                              // 2 Word ( Double Word )
#define CHUNKSIZE (1 << 12)                                  // 4096바이트 ( 힙 확장 시에 사용되는 Chunk 크기 )

#define MAX(x, y) ((x) > (y) ? (x) : (y))                    // 최대 값 반환

#define PACK(size, alloc)   ((size) | (alloc))               // 주소 연산을 통해서 Size와 Alloc(가용 상태) 상태를 합친다.

#define GET(p) (*(unsigned int *)(p))                        // 주소 P에서 4바이트 값(unsigned int 크기)을 읽음 (읽기)
#define PUT(p, val) (*(unsigned int *)(p) = (val))           // P의 처음 4바이트(위와 동일)에 val를 저장한다. (쓰기)

#define GET_SIZE(p) (GET(p) & ~0x7)                          // 하위 3비트(헤더)를 제외한 크기를 얻음
#define GET_ALLOC(p) (GET(p) & 0x1)                          // 할당 여부 확인 ( 마지막 비트가 1인가. ) -> 1은 가용 불가능한 블록

#define HDRP(bp) ((char *)(bp) - WSIZE)                      // 블럭 포인터로부터 헤더 위치를 계산한다.
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE) // 블럭 포인터로부터 푸터 위치 계산

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE))) // 다음 블록의 포인터를 계산
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE))) // 이전 블록의 포인터를 계산

#define PRED(bp) (*(char**)bp)              // 현재 Bp의 PRED를 가져온다.
#define SUCC(bp) (*(char**)bp + WSIZE)      // 현재 Bp의 SUCC를 가져온다.

static void *extend_heap(size_t);
static void *coalesce(void *);
static void *find_fit(size_t);
static void place(void *, size_t);

// Explicit Free List를 위한 함수
static void MakeFreeBlock(void *);
static void RemoveFreeBlock(void *);

static char *heap_listp;        // Heap의 패딩을 가리킨다.
static char *free_pointer;      // Heap의 PREV를 가리킨다.

int mm_init(void)   
{
    if ((heap_listp = mem_sbrk(6 * WSIZE)) == (void *)-1)
        return -1;

    PUT(heap_listp, 0);                                 // Padding
    PUT(heap_listp + (1 * WSIZE), PACK(DSIZE, 1));      // Prologue Header
    PUT(heap_listp + (2 * WSIZE), NULL);                // Heap - PREV
    PUT(heap_listp + (3 * WSIZE), NULL);                // Heap - SUCC
    PUT(heap_listp + (4 * WSIZE), PACK(DSIZE, 1));      // Prologue Footer
    PUT(heap_listp + (5 * WSIZE), PACK(0, 1));          // Epilogue

    // Heap의 Prev를 가리킨다.
    free_pointer = heap_listp + DSIZE;

    // Heap을 확장한다.
    if (extend_heap(CHUNKSIZE / WSIZE) == NULL) 
        return -1;
    return 0;
}

static void *extend_heap(size_t words) 
{
    char *bp;       
    size_t size;    

    // 2의 배수로 정렬한다.
    // words가 홀수인 경우, 수를 짝수로 만든다.
    // 아닐 경우, 그대로 연산.
    // Size의 값은 2의 배수로 보정된 값을 의미한다.
    size = (words % 2) ? (words + 1) * WSIZE : words * WSIZE;

    // bp는 size만큼 값이 할당되었을 때, 시작 주소를 가진다.
    if ((long)(bp = mem_sbrk(size)) == -1)
        return NULL;

    // 헤더와 푸터에 Size와 가용 여부를 등록한다.
    PUT(HDRP(bp), PACK(size, 0));
    PUT(FTRP(bp), PACK(size, 0));

    // 에필로그 블록을 다음 Block에 등록한다.
    PUT(HDRP(NEXT_BLKP(bp)), PACK(0, 1));

    return coalesce(bp);
}

void *mm_malloc(size_t size)
{
    size_t asize;
    size_t extendsize;
    char *bp;

    // Size가 0일 경우, 계산 필요 없음.
    if (size == 0)
        return NULL;

    // Size가 8 바이트보다 작을 경우, Header와 Footer의 공간을 확보해야 한다.
    if (size <= DSIZE)
        asize = 2 * DSIZE;
    else
    // 더 크다면, 2의 배수로 정리하고 Header와 Footer를 위한 공간만 확보한다.
        asize = DSIZE * ((size + (DSIZE) + (DSIZE - 1)) / DSIZE);

    // 해당 Size만큼 남는 공간이 있는지 식별한다.
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

void mm_free(void *ptr)
{
    size_t size = GET_SIZE(HDRP(ptr));

    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    coalesce(ptr);
}

static void *coalesce(void *bp)
{
    // 이전 블록의 할당 여부를 가져온다.
    size_t prev_alloc = GET_ALLOC(FTRP(PREV_BLKP(bp)));
    // 다음 블록의 할당 여부를 가져온다.
    size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(bp)));
    // 현재 블록의 SIZE를 가져온다.
    size_t size = GET_SIZE(HDRP(bp));

    // Case 1. 이미 이전 블록과 다음 블록이 할당된 상태.
    if (prev_alloc && next_alloc)
    {
        // Make Free Block
        return bp;
    }
    // Case 2. 이전 블록은 할당이 되었으나, 다음 블록은 할당되지 않은 상태.
    else if (prev_alloc && !next_alloc)
    {
        // Remove Free Block -> Next Alloc
        size += GET_SIZE(HDRP(NEXT_BLKP(bp)));
        PUT(HDRP(bp), PACK(size, 0));
        PUT(FTRP(bp), PACK(size, 0));
    }
    // Case 3. 이전 블록은 할당이 되지 않았으나, 다음 블록은 할당된 상태.
    else if (!prev_alloc && next_alloc)
    {
        // Remove Free Block -> PREV
        size += GET_SIZE(HDRP(PREV_BLKP(bp)));
        PUT(FTRP(bp), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }
    // Case 4. 이전 블록과 다음 블록이 할당되지 않은 상태.
    else
    {
        // Remove Free Block -> NEXT
        // Remove Free Block -> PREV
        size += GET_SIZE(HDRP(PREV_BLKP(bp))) + GET_SIZE(FTRP(NEXT_BLKP(bp)));

        PUT(HDRP(PREV_BLKP(bp)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(bp)), PACK(size, 0));
        bp = PREV_BLKP(bp);
    }

    // Make Free Block -> BP

    return bp;
}

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
    // 할당 받은 Size의 크기를 확인한다.
    size_t csize = GET_SIZE(HDRP(bp));

    // (할당 받은 Size - 필요 Size)의 값이 8 바이트라면
    if ((csize - asize) >= (2 * DSIZE))
    {
        PUT(HDRP(bp), PACK(asize, 1));
        PUT(FTRP(bp), PACK(asize, 1));
        bp = NEXT_BLKP(bp);
        PUT(HDRP(bp), PACK(csize - asize, 0));
        PUT(FTRP(bp), PACK(csize - asize, 0));
    }
    else
    {
        PUT(HDRP(bp), PACK(csize, 1));
        PUT(FTRP(bp), PACK(csize, 1));
    }
}

static void MakeFreeBlock(void *bp) 
{
    // 현재 BP의 PREV와 SUCC를 확인하고
    // 값을 추가한다.

    // Free List의 PREV와 SUCC를 등록한다.
}

static void RemoveFreeBlock(void *bp)
{
    // 현재 BP의 PREV와 SUCC를 확인하고
    // 값을 삭제한다.
}