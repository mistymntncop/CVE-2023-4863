#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <malloc.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#define MAX_ALLOWED_CODE_LENGTH      15

//copy and paste output of this program into Graphvis
//https://dreampuf.github.io/GraphvizOnline/


void print_tree() {
    int num_nodes = 1;    // number of Huffman tree nodes
    int num_open = 1;    // number of open branches in current tree level
    uint32_t n = 1;
    
#if 1
    uint32_t count[] = {0, 1, 1, 1, 1, 1, 0, 0, 0, 11, 5,   1, 10, 4, 2, 2 }; //alphabet = 40, table_size = 414
#else
    uint32_t count[] = {0, 1, 1, 1, 1, 0, 1, 1, 0, 15, 5,   9,  1, 1, 1, 2}; //alphabet = 40, table_size = 410
#endif

    printf("digraph BST {\n");
    for (int len = 1; len <= MAX_ALLOWED_CODE_LENGTH; ++len) {
        num_open <<= 1;
        num_nodes += num_open;

        uint32_t leaf_count = count[len];
        uint32_t internal_count = num_open - leaf_count;
        
        for(uint32_t i = 0; i < num_open; i++) {
            uint32_t node = ((1 << len) - 1) + i;
            uint32_t parent = (node-1)/2;
            printf("\tn%d [label=\"%d\"]\n", node, node);
            
            if(i >= internal_count) {
                printf("\tn%d [shape=doublecircle]\n", node);
            }
            printf("\tn%d -> n%d [label=\"%d\"]\n", parent, node, ((i+1) % 2));
            n++;
        }
        num_open -= leaf_count;       
    }
    printf("}\n");
}

int main(int argc, char **argv) {
    print_tree();
    return 0;
}