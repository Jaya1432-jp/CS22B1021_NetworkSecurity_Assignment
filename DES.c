    int i, j;
    
    /* 8 bits */
    char row, column;
    
    /* 28 bits */
    uint32_t C                  = 0;
    uint32_t D                  = 0;
    
    /* 32 bits */
    uint32_t L                  = 0;
    uint32_t R                  = 0;
    uint32_t s_output           = 0;
    uint32_t f_function_res     = 0;
    uint32_t temp               = 0;
    
    /* 48 bits */
    uint64_t sub_key[16]        = {0};
    uint64_t s_input            = 0;
    
    /* 56 bits */
    uint64_t permuted_choice_1  = 0;
    uint64_t permuted_choice_2  = 0;
    
    /* 64 bits */
    uint64_t init_perm_res      = 0;
    uint64_t inv_init_perm_res  = 0;
    uint64_t pre_output         = 0;
    
    /* initial permutation */
    for (i = 0; i < 64; i++) {
        
        init_perm_res <<= 1;
        init_perm_res |= (input >> (64-IP[i])) & LB64_MASK;
        
    }
    
    L = (uint32_t) (init_perm_res >> 32) & L64_MASK;
    R = (uint32_t) init_perm_res & L64_MASK;
        
    /* initial key schedule calculation */
    for (i = 0; i < 56; i++) {
        
        permuted_choice_1 <<= 1;
        permuted_choice_1 |= (key >> (64-PC1[i])) & LB64_MASK;

    }
    
    C = (uint32_t) ((permuted_choice_1 >> 28) & 0x000000000fffffff);
    D = (uint32_t) (permuted_choice_1 & 0x000000000fffffff);
    
    /* Calculation of the 16 keys */
    for (i = 0; i< 16; i++) {
        
        /* key schedule */
        // shifting Ci and Di
        for (j = 0; j < iteration_shift[i]; j++) {
            
            C = 0x0fffffff & (C << 1) | 0x00000001 & (C >> 27);
            D = 0x0fffffff & (D << 1) | 0x00000001 & (D >> 27);
            
        }
        
        permuted_choice_2 = 0;
        permuted_choice_2 = (((uint64_t) C) << 28) | (uint64_t) D ;
        
        sub_key[i] = 0;
        
        for (j = 0; j < 48; j++) {
            
            sub_key[i] <<= 1;
            sub_key[i] |= (permuted_choice_2 >> (56-PC2[j])) & LB64_MASK;
            
        }
        
    }
    
    for (i = 0; i < 16; i++) {
        
        /* f(R,k) function */
        s_input = 0;
        
        for (j = 0; j< 48; j++) {
            
            s_input <<= 1;
            s_input |= (uint64_t) ((R >> (32-E[j])) & LB32_MASK);
            
        }
        
        /* 
         * Encryption/Decryption 
         * XORing expanded Ri with Ki
         */
        if (mode == 'd') {
            // decryption
            s_input = s_input ^ sub_key[15-i];
            
        } else {
            // encryption
            s_input = s_input ^ sub_key[i];
            
        }
        
        /* S-Box Tables */
        for (j = 0; j < 8; j++) {
            // 00 00 RCCC CR00 00 00 00 00 00 s_input
            // 00 00 1000 0100 00 00 00 00 00 row mask
            // 00 00 0111 1000 00 00 00 00 00 column mask
            
            row = (char) ((s_input & (0x0000840000000000 >> 6*j)) >> 42-6*j);
            row = (row >> 4) | row & 0x01;
            
            column = (char) ((s_input & (0x0000780000000000 >> 6*j)) >> 43-6*j);
            
            s_output <<= 4;
            s_output |= (uint32_t) (S[j][16*row + column] & 0x0f);
            
        }
        
        f_function_res = 0;
        
        for (j = 0; j < 32; j++) {
            
            f_function_res <<= 1;
            f_function_res |= (s_output >> (32 - P[j])) & LB32_MASK;
            
        }
        
        temp = R;
        R = L ^ f_function_res;
        L = temp;
        
    }
    
    pre_output = (((uint64_t) R) << 32) | (uint64_t) L;
        
    /* inverse initial permutation */
    for (i = 0; i < 64; i++) {
        
        inv_init_perm_res <<= 1;
        inv_init_perm_res |= (pre_output >> (64-PI[i])) & LB64_MASK;
        
    }
    
    return inv_init_perm_res;
    
}

int main(int argc, const char * argv[]) {

    int i;
    
    uint64_t input = 0x9474B8E8C73BCA7D;
    uint64_t key = 0x0000000000000000;
    uint64_t result = input;
    
    /*
     * TESTING IMPLEMENTATION OF DES
     * X0:  9474B8E8C73BCA7D
     * X16: 1B1A2DDB4C642438
     *
     * OUTPUT:
     * E: 8da744e0c94e5e17
     * D: 0cdb25e3ba3c6d79
     * E: 4784c4ba5006081f
     * D: 1cf1fc126f2ef842
     * E: e4be250042098d13
     * D: 7bfc5dc6adb5797c
     * E: 1ab3b4d82082fb28
     * D: c1576a14de707097
     * E: 739b68cd2e26782a
     * D: 2a59f0c464506edb
     * E: a5c39d4251f0a81e
     * D: 7239ac9a6107ddb1
     * E: 070cac8590241233
     * D: 78f87b6e3dfecf61
     * E: 95ec2578c2c433f0
     * D: 1b1a2ddb4c642438  <-- X16
     */
    for (i = 0; i < 16; i++) {
        
        if (i%2 == 0) {
            
            result = des(result, result, 'e');
            printf ("E: %016llx\n", result);
            
        } else {
            
            result = des(result, result, 'd');
            printf ("D: %016llx\n", result);
            
        }
    }
    
    //result = des(input, key, 'e');
    //printf ("E: %016llx\n", result);
    
    //result = des(result, key, 'd');
    //printf ("D: %016llx\n", result);
    
    exit(0);
}
