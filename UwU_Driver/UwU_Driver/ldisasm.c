#include "ldisasm.h"


static int modrm_extra(const UINT8 *p)
{
    (void)p;
    return 0;
}

static int modrm_bytes(const UINT8 *after_opcode)
{
    UINT8 modrm = after_opcode[0];
    int mod = (modrm >> 6) & 3;
    int rm  = modrm & 7;
    int n   = 1; 

    if (mod == 3) return n; 

    if (rm == 4) {
        n++; 
        if (mod == 0 && (after_opcode[1] & 7) == 5)
        {
            n += 4;
            return n;
        }
    }

    if (mod == 1) n += 1;
    else if (mod == 2) n += 4;
    else if (mod == 0 && rm == 5) n += 4; 

    return n;
}

int ldisasm(const UINT8 *p) {
    int n = 0;
    UINT8 rex = 0;
    int pfx66 = 0;

    for (;;) {
        UINT8 b = p[n];
        if (b == 0x66) { pfx66 = 1; n++; }
        else if (b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                 b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
                 b == 0x64 || b == 0x65)
            n++;
        else if ((b & 0xF0) == 0x40) { rex = b; n++; }
        else break;
    }

    UINT8 op = p[n++];
    int W = (rex >> 3) & 1; 
    (void)pfx66;

    if (op == 0x0F) {
        op = p[n++];

        if (op >= 0x80 && op <= 0x8F) return n + 4;

        if (op == 0x1F ||                              
            op == 0xA3 || op == 0xAB || op == 0xB3 || op == 0xBB || 
            op == 0xBC || op == 0xBD ||            
            op == 0xAF ||                               
            op == 0xB6 || op == 0xB7 ||             
            op == 0xBE || op == 0xBF ||                
            (op >= 0x40 && op <= 0x4F) ||            
            (op >= 0x90 && op <= 0x9F) ||            
            (op >= 0x10 && op <= 0x17) ||           
            (op >= 0x28 && op <= 0x2F) ||              
            op == 0x10 || op == 0x11 ||                
            op == 0xB8 ||                               
            op == 0xB9 ||                               
            op == 0xAE ||                              
            op == 0x00 || op == 0x01 ||              
            op == 0x02 || op == 0x03)                   
        {
            return n + modrm_bytes(p + n);
        }

        if (op == 0xC2 || op == 0xC4 || op == 0xC5 || op == 0xC6)
            return n + modrm_bytes(p + n) + 1;

        if (op == 0x38) { n++; return n + modrm_bytes(p + n); }
        if (op == 0x3A) { n++; return n + modrm_bytes(p + n) + 1; }

        if (op == 0x30 || op == 0x31 || op == 0x32 || op == 0x33 ||
            op == 0x34 || op == 0x78 || op == 0x79 || op == 0x0D ||
            op == 0x77 || op == 0xA0 || op == 0xA1 || op == 0xA8 || op == 0xA9)
            return n;

        if (op == 0xC8 || op == 0xC9 || op == 0xCA || op == 0xCB ||
            op == 0xCC || op == 0xCD || op == 0xCE || op == 0xCF) return n;
        if (op == 0x05 || op == 0x06 || op == 0x07 || op == 0x08 ||
            op == 0x09 || op == 0x0A || op == 0x0B) return n;

        return 0;
    }

    if ((op >= 0x50 && op <= 0x5F) || 
        op == 0x90 || op == 0x91 || op == 0x92 || op == 0x93 || 
        op == 0x94 || op == 0x95 || op == 0x96 || op == 0x97 ||
        op == 0x98 || op == 0x99 || op == 0x9C || op == 0x9D ||   
        op == 0x9E || op == 0x9F ||
        op == 0xA4 || op == 0xA5 || op == 0xA6 || op == 0xA7 ||   
        op == 0xAA || op == 0xAB || op == 0xAC || op == 0xAD || 
        op == 0xAE || op == 0xAF ||                           
        op == 0xC3 || op == 0xC9 || op == 0xCB ||               
        op == 0xF1 || op == 0xF4 || op == 0xF5 ||                
        op == 0xF8 || op == 0xF9 || op == 0xFA || op == 0xFB ||   
        op == 0xFC || op == 0xFD || op == 0xCC)                   
        return n;

    if (op == 0x6A || op == 0x6B || op == 0xEB || op == 0xCD ||
        (op >= 0x70 && op <= 0x7F) ||                             
        op == 0xD4 || op == 0xD5 || op == 0xE0 || op == 0xE1 ||
        op == 0xE2 || op == 0xE3)
        return n + 1;

    if (op == 0xC2 || op == 0xCA) return n + 2;

    if (op == 0x68 || op == 0xE8 || op == 0xE9) return n + 4; 

    if (op >= 0xB8 && op <= 0xBF) return n + (W ? 8 : 4);

    if (op >= 0xB0 && op <= 0xB7) return n + 1;

    if ((op >= 0x00 && op <= 0x03) || (op >= 0x08 && op <= 0x0B) ||
        (op >= 0x10 && op <= 0x13) || (op >= 0x18 && op <= 0x1B) ||
        (op >= 0x20 && op <= 0x23) || (op >= 0x28 && op <= 0x2B) ||
        (op >= 0x30 && op <= 0x33) || (op >= 0x38 && op <= 0x3B) ||
        (op >= 0x84 && op <= 0x8F) || 
        op == 0x62 || op == 0x63 || 
        (op >= 0xD0 && op <= 0xD3) ||  
        op == 0xFF || op == 0xFE ||    
        op == 0xF6 || op == 0xF7)     
    {
        int extra = modrm_bytes(p + n);
        
        if ((op == 0xF6 || op == 0xF7) && ((p[n] >> 3) & 7) == 0) {
            return n + extra + (op == 0xF6 ? 1 : (W ? 8 : 4));
        }
        return n + extra;
    }

    if (op == 0x80 || op == 0x82 || op == 0x83 || op == 0xC0 || op == 0xC1 || op == 0xC6)                 
        return n + modrm_bytes(p + n) + 1;

    if (op == 0x81 || op == 0xC7)     
        return n + modrm_bytes(p + n) + (W && op == 0xC7 ? 4 : 4);

    if (op == 0x6B) return n + modrm_bytes(p + n) + 1;

    if (op == 0x69) return n + modrm_bytes(p + n) + 4;

    if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7) return n + 1;
    if (op == 0xEC || op == 0xED || op == 0xEE || op == 0xEF) return n;


    if (op == 0xC8) return n + 3;


    if (op == 0xEA || op == 0x9A) return n + 6;


    if (op == 0xC4 || op == 0xC5) return n + modrm_bytes(p + n);

    if (op >= 0xA0 && op <= 0xA3) return n + 8; 

    return 0; 
}

int ldisasm_aligned(const UINT8 *p, int min_bytes) {
    int total = 0;
    while (total < min_bytes) {
        int len = ldisasm(p + total);
        if (len <= 0 || len > 15) return 0;
        total += len;
        if (total > 64) return 0; 
    }
    return total;
}
