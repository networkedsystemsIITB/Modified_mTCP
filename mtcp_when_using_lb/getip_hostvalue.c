#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> 
union iptolint
{
    char ip[16];
    uint32_t n;
};
uint32_t conv(char []);
 
main()
{
    union iptolint ipl;
    printf(" Read the IP Address tobe converted\n");
    scanf("%s",ipl.ip);
    ipl.n=conv(ipl.ip);
   // printf(" Equivalent 32-bit long int is : %lu\n",ipl.n);
    printf("Value: %" PRIu32 "\n", ipl.n);
}
 
uint32_t conv(char ipadr[])
{
    uint32_t num=0,val;
    char *tok,*ptr;
    tok=strtok(ipadr,".");
    while( tok != NULL)
    {
        val=strtoul(tok,&ptr,0);
        num=(num << 8) + val;
        tok=strtok(NULL,".");
    }
    return(num);
}

