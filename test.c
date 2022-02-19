#include "types.h"
#include "stat.h"
#include "user.h"
#include "mmu.h"

void func()
{
    char *a;
    int i=0;
    int sz;
    sz = PGSIZE * 17;
    a = (char *)malloc(sz);

    while(i<sz-1){
        a[i] = (i % 26) + 'a';
        i++;
    }
    sleep(250);
    int flag = 1;

    for (i = 0; i < sz - 1; i++)
    {
        if (a[i] - 'a' != (i % 26))
        {
            wait();
            printf(2, "Index i = %d , Failed\n", i);
            flag = 0;
            break;
        }
    }
    if (flag)
    {
        wait();
        printf(2, "Success!!!\n");
    }
    else
    {
        wait();
        printf(2, "Failed!!!\n");
    }
    free((void *)a);
}

int main(int argc, char *argv[])
{
    func();
    
    int sz;
    int *a; 
    int pid;
    int x;
    int y;
    int i;
    int flag = 1;

    sz = PGSIZE * 15;
    a = (int *)malloc(sz);
    pid = fork();

    if (pid != 0)
    {
        x = 15;
        y = 25;
    }
    else
    {
        x = 11;
        y = 20;
    }

    for (i = 0; i < sz / 4; i++)
    {
        a[i] = (x ^ i) * y;
    }
    sleep(250);
    
    for (i = 0; i < sz / 4; i++)
    {
        if (a[i] != (x ^ i) * y)
        {
            wait();
            printf(2, "Try2 %d %d %d %d %d\n",x, y, i, (x ^ i) * y, a[i]);
            flag = 0;
            break;
        }
    }
    if (flag)
    {
        wait();
        printf(2, "Success!!!\n");
    }
    else
    {
        wait();
        printf(2, "Failed!!!\n");
    }
    free((void *)a);
    if (pid != 0)
    {
        wait();
    }

    exit();
}