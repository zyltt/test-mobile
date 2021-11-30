//一个普普通通的冒泡排序方法。
//选用冒泡排序的原因是作者代码能力较弱~~~
//注意：该排序方法定义的数组大小为400。该大小是所依赖的FPGA规定的数组大小。
//每一个整数的字长规定为24位，这一长度也是由所使用的FPGA特性所决定的。
#include "bubble.h"
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char *argv[])
{
    int c, d, swap, retval=0;
    int n;
    FILE* f = fopen(argv[1], "r");

    ap_int<24> numbers[K];
    int i=0;

    for (i=0; i<K; i++)
    {
    	fscanf(f, "%d\n", &n);
    	numbers[i]=n;
    }
    fclose(f);

    ap_int<24> array[K];
    for (c = 0; c < K; c++)
    {
	array[c] = numbers[c];
    }
    printf("Begin sort!\n");

    bubbleSort(array);

//    FILE* fw = fopen("1.dat", "w");
//    for (int cnt=0; cnt<K; cnt++)
//    {
//    	fprintf(fw, "%d\n", array[cnt].to_int());
//    }
//    fclose(fw);

    return retval;

}
