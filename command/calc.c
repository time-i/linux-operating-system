/***************************calculator*********************************/
#include "stdio.h"
#define ctoi(num) num-'0'
void main(int argc, char * argv[])
{
	int result;
	int a = ctoi(argv[1][0]);
	int b = ctoi(argv[1][2]);
	switch(argv[1][1]){
	case '+':
		result = a + b;
		break;
	case '-':
		result = a - b;
		break;
	case '*':
		result = a * b;
		break;
	case '/':
		if(b){
			result = a / b;
		} else {
			printf("[ERROR]DIV / 0!\n");
			return;
		}
		break;	
	}

	printf("%d %c %d = %d\n", a, argv[1][1], b, result);

}

int my_atoi(const char *s)
{
	int num, i;
	char ch;
	num = 0;
	while(s[i]) {
		ch = s[i];
		i++;
		if (ch < '0' || ch > '9')
			break;
		num = num * 10 + (ch - '0');
	}
	return num;
}
