#include <iostream>
#include<stdio.h>     
#include<conio.h>   
#include<stdlib.h> 
#include<stdio.h>    
#include<math.h>    
#include<string>  
#include <vector>

using namespace std;

class rc6 {

public:

	rc6(string bytes, unsigned int a, unsigned int b, unsigned int c, unsigned int d);
	unsigned int rotate(unsigned int a, unsigned int b, int ch);
	void keySchedule();
	string encryption();
	string decryption();


private:
	string userkey;
	unsigned int A, B, C, D;
	int w = 32, r = 20, byte;
	unsigned int log = (unsigned int)log2(w);
	unsigned int mod = (unsigned int)2 << w;
	unsigned int* keys;
	unsigned int* L;
	unsigned int p = (unsigned int)ceil((exp(1) - 2) * mod);
	unsigned int q = (unsigned int)((1.618033988749895 - 1) * mod);
};