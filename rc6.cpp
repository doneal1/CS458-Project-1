#include <fstream>
#include "rc6.h"

using namespace std;

rc6::rc6(string bytes, unsigned int a, unsigned int b, unsigned int c, unsigned int d) {
	userkey = bytes;
	byte = userkey.length();
	A = a;
	B = b;
	C = c;
	D = d;
	keys = new unsigned int[44];
	L = new unsigned int[ceil((float)byte / 4)];
	
}

unsigned int rc6::rotate(unsigned int a, unsigned int b, int ch) {
	b = b << 27;
	b = b >> 27;
	if(ch == 0) //rotate left
		a = (a << b) | (a >> (32 - b));
	else //rotate right
		a = (a >> b) | (a << (32 - b));
	return a;
}

void rc6::keySchedule() {

}

string rc6::encryption() {
	string encrypt;

	unsigned int t,u,sw;

	B += keys[0];
	D += keys[1];

	for (int i = 1; i <= r; i++) {
		t = rotate(B * (2 * B + 1) % mod, 5, 0);
		u = rotate(D * (2 * D + 1) % mod, 5, 0);
		A = rotate(A ^ t, u, 0) + keys[2 * i];
		C = rotate(C ^ u, t, 0) + keys[2 * i + 1];

		sw = A;
		A = B;
		B = C;
		C = D;
		D = sw;
	}

	A += keys[42];
	C += keys[43];

	return encrypt;
}

string rc6::decryption() {
	string decrypt;

	unsigned int t, u, sw;

	A -= keys[42];
	C -= keys[43];

	for (int i = r; i > 0; i--) {
		sw = A;
		A = D;
		D = C;
		C = B;
		B = sw;

		u = rotate((D * (2*D + 1)), 5, 0);
		t = rotate((B * (2 * B + 1)), 5, 0);
		C = (rotate(C - keys[2 * i + 1], t, 1)) ^ u;
		A = (rotate(A - keys[2 * i], u, 1)) ^ t;
	}

	D -= keys[1];
	B -= keys[0];

	return decrypt;
}

string removeSpaces(string text) {
	int count = 0;
	for (int i = 0; i < (int)text.length(); i++) {
		if (text[i] != ' ') {
			text[count] = text[i];
			count++;
		}
	}
	text[count] = '\0';
	text = text.substr(0, count+1);
	return text;
}


int main(int argc, char* argv[]) {

	if (argc != 3) {
		cout << "Run the program as ./run ./input.txt ./output.txt\n";
		return 1;
	}
	string line, text, key;
	ifstream input(argv[1]);
	ofstream output(argv[2]);
	if (!input) {
		cout << "The given input file does not exist.\n";
		return 1;
	}
	if (!output) {
		cout << "The given output file does not exist.\n";
		return 1;
	}

	getline(input, line);
	getline(input, text);
	getline(input, key);

	if(text.compare(0,strlen("plaintext: "), "plaintext: ") == 0)
		text = text.substr(strlen("plaintext: "), text.length() - strlen("plaintext: "));
	else if(text.compare(0, strlen("ciphertext: "), "ciphertext: ") == 0)
		text = text.substr(strlen("ciphertext: "), text.length() - strlen("ciphertext: "));
	else {
		cout << "Hey....the input file is badly formatted. Do better :(\n";
		return 1;
	}
	if (key.compare(0, strlen("userkey: "), "userkey: ") == 0) {
		key = key.substr(strlen("userkey: "), key.length() - strlen("userkey: "));
	}
	else {
		cout << "Hey....the key is badly formatted. Do better :(\n";
		return 1;
	}

	text = removeSpaces(text);
	key = removeSpaces(key);
	
	unsigned int a = (unsigned int)stoi(text.substr(0,4), 0, 16);
	unsigned int b = (unsigned int)stoi(text.substr(4, 4), 0, 16);
	unsigned int c = (unsigned int)stoi(text.substr(8, 4), 0, 16);
	unsigned int d = (unsigned int)stoi(text.substr(12, 4), 0, 16);
	
	rc6(key, a, b, c, d);
	return 0;
}