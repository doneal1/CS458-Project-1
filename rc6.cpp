#include <fstream>
#include "rc6.h"

using namespace std;

rc6::rc6(string bytes, unsigned int a, unsigned int b, unsigned int c, unsigned int d) {
	userkey = bytes;
	byte = userkey.length()/2;
	A = a;
	B = b;
	C = c;
	D = d;
	keys = new unsigned int[44];
	L = new unsigned int[ceil((float)byte / 4)];
	
}

rc6::~rc6() {
	delete L;
	delete keys;
}

unsigned int swapEndian(unsigned int sw) {
	unsigned int swap = ((sw >> 24) & 0xff) | ((sw << 8) & 0xff0000) | ((sw >> 8) & 0xff00) | ((sw << 24) & 0xff000000);
	return swap;
}

string rc6::makeHexString(unsigned int a, unsigned int b, unsigned int c, unsigned int d) {
	string ret;
	stringstream add;
	a = swapEndian(a);
	for (int i = 7; i > 0; i--) {
		unsigned int min = (unsigned int)pow(16.0, (double)i);
		if (a < min) {
			add << hex << 0;
		}
	}	
	add << hex << a;
	b = swapEndian(b);
	for (int i = 7; i > 0; i--) {
		unsigned int min = (unsigned int)pow(16.0, (double)i);
		if (b < min) {
			add << hex << 0;
		}
	}
	add << hex << b;
	c = swapEndian(c);
	for (int i = 7; i > 0; i--) {
		unsigned int min = (unsigned int)pow(16.0, (double)i);
		if (c < min) {
			add << hex << 0;
		}
	}
	add << hex << c;
	d = swapEndian(d);
	for (int i = 7; i > 0; i--) {
		unsigned int min = (unsigned int)pow(16.0, (double)i);
		if (d < min) {
			add << hex << 0;
		}
	}
	add << hex << d;
	ret += add.str();
	add.clear();

	return ret;
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
	unsigned int add = ceil((float)byte / 4);
	for (int i = 0; i < (int)add; i++) {
		unsigned int sw = strtoul(userkey.substr(8 * i, 8).c_str(), 0, 16);
		sw = swapEndian(sw);
		L[i] = sw;
	}
	keys[0] = p;
	for (int i = 1; i <= 43; i++) {
		keys[i] = (keys[i - 1] + q);
	}

	unsigned int a = 0, b = 0, c = 0, d = 0, f = 3 * max((int)add,44);

	for (int n = 1; n <= (int)f; n++) {
		a = keys[c] = rotate((keys[c] + a + b), 3, 0);
		b = L[d] = rotate((L[d] + a + b), a + b, 0);
		c = (c + 1) % 44;
		d = (d + 1) % add;
		
	}
}

string rc6::encryption() {
	string encrypt;

	unsigned int t,u,sw;
	B += keys[0];
	D += keys[1];

	for (int i = 1; i <= r; i++) {
		t = rotate(B * (2 * B + 1), 5, 0);
		u = rotate(D * (2 * D + 1), 5, 0);
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

	encrypt = makeHexString(A, B, C, D);

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

	decrypt = makeHexString(A, B, C, D);

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

string addSpaces(string text) {
	string ret = "";
	for (int i = 0; i < 16; i++) {
		ret += text.substr(2 * i, 2);
		ret += " ";
	}
	return ret;
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

	if(text.compare(0,11, "plaintext: ") == 0)
		text = text.substr(11, text.length() - 11);
	else if(text.compare(0, 12, "ciphertext: ") == 0)
		text = text.substr(12, text.length() - 12);
	else {
		cout << "Hey....the input file is badly formatted. Do better :(\n";
		return 1;
	}
	if (key.compare(0, 9, "userkey: ") == 0) {
		key = key.substr(9, key.length() - 9);
	}
	else {
		cout << "Hey....the key is badly formatted. Do better :(\n";
		return 1;
	}

	text = removeSpaces(text);
	key = removeSpaces(key);
	
	unsigned int a = (unsigned int)strtoul(text.substr(0,8).c_str(), 0, 16);
	unsigned int b = (unsigned int)strtoul(text.substr(8, 8).c_str(), 0, 16);
	unsigned int c = (unsigned int)strtoul(text.substr(16, 8).c_str(), 0, 16);
	unsigned int d = (unsigned int)strtoul(text.substr(24, 8).c_str(), 0, 16);
	a = swapEndian(a);
	b = swapEndian(b);
	c = swapEndian(c);
	d = swapEndian(d);

	rc6 run(key, a, b, c, d);
	run.keySchedule();

	string out;
	if(line.compare(0, 10, "Encryption") == 0) {
		out = run.encryption();
		out = addSpaces(out);
		output << "ciphertext: " << out;
	}
	else if (line.compare(0, 10, "Decryption") == 0) {
		out = run.decryption();
		out = addSpaces(out);
		output << "plaintext: " << out;
	}
	else {
		cout << "Either Encryption or Decryption please!\n";
		return 1;
	}

	
	cout << out << "\n";
	
	return 0;
}
