void Round(unsigned char * state, unsigned char * key) {
 SubRoundKey(state, key);
 InverseMixColumns(state);
 ShiftRows(state);
 SubBytes(state);
}

/* Initial round without InverseMixColumns */
void InitialRound(unsigned char * state, unsigned char * key) {
 SubRoundKey(state, key);
 ShiftRows(state);
 SubBytes(state);
}

/* AES decryption function */
void AESDecrypt(unsigned char * encryptedMessage,
 unsigned char * expandedKey,
 unsigned char * decryptedMessage)
{
 unsigned char state[16];

 for (int i = 0; i < 16; i++) {
  state[i] = encryptedMessage[i];
 }

 InitialRound(state, expandedKey + 160);

 int numberOfRounds = 9;

 for (int i = 8; i >= 0; i--) {
  Round(state, expandedKey + (16 * (i + 1)));
 }

 SubRoundKey(state, expandedKey);

 for (int i = 0; i < 16; i++) {
  decryptedMessage[i] = state[i];
 }
}

int main() {

 cout << "=============================" << endl;
 cout << " 128-bit AES Decryption Tool " << endl;
 cout << "=============================" << endl;

 // Read encrypted file
 ifstream infile("message.aes", ios::binary | ios::ate);

 if (!infile.is_open()) {
  cout << "Unable to open message.aes" << endl;
  return 1;
 }

 streamsize size = infile.tellg();
 infile.seekg(0, ios::beg);

 unsigned char* encryptedMessage = new unsigned char[size];

 if (!infile.read((char*)encryptedMessage, size)) {
  cout << "Failed to read encrypted file" << endl;
  delete[] encryptedMessage;
  return 1;
 }

 infile.close();

 cout << "Read encrypted message from message.aes" << endl;

 // Read key
 string keystr;

 ifstream keyfile;
 keyfile.open("keyfile", ios::in | ios::binary);

 if (keyfile.is_open()) {
  getline(keyfile, keystr);
  cout << "Read key from keyfile" << endl;
  keyfile.close();
 }
 else {
  cout << "Unable to open keyfile" << endl;
  delete[] encryptedMessage;
  return 1;
 }

 istringstream hex_chars_stream(keystr);

 unsigned char key[16];

 int i = 0;
 unsigned int c;

 while (hex_chars_stream >> hex >> c) {
  key[i] = c;
  i++;
 }

 unsigned char expandedKey[176];

 KeyExpansion(key, expandedKey);

 int messageLen = (int)size;

 unsigned char* decryptedMessage = new unsigned char[messageLen];

 for (int i = 0; i < messageLen; i += 16) {
  AESDecrypt(encryptedMessage + i,
   expandedKey,
   decryptedMessage + i);
 }

 cout << "Decrypted message in hex:" << endl;

 for (int i = 0; i < messageLen; i++) {
  cout << hex << (int)decryptedMessage[i] << " ";
 }

 cout << endl;

 cout << "Decrypted message: ";

 for (int i = 0; i < messageLen; i++) {
  if (decryptedMessage[i] != 0) {
   cout << decryptedMessage[i];
  }
 }

 cout << endl;

 delete[] encryptedMessage;
 delete[] decryptedMessage;

 return 0;
}
