void FinalRound(unsigned char * state, unsigned char * key) {
 SubBytes(state);
 ShiftRows(state);
 AddRoundKey(state, key);
}

/* The AES encryption function
 * Organizes the confusion and diffusion steps into one function
 */
void AESEncrypt(unsigned char * message, unsigned char * expandedKey, unsigned char * encryptedMessage) {
 unsigned char state[16];

 for (int i = 0; i < 16; i++) {
  state[i] = message[i];
 }

 int numberOfRounds = 9;

 AddRoundKey(state, expandedKey);

 for (int i = 0; i < numberOfRounds; i++) {
  Round(state, expandedKey + (16 * (i + 1)));
 }

 FinalRound(state, expandedKey + 160);

 for (int i = 0; i < 16; i++) {
  encryptedMessage[i] = state[i];
 }
}

int main() {

 cout << "=============================" << endl;
 cout << " 128-bit AES Encryption Tool " << endl;
 cout << "=============================" << endl;

 char message[1024];

 cout << "Enter the message to encrypt: ";
 cin.getline(message, sizeof(message));

 int originalLen = strlen((const char *)message);

 int paddedMessageLen = originalLen;

 if ((paddedMessageLen % 16) != 0) {
  paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
 }

 unsigned char * paddedMessage = new unsigned char[paddedMessageLen];

 for (int i = 0; i < paddedMessageLen; i++) {
  if (i >= originalLen) {
   paddedMessage[i] = 0;
  }
  else {
   paddedMessage[i] = message[i];
  }
 }

 unsigned char * encryptedMessage = new unsigned char[paddedMessageLen];

 string str;

 ifstream infile;
 infile.open("keyfile", ios::in | ios::binary);

 if (infile.is_open()) {
  getline(infile, str);
  infile.close();
 }
 else {
  cout << "Unable to open keyfile" << endl;
  return 1;
 }

 istringstream hex_chars_stream(str);

 unsigned char key[16];

 int i = 0;
 unsigned int c;

 while (hex_chars_stream >> hex >> c) {
  key[i] = c;
  i++;
 }

 unsigned char expandedKey[176];

 KeyExpansion(key, expandedKey);

 for (int i = 0; i < paddedMessageLen; i += 16) {
  AESEncrypt(paddedMessage + i, expandedKey, encryptedMessage + i);
 }

 cout << "Encrypted message in hex:" << endl;

 for (int i = 0; i < paddedMessageLen; i++) {
  cout << hex << (int)encryptedMessage[i] << " ";
 }

 cout << endl;

 // Write encrypted binary data to file
 ofstream outfile;
 outfile.open("message.aes", ios::out | ios::binary);

 if (outfile.is_open()) {
  outfile.write((char*)encryptedMessage, paddedMessageLen);
  outfile.close();

  cout << "Wrote encrypted message to file message.aes" << endl;
 }
 else {
  cout << "Unable to open output file" << endl;
 }

 delete[] paddedMessage;
 delete[] encryptedMessage;

 return 0;
}
