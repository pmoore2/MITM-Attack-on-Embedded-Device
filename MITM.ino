#include <Arduino.h>
#include <Crypto.h>
#include <AES.h>
#include <uECC.h>

#define KEY_SIZE 24

AES128 aes;

uint8_t arduinoPrivateKey[KEY_SIZE];
uint8_t arduinoPublicKey[KEY_SIZE * 2];
uint8_t interceptedHostPublicKey[KEY_SIZE * 2];
uint8_t sharedSecret[KEY_SIZE];
uint8_t encryptedMessage[16];

bool havePublicKey = false;
bool haveCiphertext = false;

String uartBuffer = "";

const struct uECC_Curve_t *curve = uECC_secp192r1();

void printHexArray(const char* label, const uint8_t* data, size_t length) {
  Serial.print(label);
  for (size_t i = 0; i < length; ++i) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
    Serial.print(" ");
  }
  Serial.println();
}

void computeSharedSecret() {
  printHexArray("[MITM] Private Key: ", arduinoPrivateKey, KEY_SIZE);
  printHexArray("[MITM] Host Public Key: ", interceptedHostPublicKey, KEY_SIZE * 2);

  if (!uECC_shared_secret(interceptedHostPublicKey, arduinoPrivateKey, sharedSecret, curve)) {
    Serial.println("[MITM] Failed to compute shared secret.");
    return;
  }
  printHexArray("[MITM] Shared Secret: ", sharedSecret, 16);
}

void decryptMessage() {
  aes.setKey(sharedSecret, 16);
  uint8_t output[16];
  aes.decryptBlock(output, encryptedMessage);

  Serial.println("[MITM] Decrypted Message:");
  for (int i = 0; i < 16; ++i)
    Serial.print((char)output[i]);
  printHexArray("[MITM] Encrypted Message: ", encryptedMessage, 16);
  Serial.println();
}

uint8_t hexToByte(char high, char low) {
  return (strtol((String("") + high + low).c_str(), NULL, 16)) & 0xFF;
}

void parseHexToBytes(const String& hexStr, uint8_t* output, size_t length) {
  for (int i = 0; i < length; i++) {
    output[i] = hexToByte(hexStr[i * 2], hexStr[i * 2 + 1]);
  }
}

int custom_rng(uint8_t *dest, unsigned size) {
  while (size--) {
    *dest++ = random(256);
  }
  return 1;
}

void generateKeypair() {
  Serial.println("Initializing RNG...");
  uECC_set_rng(&custom_rng);
  
  Serial.println("Verifying curve...");
  if (!curve) {
    Serial.println("Curve initialization failed!");
    return;
  }

  Serial.println("Generating keys...");
  if (!uECC_make_key(arduinoPublicKey, arduinoPrivateKey, curve)) {
    Serial.println("Key generation failed!");
    return;
  }
  
  Serial.println("Key generation successful!");
}

void setup() {
  Serial.begin(115200);
  Serial1.begin(115200);
  while (!Serial);
  
  randomSeed(0);

  pinMode(1, OUTPUT);
  digitalWrite(1, HIGH);

  curve = uECC_secp192r1();
  if (!curve) {
    Serial.println("Curve not supported!");
    while(1);
  }

  Serial.println("MITM Arduino Initialized for NIST P-192");

  generateKeypair();
  printHexArray("public key ", arduinoPublicKey, KEY_SIZE*2);
}

void loop() {
  while (Serial1.available()) {
    char incoming = Serial1.read();
    Serial.print(incoming);

    if (incoming == '\n') {
      if (uartBuffer.startsWith("e")) {
        uartBuffer.remove(0, 1);
        Serial1.write("x", 1);
        for (size_t i = 0; i < KEY_SIZE; i++) {
          if (arduinoPublicKey[i] < 16) {
            Serial1.print("0");
          } 
          Serial1.print(arduinoPublicKey[i], HEX);
        }
        Serial1.write("\n");
        Serial1.write("y", 1);
        for (size_t i = KEY_SIZE; i < KEY_SIZE * 2; i++) {
          if (arduinoPublicKey[i] < 16) {
            Serial1.print("0");
          } 
          Serial1.print(arduinoPublicKey[i], HEX);
        }
        Serial1.write("\n");
        Serial1.write("z00", 3);

        Serial.write("x", 1);
        for (size_t i = 0; i < KEY_SIZE; i++) {
          if (arduinoPublicKey[i] < 16) {
            Serial.print("0");
          }
          Serial.print(arduinoPublicKey[i], HEX);
        }
        Serial.write("\n");
        Serial.write("y", 1);
        for (size_t i = KEY_SIZE; i < KEY_SIZE * 2; i++) {
          if (arduinoPublicKey[i] < 16) {
            Serial.print("0");
          } 
          Serial.print(arduinoPublicKey[i], HEX);
        }
        Serial.write("\n");
        Serial.write("z00", 3);
      } else if (uartBuffer.startsWith("l")) {
        uartBuffer.remove(0,1);
        if (uartBuffer.length() == 96) {
          parseHexToBytes(uartBuffer, interceptedHostPublicKey, KEY_SIZE*2);
          computeSharedSecret();
          havePublicKey = true;
        }
      } else if (uartBuffer.startsWith("s")) {
        uartBuffer.remove(0, 1);
        if (uartBuffer.length() == 32) {
          parseHexToBytes(uartBuffer, encryptedMessage, 16);
          Serial.println("[MITM] Intercepted Ciphertext");
          haveCiphertext = true;
        }
      }
      uartBuffer = "";
    } else if (incoming != '\r') {
      uartBuffer += incoming;
    }
  }

  if (havePublicKey && haveCiphertext) {
    decryptMessage();
    havePublicKey = false;
    haveCiphertext = false;
  }
}
