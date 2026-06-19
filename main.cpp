#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <vector>

using namespace std;

const string VAULT_FILE = "vault.bin";
const string HASH_FILE = "master.hash";

void secureZero(string& s){
    if(!s.empty()){
        OPENSSL_cleanse(s.data(), s.length());
        s.clear();
    }
}

void secureZero(vector<unsigned char>& v){
    if(!v.empty()){
        OPENSSL_cleanse(v.data(), v.size());
        v.clear();
    }
}

vector<unsigned char> encryptAES(const string& plaintext, const vector<unsigned char>& key){
    // Generate a random 16-byte IV.
    unsigned char iv[16];
    if(RAND_bytes(iv, sizeof(iv))!=1){
        throw runtime_error("Critical Error: Failed to generate random IV.");
    }

    // Setup OpenSSL Cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv);

    // IV and AES block size padding requires slightly more space 
    vector<unsigned char> ciphertext(16 + plaintext.size() + 16);
    copy(iv, iv+16, ciphertext.begin());
    int len = 0, clen = 16;

    // Encrypt the data
    EVP_EncryptUpdate(ctx, ciphertext.data()+16, &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
    clen += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + clen, &len);
    clen += len;

    // Shrink the vector to correct size
    ciphertext.resize(clen);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

string decryptAES(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key){
    if(ciphertext.size() < 16) return "";

    // Extract the 16 byte IV
    unsigned char iv[16];
    copy(ciphertext.begin(), ciphertext.begin() + 16, iv);

    // Setup OpenSSL Cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv);

    vector<unsigned char> plaintext(ciphertext.size()-16);
    int len = 0, plen = 0;

    // Decrypt the data
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + 16, ciphertext.size()-16);
    plen = len;

    if(EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0){
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    plen += len;
    plaintext.resize(plen);

    EVP_CIPHER_CTX_free(ctx);
    return string(plaintext.begin(), plaintext.end());
}

vector<unsigned char> computeSHA256(const string& input){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), hash);
    return vector<unsigned char>(hash, hash + SHA256_DIGEST_LENGTH);
}

map<string, string> loadVault(const vector<unsigned char>& key){
    map<string, string> vault;
    ifstream infile(VAULT_FILE, ios::binary | ios::ate);

    if(infile.is_open()){
        streamsize siz = infile.tellg();
        if(siz<=0) return vault;

        infile.seekg(0, ios::beg);
        vector<unsigned char> bin(siz);
        infile.read(reinterpret_cast<char*>(bin.data()), siz);
        infile.close();

        string plaintext = decryptAES(bin, key);
        if(plaintext.empty()){
            cout << "\nDecryption Failed : Wrong Password or Tampered File" << endl;
            return vault;
        }

        stringstream ss(plaintext);
        string line;

        while(getline(ss, line)){
            auto pos = line.find('=');
            if(pos != string::npos){
                vault[line.substr(0, pos)] = line.substr(pos+1);
            }
        }
        secureZero(plaintext);
    }
    return vault;
}

void saveVault(const map<string, string>& vault, const vector<unsigned char>& key){
    // Replaced stringstream with string to ensure the destruction of decrypted data
    string plaintext;
    for(auto const& it : vault){
        plaintext.append(it.first);
        plaintext.append("=");
        plaintext.append(it.second);
        plaintext.append("\n");
    }

    vector<unsigned char> ciphertext = encryptAES(plaintext, key);
    secureZero(plaintext);
    ofstream outfile(VAULT_FILE, ios::binary);

    if(!outfile.is_open()){
        cerr << "Error: unable to open " << VAULT_FILE << endl;
        return;
    }

    outfile.write(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    outfile.close();
}

vector<unsigned char> authenticate(){
    ifstream infile(HASH_FILE);

    if(!infile.is_open()){
        cout << "---First time setup---\nCreate a Master Password:\t";
        string master_pass;
        getline(cin, master_pass);
        vector<unsigned char> key = computeSHA256(master_pass);
        secureZero(master_pass);

        ofstream outfile(HASH_FILE);
        for(unsigned char byte : key){
            outfile << hex << setw(2) << setfill('0') << (int)byte;
        }
        outfile.close();
        cout << "Vault initialized" << endl;
        return key;
    }

    string master_hash;
    infile >> master_hash;
    infile.close();

    cout << "\nEnter Master Password:\t";
    string master_pass;
    getline(cin, master_pass);
    vector<unsigned char> key = computeSHA256(master_pass);
    secureZero(master_pass);

    stringstream ss;
    for(unsigned char byte : key){
        ss << hex << setw(2) << setfill('0') << (int)byte;
    }

    if(ss.str() == master_hash) return key;
    else return vector<unsigned char>();
}

int main(int argc, char* argv[]){
    if(argc<2){
        cout << "Usage: ./vault [add/get/list] [service] [password]" << endl;
        return 1;
    }

    vector<unsigned char> key = authenticate();
    if(key.empty()){
        cout << "---Incorrect Master Password. Access Denied---" << endl;
        return 1;
    }

    cout << "---Access Granted---" << endl;
    string command = argv[1];
    map<string, string> vault = loadVault(key);

    if(command == "add" && argc==4){
        string service = argv[2];
        string password = argv[3];
        vault[service] = password;
        saveVault(vault, key);
        cout << "Saved password for " << service << endl;
    }
    else{
        if(command == "get" && argc==3){
            string service = argv[2];
            if(vault.find(service) != vault.end()) cout << "Password for " << service << " is " << vault[service] << endl;
            else cout << "Service \"" << service << "\" not found in vault" << endl;
        }
        else{
            if(command == "list" && argc==2){
                cout << "Saved services :\n";
                for(auto const& it : vault) cout << "- " << it.first << "\n";
            }
            else{
                cout << "Invalid command or arguments" << endl;
            }
        }
    }
    secureZero(key);
    return 0;
}