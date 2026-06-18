#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>

using namespace std;

const string VAULT_FILE = "vault.txt";
const string HASH_FILE = "master.hash";

string masterHash(const string& pass){
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(pass.c_str()), pass.length(), hash);
    stringstream ss;
    
    for(int i=0; i<SHA256_DIGEST_LENGTH; i++){
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }

    return ss.str();
}

bool authenticate(){
    ifstream infile(HASH_FILE);

    if(!infile.is_open()){
        cout << "---First time setup---\nCreate a Master Password: \n";
        string master_pass;
        getline(cin, master_pass);
        ofstream outfile(HASH_FILE);
        outfile << masterHash(master_pass);
        outfile.close();
        cout << "Vault initialized" << endl;
        return true;
    }

    string master_hash;
    infile >> master_hash;
    infile.close();
    cout << "Enter Master Password: \n";
    string pass;
    getline(cin, pass);

    return masterHash(pass)==master_hash;
}

map<string, string> loadVault(){
    map<string, string> vault;
    ifstream infile(VAULT_FILE);
    string line, service, password;

    if(infile.is_open()){
        while(getline(infile, line)){
            auto pos = line.find('=');
            if(pos != string::npos){
                service = line.substr(0, pos);
                password = line.substr(pos+1);
                vault[service] = password;
            }
        }
        infile.close();
    }

    return vault;
}

void saveVault(const map<string, string>& vault){
    ofstream outfile(VAULT_FILE);

    if(!outfile.is_open()){
        cerr << "Error: unable to open " << VAULT_FILE << endl;
        return;
    }

    for(auto const& it : vault){
        outfile << it.first << "=" << it.second << "\n";
    }
    outfile.close();
}

int main(int argc, char* argv[]){
    if(argc<2){
        cout << "Usage: ./vault [add/get/list] [service] [password]" << endl;
        return 1;
    }

    if(!authenticate()){
        cout << "Incorrect Master Password. Access Denied." << endl;
        return 1;
    }

    cout << "Access Granted." << endl;
    string command = argv[1];
    map<string, string> vault = loadVault();

    if(command == "add" && argc==4){
        string service = argv[2];
        string password = argv[3];
        vault[service] = password;
        saveVault(vault);
        cout << "Saved password for " << service << endl;
    }
    else{
        if(command == "get" && argc==3){
            string service = argv[2];
            if(vault.find(service) != vault.end()) cout << "Password for " << service << " is " << vault[service] << endl;
            else cout << "Service not found in vault" << endl;
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

    return 0;
}