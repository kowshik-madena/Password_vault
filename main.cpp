#include <iostream>
#include <fstream>
#include <string>
#include <map>

using namespace std;

const string VAULT_FILE = "vault.txt";

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