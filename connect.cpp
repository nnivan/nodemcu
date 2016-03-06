#include <string>
#include <iostream>
#include <cstdio>
#include <memory>
#include <cstring>

std::string exec(const char* cmd) {
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return "ERROR";
    char buffer[128];
    std::string result = "";
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            result += buffer;
    }
    return result;
}

int main(int argc, char *argv[]){

    std::string ip;
    ip = exec("ifconfig | grep -A1 -E 'tether|wlp1s0' | grep -Eo 'inet (addr:)?([0-9]*\\.){3}[0-9]*' | grep -Eo '([0-9]*\\.){3}[0-9]*' | grep -v '127.0.0.1'");
    ip.erase(10,4);
    ip.append("1 ");
    ip.insert(0, "/home/root/galileo/work/communication/client ");
    ip.append(std::string(argv[1]));

    char cmd[100];

    strcpy(cmd, ip.c_str());

    std::cout<<cmd<<std::endl;

    exec(cmd);

    return 0;
}
