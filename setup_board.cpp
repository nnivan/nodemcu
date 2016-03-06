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

int main(){

    exec("echo \'f\' > /media/card/status.txt");

    std::cout<<"0 -\n";
    std::cout<<exec("connmanctl disable wifi");

	std::cout<<"1 -\n";
	std::cout<<exec("connmanctl enable wifi");
	std::cout<<"2 -\n";
	std::cout<<exec("connmanctl scan wifi");
	std::cout<<"3 -\n";

	std::string wifi_connection = exec("connmanctl services | grep Galileo");
	wifi_connection.erase(0,25);

	if(wifi_connection.empty()){

		std::cout<<exec("connmanctl tether wifi on Galileo 3edc4rfv");
		std::cout<<"5.2 -\n";

		exec("echo \'s\' > /media/card/status.txt");

        system("/home/root/galileo/work/communication/server > information.txt &");

	}else{

		wifi_connection.insert(0, "connmanctl connect ");

		std::cout<<wifi_connection;
		std::cout<<"4 -\n";

		char buff[128];
		strncpy(buff,wifi_connection.c_str(), sizeof(buff));

		std::cout<<exec(buff);
		std::cout<<"5.1 -\n";

		exec("echo \'c\' > /media/card/status.txt");

	}

	return 0;
}

