//Illumio Firewall Coding Challenge
//Gautam Nambiar
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <vector>
#include <unordered_set>

//class to decompose a rule from the inut file into different compontents: direction, protocol, port, IP address
//minimum port and maximum port value is stored to account for range
//IP address is stored as a vector of integers with a MinIP and a MaxIP stored to account for range
class Rules
{
    public:
    std::string direction, protocol;
    int portMin, portMax;
    std::vector<int> IPAddrMin, IPAddrMax;
    Rules(std::string ruleline)
    {
        std::vector<std::string> rules;
        std::stringstream ss(ruleline);
        std::string minIP, maxIP;
        std::string rule_component;
        while (getline(ss, rule_component, ','))
            rules.push_back(rule_component);

        direction = rules[0];
        protocol = rules[1];
        if (rules[2].find("-") != std::string::npos) {                          //check if a range exits in the port values
            portMin = stoi(rules[2].substr(0, rules[2].find('-')));
            portMax = stoi(rules[2].substr(rules[2].find('-') + 1));
        }
        else {
            portMin = portMax = stoi(rules[2]);
        }
        if (rules[3].find("-") != std::string::npos) {                          //check if a range exits in the ip values
            minIP = rules[3].substr(0, rules[3].find('-'));
            maxIP = rules[3].substr(rules[3].find('-') + 1);
        }
        else {
            minIP = maxIP = rules[3];                                           //if no range exits set max min to same value
        }
        std::stringstream sminIP(minIP);
        std::stringstream smaxIP(maxIP);
        for (int i; sminIP >> i;)                                               //divvy the ip to 4 numbers
        {
            IPAddrMin.push_back(i);
            if(sminIP.peek() == '.')
                sminIP.ignore();
        }
        for (int i; smaxIP >> i;) 
        {
            IPAddrMax.push_back(i);
            if(smaxIP.peek() == '.')
                smaxIP.ignore();
        }
    }
};

class Firewall
{
    private:
    std::unordered_set<std::string> rules;
    //function to consolidate the compontes of a Rule class back into line similar to a line in the csv file
    //this is done so we can enter these lines into  a set with averaege O(1) lookup time, as a search with 
    //a coherent stinrg key made more sense than attempting the same with the object of user-defined class
    std::string get_ruleline(std::string direction, std::string protocol, int port, int IP1, int IP2, int IP3, int IP4)
    {
        return direction + "," + protocol + "," + std::to_string(port) + "," + std::to_string(IP1) + "."+ std::to_string(IP2) + "."+ std::to_string(IP3) + "."+ std::to_string(IP4);
    }
    public:
    Firewall(std::string path) 
    {
        std::ifstream rulefile (path);
        std::string ruleline;
        if (rulefile.is_open()) 
        {
            while (getline(rulefile, ruleline))                                                                             //generate alll possible rules from the rule set given
            {                                                                                                               //store all posible rules in unordered_set
                Rules rule(ruleline);
                //denormlize the range of rules into all possible unique rules and store in set
                for (int i = rule.portMin; i <= rule.portMax; i++) {
                    for (int j = rule.IPAddrMin[0]; j <= rule.IPAddrMax[0]; j++) {
                        for (int k = rule.IPAddrMin[1]; k <= rule.IPAddrMax[1]; k++) {
                            for (int l = rule.IPAddrMin[2]; l <= rule.IPAddrMax[2]; l++) {
                                for (int m = rule.IPAddrMin[3]; m <= rule.IPAddrMax[3]; m++) {
                                    rules.insert(get_ruleline(rule.direction, rule.protocol, i, j, k, l, m));
                                }
                            }
                        }   
                    }    
                }
            }
        }
    }
    bool accept_packet(std::string direction, std::string protocol, int port, std::string IP) 
    {
        
        std::vector<int> IPAddr;
        std::stringstream ss(IP);
        for (int i; ss >> i;) {
            IPAddr.push_back(i);
            if(ss.peek() == '.')
                ss.ignore();
        }

        //find rule in the rule set in o(1)
        if (rules.find(get_ruleline(direction, protocol, port, IPAddr[0], IPAddr[1], IPAddr[2], IPAddr[3])) != rules.end())
            return true;
        else 
            return false;
    }
};

int main()
{
    Firewall fireWall("rules.csv");
    if (fireWall.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
        std::cout << "Yup \n";
    else 
        std::cout << "Nah \n";
}