#include <iostream>
#include <fstream>
#include <ctime>
using namespace std;
bool openFile(ifstream& filepath)
{
    string file;
    cout << "enter PATH of file (exemple C:\\Windows\\System32\\namefile) : " << endl;

    cin >> file;

    filepath.open(file, ios::binary);
    if (!filepath)
    {

        cout << "cant open this file or not found" << endl;
        cout << "=====================================" << endl;
        return false;
    }
    else
    {

        cout << "the file is opened successfully!" << endl;
        cout << "=====================================" << endl;
    }
    return true;
}bool checkDOSHeader(ifstream& filepath)
{
    char dosHeader[2];
    filepath.read(dosHeader, 2);

    if (dosHeader[0] != 'M' || dosHeader[1] != 'Z')
    {

        cout << "faild open file" << endl;
        cout << "=====================================" << endl;
        filepath.close();
        return false;
    }
    else
    {

        cout << "[+] DOS Header Signature (MZ): Valid!" << endl;
        cout << "=====================================" << endl;
        return true;
    }
}bool readthePE(ifstream& filepath)
{
    filepath.seekg(60, ios::beg);
    long ntHeaderOffset;
    filepath.read(reinterpret_cast<char*>(&ntHeaderOffset), sizeof(ntHeaderOffset));

    filepath.seekg(ntHeaderOffset, ios::beg);
    char peSignature[4];
    filepath.read(peSignature, 4);

    if (peSignature[0] != 'P' || peSignature[1] != 'E' || peSignature[2] != 0 || peSignature[3] != 0)
    {

        cout << "[-] Error: Invalid PE Signature." << endl;
        cout << "=====================================" << endl;
        filepath.close();
        return false;
    }
    else
    {

        cout << "[+] NT Header Signature (PE): Valid!" << endl;
        cout << "=====================================" << endl;
        return true;
    }
}void typemachine(ifstream& filepath)
{
    unsigned short machineType;
    filepath.read(reinterpret_cast<char*>(&machineType), sizeof(machineType));

    if (machineType == 0x8664) {


        cout << "[+] Architecture: 64-bit (x64)" << endl;
        cout << "=====================================" << endl;
    }
    else if (machineType == 0x014c) {

        cout << "[+] Architecture: 32-bit (x86)" << endl;
        cout << "=====================================" << endl;
    }
    else {

        cout << "[?] Architecture: Unknown (0x" << hex << machineType << ")" << endl;
        cout << "=====================================" << endl;
    }

}void timepast(ifstream& filepath)
{
    unsigned long timestamp;
    filepath.read(reinterpret_cast<char*>(&timestamp), sizeof(timestamp));

    time_t rawTime = static_cast<time_t>(timestamp);
    char timeBuffer[26];
    ctime_s(timeBuffer, sizeof(timeBuffer), &rawTime);

    cout << "[+] Compile Time (Timestamp): " << timeBuffer;
    cout << "=====================================" << endl;
}
int main()
{
    cout << "\n";
    cout << "                                              OOOOOO  O    O   OOOOO  OOOOOO   OOOOO  O    O  OOOOOOO \n";
    cout << "                                             O        O    O  O     O |     ) O     O O    O       O   \n";
    cout << "                                             O        OOOOOO  OOOOOOO OOOOOO  O     O O    O      O     \n";
    cout << "                                             O        O    O  O     O |     ) O     O O    O     O      \n";
    cout << "                                              OOOOOO  O    O  O     O OOOOOO   OOOOO   OOOO     O      \n";
    cout << "                                                                [ PE PARSER v1.0 ]\n\n";
    ifstream filepath;

    if (!openFile(filepath)) {
        return 1;
    }


    if (!checkDOSHeader(filepath))
    {
        return 1;
    }


    if (!readthePE(filepath))
    {
        return 1;
    }

    typemachine(filepath);

    timepast(filepath);

    filepath.close();
    return 0;
}
