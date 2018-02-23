/******************************************************************************
**
**  ipmiparm - a menu-driven kmod parameter manager for ipmi kmods
**
**  Tony Camuso
**  April, 2014
**
**    ipmiparm is free software: you can redistribute it and/or modify
**    it under the terms of the GNU General Public License as published by
**    the Free Software Foundation, either version 3 of the License, or
**    (at your option) any later version.
**
**    This program is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**
**  GNU General Public License http://www.gnu.org/licenses/gpl.html
**
**  Copyright 2014 by Tony Camuso.
**
**  Very simple compile
**
**      $ make ipmiparm
**  or
**      $ g++ -o ipmiparm ipmiparm.cpp
**
******************************************************************************/

#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>

using namespace std;

/**************************************************************
 * class kmodparm
 *************************************************************/
class kmodparm {
public:

    kmodparm() {value = 0; m_isbitmask = false; isstring = false; }

    int togglebit(int bit, int& mask);

    string kmodname;
    string parmname;
    int    value;
    string strval;
    bool   isstring;

private:
    bool   m_isbitmask;
};

/**************************************************************
 * kmodparm::togglebit - toggle a bit in a bitmask
 *
 */int kmodparm::togglebit(int bit, int &mask)
{
    bit = (1 << bit);
    mask = bit xor mask;
    return mask;
}

/**************************************************************
 * class kmod
 *************************************************************/
class kmod {
public:
    kmod(){}
    string kmodname;
    vector<kmodparm> parms;
};


/**************************************************************
 * class parmapp
 *************************************************************/
class parmapp {
public:
    parmapp() {init();}
    parmapp(int test) {init(test);}

    void   dump();
    int    shell(stringstream& command, stringstream& outstr);
    void   getmenu();
    void   showmenu();
    void   showkmodmenu(int pos);
    void   getkmodmenu(int pos);
    char   getchar();
    int    toxint(char c);
    string tobin(int hex, int bits);
    void   editparm(kmodparm& parm);
    void   editparmbitmask(kmodparm& parm);
    bool   toggleradix() {hexdec = !hexdec; return hexdec;}
    string getradixstr() {return hexdec ? "hex" : "dec";}
    string getstr(string prompt, string curval);
    int    getint(string prompt, int curval = 0);
    bool   isint(string& s);
    bool   str2int(string& str, int& num);
    int    str2int(string& str);
    int    tokenize(stringstream& ss, vector<string>& tokens);

private:
    string topdir;
    bool hexdec;            // hex radix when true, dec when false
    bool binary;            // binary input enabled for bitmasks when true
    vector<kmod> kmods;

    void init(bool test = false);
    void init_kmod(string kmod);
};

/**************************************************************
 * parmapp::tokenize - tokenizes a string stream and creates a
 *                     vector of strings.
 * ss       - stringstream to tokenize
 * tokens   - a vector of strings
 *
 * Returns the number of tokens
 *
 */
int parmapp::tokenize (stringstream& ss, vector<string>& tokens)
{
    int i;
    string str;

    for (i = 0; ss.eof() == false; ++i) {
        ss >> str;
        tokens.push_back(str);
    }
    return i;
}


/**************************************************************
 * parmapp::dump - dump the contents of the vector of kemod parms
 *
 */
void parmapp::dump()
{
    for (uint j = 0; j < kmods.size(); ++j) {
       kmod& km = kmods[j];
        for (uint k = 0; k < km.parms.size(); ++k) {
            cout << "kmod: " << km.parms[k].kmodname
                 << "  parm: " << km.parms[k].parmname;

            if(km.parms[k].isstring)
                cout << "  val: " << km.parms[k].strval << endl;
            else
                cout << "  val: " << km.parms[k].value << endl;
         }
    }
}

/**************************************************************
 * parmapp::init_kmod - Initialize the vector of kmod parameters
 *                      by reading the contents of the parameter
 *                      files in sysfs.
 *
 * Makes a system() call to the bash shell.
 *
 */
void parmapp::init_kmod(string kmodstr)
{
    stringstream cmd;
    stringstream s1;
    stringstream s2;
    string str;
    string dir = topdir + "module/" + kmodstr + "/parameters/";
    int j = kmods.size();
    int k = 0;

    cmd << "ls 2>/dev/null " << dir;
    if (shell(cmd, s1))
        return;

    kmods.resize(j + 1);

    kmods[j].kmodname = kmodstr;
    kmod& km = kmods[j];

    while (getline(s1, str)) {

	    if (str == "hotmod")
		    continue;

        km.parms.resize(km.parms.size() + 1);
        km.parms[k].kmodname = kmodstr;
        km.parms[k].parmname = str;

        s2.clear();
        s2.str("");
        cmd.str("");
        cmd << "cat " << dir << str << "\n";
        cmd.flush();
        shell(cmd, s2);

        if ((s2 >> km.parms[k].value).fail()) {
            s2.clear();
            s2 >> km.parms[k].strval;
            km.parms[k].isstring = true;
        } else
            km.parms[k].isstring = false;

        ++k;
    }
}

/**************************************************************
 * parmapp::init - top level init routine
 *
 */
void parmapp::init(bool test)
{
    topdir = test ? "$HOME/" : "/sys/";
    hexdec = true;
    binary = false;
    init_kmod("ipmi_si");
    init_kmod("ipmi_msghandler");
    init_kmod("ipmi_watchdog");
}

/**************************************************************
 * parmapp::shell - execute a shell command and capture its output
 *
 * command - stringstream containing the command string
 * outstr  - reference to a stringstream that will contain the
 *           output from the shell after running the command
 * BUFSIZ  - defined by the compiler. In g++ running on Linux
 *           64-bit kernel, it's 8192.
 *
 * Returns the status of the OS call.
 *
 */
int parmapp::shell(stringstream& command, stringstream& outstr)
{
    int retval;
    int retidx;
    int i;
    vector<string> tokens;
    char buff[BUFSIZ];

    command << "\necho $?\n";
    command.flush();

    FILE *fp = popen(command.str().c_str(), "r");

    for (i = 0; fgets(buff, BUFSIZ, fp ) != NULL; ++i)
        tokens.push_back(buff);

    pclose(fp);

    retidx = i - 1;
    retval = str2int(tokens[retidx]);

    for (i = 0; i < retidx; ++i)
        outstr << tokens[i];

    return retval;
}

/**************************************************************
 * parmapp::getchar() - read one character and return without
 *                      waiting for user to press RETURN key
 *
 * Makes a call to the bash shell
 *
 */
char parmapp::getchar()
{
    stringstream cmd;
    stringstream ans;

    cmd << "read -n1 val; echo $val 2>&1";
    shell(cmd, ans);
    return *ans.str().c_str();
}

string parmapp::tobin(int num, int bits)
{
    string temp;
    int bit;
    temp.resize(bits);
    for (int i = 0; i < bits; ++i) {
        bit = 1 << (bits - 1 - i);
        temp[i] = bit & num ? '1' : '0';
    }
    return temp;
}

/**************************************************************
 * parmapp::toxint - convert single hex (base 16) chars to digits
 *
 */
int parmapp::toxint(char c)
{
    if (c >= '0' && c <= '9')
        return c - 48;

    if (c >= 'a' && c <= 'f')
        return c - 87;

    if (c >= 'A' && c <= 'F')
        return c - 55;

    return -1;
}

/**************************************************************
 * parmapp::isint - test the string to see whether it's an int
 */
bool parmapp::isint(string& s)
{
    bool isnumber = true;

    for(string::const_iterator k = s.begin(); k != s.end(); ++k) {
        if (hexdec)
            isnumber = isnumber && isxdigit(*k);
        else
            isnumber = isnumber && isdigit(*k);
    }

    return isnumber;
}

/**************************************************************
 * parmapp::str2int - safely convert a string to an int
 *
 * This version of the function first determines whether the str
 * actually contains a number, depending on the radix. For exapmle,
 * with the parmapp class hexdec set for hexadecimal, foo is not
 * considered a number while f00 is.
 *
 * str  - string to convert
 * num  - integer value of the converted number
 *
 * Returns true if the str is indeed a number, else false and
 * the value of num is undefined.
 */
bool parmapp::str2int(string& str, int& num)
{
    if (!isint(str))
        return false;

    num = str2int(str);
    return true;
}

/**************************************************************
 * parmapp::str2int - safely convert a string to an int
 *
 * This version of the function simply performs the conversion
 * without worrying whether the str contains a real number. This
 * version of the function is only used when you KNOW that the
 * str has a real number in it. For example, with parmapp::hexdec
 * set to true (hexadecimal mode), then foo will be evaluated as
 * 15.
 *
 * str  - string to convert
 *
 * Returns the converted integer. Returns 0 if the integer could
 * not be converted.
 */
int parmapp::str2int(string& str)
{
    int num;
    stringstream ss(str);

    if (hexdec)
        ss >> hex >> num;
    else
        ss >> num;

    return num;
}

/**************************************************************
 * parmapp::getint - obtain multi-char input from user accepting
 *                   only hex or decimal characters, depending
 *                   on the parmapp::radix variable.
 *
 */
int parmapp::getint(string prompt, int curval)
{
    int num;
    string str;

    while (true) {
        cout << prompt;
        getline(cin, str);

        // If user simply pressed return key, return with the
        // current value.
        //
        if(str == "")
            return curval;

        if(str2int(str, num))
            break;

        cout << "Invalid number, please try again" << endl;
    }
    return num;
}

/**************************************************************
 * parmapp::getstr - present a prompt and obtain a string rom user
 */
string parmapp::getstr(string prompt, string curval)
{
    string str;

    cout << prompt;
    getline(cin, str);

    // If user simply pressed return key, return with the
    // current value.
    //
    if(str == "")
        return curval;

    return str;
}

/**************************************************************
 * parmapp::editparm - get a new value for the kmod parameter
 *
 */
void parmapp::editparm(kmodparm& parm)
{
    string parmfile;
    stringstream cmd;
    stringstream ss;
    string linestr = "-----------------------------------------\n";
    string prompt = "  New value: ";

    parmfile = topdir + "module/" + parm.kmodname
                      + "/parameters/" + parm.parmname;

    printf("  %s - Current Value: ", parm.parmname.c_str());
    ss.clear();
    ss.str("");
    cmd.str("");
    cmd << "echo ";

    if(parm.isstring) {
        printf("%s\n", parm.strval.c_str());
        cout << linestr;
        parm.strval = getstr(prompt, parm.strval);
        if (str2int(parm.strval, parm.value)) {
            parm.isstring = false;
            cmd << parm.value;
        } else {
            parm.isstring = true;
            cmd << parm.strval;
        }
    } else {
        printf("%3d  :  0x%02x\n", parm.value, parm.value);
        cout << linestr;
        parm.value = getint(prompt, parm.value);
        cmd << parm.value;
    }

    cmd << " > " << parmfile << "\n";
    cmd.flush();
    shell(cmd, ss);
}


/**************************************************************
 * parmapp::editparmbitmask - get a new value for the kmod
 *                            parameter as a bitmask.
 *
 * Provides ability to change individual bits in the value,
 * rather than changing the whole value with one input.
 *
 */
void parmapp::editparmbitmask(kmodparm& parm)
{
    char ch;
    string parmfile;
    stringstream cmd;
    stringstream ss;

    while (true) {
        printf("  %-15s: %3d  :  0x%02x  :  %s\n",
               parm.parmname.c_str(), parm.value, parm.value,
               tobin(parm.value, 8).c_str());
        cout << "  --------------------------------------------\n";
        cout << "  Number from 0 to 7 to toggles the corresponding bit.\n";
        cout << "  v  prompts to change the value directly\n";
        cout << "  q  quit\n\n";
        cout << "  Your choice: ";
        cout.flush();
        ch = getchar();
        cout << endl;

        switch (ch) {
        case 'q' : return;
        case 'v' : parm.value = getint("  New Value: ", parm.value); break;
        case '0' :
        case '1' :
        case '2' :
        case '3' :
        case '4' :
        case '5' :
        case '6' :
        case '7' : parm.togglebit(toxint(ch), parm.value); break;
        }
        cmd.str("");
        ss.str("");
        parmfile = topdir + "module/" + parm.kmodname
                 + "/parameters/" + parm.parmname;
        cmd << "echo " << parm.value << " > " << parmfile << "\n";
        shell(cmd, ss);
    }
}

/**************************************************************
 * parmapp::showkmodmenu - menu of kmod parameters that can be edited
 *
 * kmodvec - the position int he kmod vector where the parameters for
 *           this kmod start.
 */
void parmapp::showkmodmenu(int pos)
{
    vector<kmodparm> parms = kmods[pos].parms;

    cout << " " << kmods[pos].kmodname << " parameters\n"
         <<    " --------------------------------------\n";

    for (uint i = 0; i < parms.size(); ++i) {
        printf("  %0x  %-19s: ", i, parms[i].parmname.c_str());

        if(parms[i].isstring)
            printf("str %s\n", parms[i].strval.c_str());
        else
            printf("int %3d  :  0x%02x\n", parms[i].value, parms[i].value);
     }

    cout << "\n  r  switch radix. Current input radix: "
         << getradixstr() << endl;
    cout << "  q  quit\n\n";
    cout << "  Select a parameter to edit: ";
    cout.flush();
}

void parmapp::getkmodmenu(int pos)
{
    kmod& km = kmods[pos];
    char ch;

    while (true) {
        cout << endl;
        showkmodmenu(pos);
        ch = getchar();
        cout << endl;

        switch (ch) {
        case 'q': cout << endl; return;
        case 'r': toggleradix(); break;
        }

        int i = toxint(ch);
        if (i == -1 || (uint)i >= km.parms.size())
            continue;

        // If it's a debug parameter, it will be a bitmask, else it is a
        // simple value. We determine it's a debug parameter by looking for
        // "debug" in the parameter's name string.
        //
        if (km.parms[i].parmname.find("debug") == string::npos)
            editparm(km.parms[i]);
        else
            editparmbitmask(km.parms[i]);

        cout << endl;
    }
}

/**************************************************************
 * parmapp::showmenu - top level menu
 *
 */
void parmapp::showmenu()
{
    string kmod = "";

    cout << "\nSelect a kmod to change its parameters\n"
         <<   "--------------------------------------\n";

    for (uint i = 0; i < kmods.size(); ++i)
        printf("  %d  %s\n", i, kmods[i].kmodname.c_str());

    cout << "\n  r  switch radix. Current input radix: "
         << getradixstr() << endl;
    cout << "  q  quit\n\n";
    cout << "  Select a kmod to access its parameters: ";
    cout.flush();
}

/**************************************************************
 * parmapp::getmenu - top level menu parser and main program loop
 *
 */
void parmapp::getmenu()
{
    char ch;

    while (true) {
        showmenu();
        ch = getchar();

        switch (ch) {
        case 'q': cout << endl; return;
        case 'r': toggleradix(); break;
        }

        int i = toxint(ch);
        if (i == -1 || (uint)i >= kmods.size())
            continue;

        cout << endl << endl;
        cout.flush();

        getkmodmenu(i);
    }
}

/**************************************************************
** main - the main program
***************************************************************/
//int main(int argc, char** argv)
int main()
{
    string version = "v1.0";

    cout << "\nipmiparm " << version << " ipmi kmod parameter manager\n";

    parmapp pa;
    pa.getmenu();
    return 0;
}

