// put the 2 other scripts in one folder for these includes to work
#include "fodhelper.c" 
#include "edvade.c"
int main(){ // function that runs at start up
    detect();   // calls the main function in the sandbox detection code
    exploit();  // calls the exploit main function to exploit
    return 0;
}