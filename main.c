/*********************************************************
 *                                                       *
 *                     CODE SCANNER                      *
 * checks for memory injections and gets vulnerabilities *
 *       Jacob Beaman, Justin Petri, Rebecca Gee         *
 *                Ansh Shah, Hannah Scott                *
 *                                                       *
**********************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <regex.h>
#define ar 10000
// Create a struct named node that has the following elements: line num, vulnerability and mitre techniques
typedef struct vo
{
    
    char *MITRE; //mitre technique will be stored here
    char *VULN; //vulnerability will be stored here
    int lineNum; //the line number will be stored here
} v;

v Node[ar]; //creating an array variable for the structure

// define global node start

char *mitreTec;

int useRegex(char *textToCheck)
{
    regex_t compiledRegex; // compiledRegex from the regex.h struct (regex_t) used to store the regular expression
    int reti;              // creates "reti" variable to store result of regex compilation
    int reti2;
    // char messageBuffer[100];

    /* Compiles regular expression */
    reti = regcomp(&compiledRegex, "[a-zA-Z0-9]+\\[[a-zA-Z0-9]+].*=.*[a-zA-Z0-9]+;", REG_EXTENDED | REG_ICASE); // regcomp takes three args: regex_t pointer created above, the expression, and the flag, the flags (REG_EXTENDED allow for other languages)
    
    /* Executes compiled regular expression */
    reti = regexec(&compiledRegex, textToCheck, 0, NULL, 0);
    
    char gets_vuln[40] = "gets(";                            // vulnerable string to search for
    char *result;
    result = strstr(textToCheck, gets_vuln); // searches strings from inputted c file for the gets_vuln

    if (!reti) // if match, return Match and 0
    {
        
        reti = regcomp(&compiledRegex, "[a-zA-Z0-9]+\\[[0-9]+].*=.*[0-9]+;", REG_EXTENDED | REG_ICASE); //searching false positive memory injection
        reti = regexec(&compiledRegex, textToCheck, 0, NULL, 0);
        if(!reti){
            // reti = regcomp(&compiledRegex, "[a-zA-Z0-9]+\\[[0-9]+].*=.*[a-zA-Z0-9]+;", REG_EXTENDED | REG_ICASE);
            // reti = regexec(&compiledRegex, textToCheck, 0, NULL, 0);
            return 0;
            
      

        }
        else{
        mitreTec = "Memory Injection";//mitre technique for mem injec vuln
        return 1;
        
        }
        
    
    }
    
    else if (reti)
    {
        reti = regcomp(&compiledRegex, "[a-zA-Z0-9]+\\[[-1]+].*=.*[a-zA-Z0-9]+;", REG_EXTENDED | REG_ICASE);//checking to see if there is array[-1]=vulnAddr
        reti = regexec(&compiledRegex, textToCheck, 0, NULL, 0);
        if(!reti){ //if it matches
        reti = regcomp(&compiledRegex, "[a-zA-Z0-9]+\\[[-1]+].*=.*[0-9]+;", REG_EXTENDED | REG_ICASE);
        reti = regexec(&compiledRegex, textToCheck, 0, NULL, 0);
        if(!reti){return 0;}
        mitreTec = "Memory Injection";//mitre technique for mem injec vuln
        return 1;
        }
        
    }
    
    if (result != NULL)
    {
        reti = regcomp(&compiledRegex, "fgets\\([A-Za-z0-9]+\\);", REG_EXTENDED | REG_ICASE);//gets regex
        reti = regexec(&compiledRegex, textToCheck, 0, NULL, 0);
        if (reti) //if it doesnt match fgets but does the strstr is not null then it is a gets();
        {
            mitreTec = "DDOS            ";//mitre technique and spaces after for formatting during the print
            return 1;
        }
        
       else{return 0;}
    }
    else // if no match, return No Match and 1
    {
        return 0;
    }

    /* Frees memory allocated to the pattern buffer by regcomp() */
    regfree(&compiledRegex);
    printf("%s", mitreTec);
}

void searchFile(char *filename) //searching through the file
{
    FILE *file_ptr; //the pointer for the file.
    int line_number = 1; //line num
    int find_result = 0; //dont think this is used anymore
    int count = 0; //used for the print statement and keeping index on  the array after each for loop completion
    char *temp_str; //the temp string that the whole line is stored on, also used to print out vulnerability

    if ((file_ptr = fopen(filename, "r")) == NULL)//if the file doesnt exist
    {
        printf("file does not exist\n");
    }
    else//added this statement so that the while loopes dont run even if the file doesnt exist
    {
        printf("Line Number  MITRE Techniques\tVulnerability\n");//pretty formatting
        printf("-----------  ----------------\t-------------\n");//^

        while (fgets(temp_str, 10000, file_ptr) != NULL)//while we arent at the end of the file
        {
            if (useRegex(temp_str) == 1) /*If vuln is found create Node*/
            {

                // for (int a = 0; a < 3; a++)//mapping each of the parts of the structure to an array
                // {
                    int a = 0;
                    int b = a + 1;//these are needed so that the during each incrementation of the for there is a slot for each part of the struct
                    int c = a + 2;

                    Node[a + count].lineNum = line_number;//count increments by 3 after each iteration of the while loop so that it doesnt overwrite the already existing values within the array
                    Node[b + count].VULN = malloc(strlen(temp_str)* 2);//allocating space for the string (need this because each is an array)
                    strcpy(Node[b + count].VULN, temp_str);//have to use strcopy so that it gets the value as the string and not the address
                    Node[c + count].MITRE = malloc(strlen(mitreTec) * 2);//allocating space for the string (need this because each is an array)
                    strcpy(Node[c + count].MITRE, mitreTec);
                // }
                printf("%d\t     %s\t%s", Node[count].lineNum, Node[count + 2].MITRE, Node[count + 1].VULN);//printing the 
                
                count += 3;
            }
            line_number++; // incrementing line number
            // count += 3;    // used for the printing
            continue; //just in case
        }
        fclose(file_ptr); //closing the file
        
}
}
int main()
{
    
    char filename[1000], c; //variable to store the filename
    
    printf("Enter the filename to analyze: ");
    scanf("%s", filename);//retrieving the file
    // clock_t tic = clock();
    searchFile(filename); //scan for ouchies located within the file
    // clock_t toc = clock();
    
    
 
    // printf("Elapsed: %f seconds\n", (double)(toc - tic) / CLOCKS_PER_SEC);
    return 0;
   
// // 
}
