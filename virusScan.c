#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define FALSE 0
#define TRUE !FALSE

#define DIRLOC 1
#define FILELOC 2
#define TOTALARGC 3

#define FULLSCAN "0"

#define ONE 1

#define SLASH "\\"
#define LOGNAME "\\AntiVirusLog.txt"

#define INFECTED 1
#define INFECTEDFIRSTPART 2
#define INFECTEDLASTPART 3
#define CLEAR 0

#define TWENTYPERCENT 5
#define EIGHTYPERCENT 4

#define STR_LEN 50

typedef struct File
{
    char* path;
    int infectedFlag;
} File;

typedef struct Folder
{
    File** files;
    int amountOfFiles;
} Folder;

void dirChecker(char* path);
void fileChecker(char* path);
void validExecution(int argc, char** argv);
void checkAllocation(void* ptr);
void menu(char** argv, char scanningOption[]);
void folderOpener(Folder* folder, char** argv);
void freeFolder(Folder* folder);
char* fileToString(char* path, int* lenOfFile);
void resultPrinter(File* file);
void logFilePrinter(char** argv, Folder* folder, char scanningOption[]);
int scan(char* virusString, int lenOfVirus, char* fileString, int lenOfFile);
int quickScan(char* virusString, int lenOfVirus, char* fileString, int lenOfFile);
void bubbleSort(char** arr, int n);
void myFgets(char* str);

int main(int argc, char** argv)
{
    Folder folder = { NULL, 0 };
    char* virusString = NULL;
    char* fileString = NULL;
    char scanningOption[STR_LEN] = {0};
    int lenOfFile = 0;
    int lenOfVirus = 0;
    validExecution(argc, argv);
    folderOpener(&folder, argv);
    menu(argv, scanningOption);
    printf("Scanning began...\nThis process may take several minutes...\n\nScanning:\n");
    virusString = fileToString(argv[FILELOC], &lenOfVirus);
    if(!strcmp(scanningOption, FULLSCAN))
    {
        for (int i = 0; i < folder.amountOfFiles; i++)
        {
            fileString = fileToString(folder.files[i]->path, &lenOfFile);
            folder.files[i]->infectedFlag = scan(virusString, lenOfVirus, fileString, lenOfFile); //scanning and puting the result to the flag
            free(fileString);
            resultPrinter(folder.files[i]);
        }
    }
    else
    {
        for (int i = 0; i < folder.amountOfFiles; i++)
        {
            fileString = fileToString(folder.files[i]->path, &lenOfFile);
            folder.files[i]->infectedFlag = quickScan(virusString, lenOfVirus, fileString, lenOfFile); //scanning and puting the result to the flag
            free(fileString);
            resultPrinter(folder.files[i]);
        }
    }
    printf("Scan Completed.\nSee log path for results: %s/AntiVirusLog.txt\n", argv[DIRLOC]);
    logFilePrinter(argv, &folder, scanningOption);
    free(virusString);
    freeFolder(&folder);
    getchar();
    return EXIT_SUCCESS;
}

void dirChecker(char* path)
/*
This function checks if the path that was given can be opened as a dir
Input: pointer of chars (string of array) that will be used as a dir path
Output: none
*/
{
    DIR* d = NULL;
    struct dirent* dir = NULL;
    d = opendir(path);
    if (d == NULL) //if cant open dir
    {
        printf("Error opening directory: %s\n", path);
        getchar();
        exit(EXIT_FAILURE);
    }
    closedir(d);
}

void fileChecker(char* path)
/*
This function checks if the path that was given can be opened as a file
Input: pointer of chars (string of array) that will be used as a file path
Output: none
*/
{
    FILE* file = NULL;
    file = fopen(path, "r");
    if (file == NULL) //if cant open filevcb,
    {
        printf("Error opening file: %s\n", path);
        getchar();
        exit(EXIT_FAILURE);
    }
    fclose(file);
}

void validExecution(int argc, char** argv)
/*
This function checks if the execution was valid, if we had the right amount of argc and if the argv are working as a paths
Input: argc, argv
Output: none
*/
{
    if (argc != TOTALARGC) // if too much or less arguments
    {
        printf("Invalid execution.\nUsage: virusScan.exe <dir> <file>\n");
        getchar();
        exit(EXIT_FAILURE);
    }
    dirChecker(argv[DIRLOC]); //checks if the second arg is not a path to a dir
    fileChecker(argv[FILELOC]); //checks if the third arg is not a path to a file
}

void menu(char** argv, char scanningOption[])
/*
This function prints the menu and return the option that the user chose
Input: argv to print the paths
Output: char that represent the choice
*/
{
    //prints the menu
    printf("Welcome to my Virus Scan!\n\n");
    printf("Folder to scan: %s\n", argv[DIRLOC]);
    printf("Virus signature: %s\n", argv[FILELOC]);
    printf("Press 0 for a normal scan or any other key for a quick scan: ");
    myFgets(scanningOption);
}

void checkAllocation(void* ptr)
/*
This function checks in the allocating was good
Input: a pointer
Output: none
*/
{
    if (ptr == NULL) //if the pointer didnt got a value than exit
    {
        printf("Memory allocation error!\n");
        getchar();
        exit(EXIT_FAILURE);
    }
}

void folderOpener(Folder* folder, char** argv)
/*
This function sets the right amount of files in the files array in folder and sets all the value of each file to the path and resets the infectedFlag
Input: argv to get the path of the dir and a pointer to the folder we want to set
Output: none
*/
{
    DIR* d = NULL;
    struct dirent* dir = NULL;
    char** paths = NULL;
    char* temp = NULL;
    int amountOfFiles = 0;
    d = opendir(argv[DIRLOC]);
    //sets all the file names into the paths array
    while ((dir = readdir(d)) != NULL)
    {
        if (strcmp(dir->d_name, ".") && strcmp(dir->d_name, ".."))
        {
            amountOfFiles++;
            paths = (char**)realloc(paths, amountOfFiles * sizeof(char*));
            checkAllocation(paths);
            paths[amountOfFiles - ONE] = (char*)malloc(sizeof(char) * (strlen(dir->d_name) + strlen(SLASH) + strlen(argv[DIRLOC]) + ONE));
            checkAllocation(paths[amountOfFiles - ONE]);
            strcpy(paths[amountOfFiles - ONE], argv[DIRLOC]);
            strcat(paths[amountOfFiles - ONE], SLASH);
            strcat(paths[amountOfFiles - ONE], dir->d_name);
        }
    }
    //sorting the paths array
    bubbleSort(paths, amountOfFiles);
    folder->amountOfFiles = amountOfFiles;
    folder->files = (File**)malloc(folder->amountOfFiles * sizeof(File*));
    checkAllocation(folder->files);
    for(int i = 0; i < amountOfFiles; i++)
    {
        folder->files[i] = (File*)malloc(sizeof(File));
        checkAllocation(folder->files[i]);
        folder->files[i]->infectedFlag = FALSE;
        folder->files[i]->path = paths[i];
    }
    free(paths); //free the paths array
    closedir(d);
}

char* fileToString(char* path, int* lenOfFile)
/*
This function return a pointer to a string that contains what is in a file
Input: path to a file and pointer to int that will hold the length of the file
Output: pointer to what the file containes
*/
{
    FILE* file = NULL;
    long int sizeOfFile = 0;
    char* fileString = NULL;
    file = fopen(path, "rb");
    fileChecker(path);
    fseek(file, 0, SEEK_END);
    *lenOfFile = ftell(file);
    fileString = (char*)malloc(sizeof(char) * (*lenOfFile + ONE));
    checkAllocation(fileString);
    rewind(file);
    fread(fileString, *lenOfFile + ONE, ONE, file);
    fclose(file);
    return fileString;
}

void freeFolder(Folder* folder)
/*
Free all the memory allocated to the folder
Input: pointer to a folder
Output: none
*/
{
    int i = 0;
    for (i = 0; i < folder->amountOfFiles; i++)
    {
        free(folder->files[i]->path);
        free(folder->files[i]);
    }
    free(folder->files);
}

void logFilePrinter(char** argv, Folder* folder, char scanningOption[])
/*
Prints to the file the result of the scan
Input: argv, pointer to folder, the scanningOption
Output: none
*/
{
    FILE* file = NULL;
    char* logFilePath = NULL;
    logFilePath = (char*)malloc(sizeof(char) * (strlen(argv[DIRLOC]) + strlen(LOGNAME)));
    checkAllocation(logFilePath);
    strcpy(logFilePath, argv[DIRLOC]);
    strcat(logFilePath, LOGNAME);
    file = fopen(logFilePath, "w");
    fileChecker(logFilePath);
    fprintf(file, "Anti-virus began! Welcome!\n\nFolder to scan:\n%s\nVirus signature:\n%s\n\nScanning option:\n", argv[DIRLOC], argv[FILELOC]);
    if(!strcmp(scanningOption, FULLSCAN))
        fprintf(file, "Normal Scan\n\n");
    else
        fprintf(file, "Quick Scan\n\n");
    fprintf(file, "Results:\n");
    for(int i = 0; i < folder->amountOfFiles; i++)
    {
        //prints the path to the file
        fprintf(file, "%s  ", folder->files[i]->path);
        //prints to the file if the file infected
        switch(folder->files[i]->infectedFlag)
        {
            case(CLEAR):
                fprintf(file, "Clean\n");
                break;
            case(INFECTED):
                fprintf(file, "Infected!\n");
                break;
            case(INFECTEDFIRSTPART):
                fprintf(file, "Infected! (first 20%%)\n");
                break;
            case(INFECTEDLASTPART):
                fprintf(file, "Infected! (last 20%%)\n");
                break;
        }
    }
    free(logFilePath);
    fclose(file);
}

void resultPrinter(File* file)
/*
Prints the result to the screen for each file
Input: pointer to a file
Output: none
*/
{
    //prints the path
    printf("%s - ", file->path);
    //prints the effect on it
    switch(file->infectedFlag)
    {
        case(CLEAR):
            printf("Clean\n");
            break;
        case(INFECTED):
            printf("Infected!\n");
            break;
        case(INFECTEDFIRSTPART):
            printf("Infected! (first 20%%)\n");
            break;
        case(INFECTEDLASTPART):
            printf("Infected! (last 20%%)\n");
            break;
    }
}

int scan(char* virusString, int lenOfVirus, char* fileString, int lenOfFile)
/*
This function preforms a scan on fileString and tries to find if virusString is in fileString
Input: string of the virus and the len of it and string of the file and the len of it
Output: flag if the virus found or not
*/
{
    int fileCounter = 0;
    int virusCounter = 0;
    int infectedFlag = 0;
    while(fileCounter - virusCounter <= lenOfFile - lenOfVirus && infectedFlag == FALSE)
    {
        if(*(virusString + virusCounter) == *(fileString + fileCounter))
            virusCounter++;

        else
            virusCounter = 0;

        if(virusCounter == lenOfVirus)
            infectedFlag = INFECTED;

        fileCounter++;
    }
    return infectedFlag;
}

int quickScan(char* virusString, int lenOfVirus, char* fileString, int lenOfFile)
/*
This function preforms a quick scan, first it sends the pointer to the beggining of the file and the len until the 20 percent
of the file than it sends the pointer to the 80 percent of the file and scans until the end of the file and if both of them didnt
found a virus than it preformes a regular scan
Input: string of the virus and the len of it and string of the file and the len of it
Output: the flag that tells if the virus found and where
*/
{
    int infectedFlag = 0;
    
    if(scan(virusString, lenOfVirus, fileString, lenOfFile / TWENTYPERCENT))
        infectedFlag = INFECTEDFIRSTPART;
    
    else if(scan(virusString, lenOfVirus, fileString + lenOfFile / TWENTYPERCENT * EIGHTYPERCENT, lenOfFile / TWENTYPERCENT))
        infectedFlag = INFECTEDLASTPART;
    
    else if(scan(virusString, lenOfVirus, fileString, lenOfFile))
        infectedFlag = INFECTED;
    
    return infectedFlag;
}

void bubbleSort(char** arr, int n)
/*
Sorting array of strings
Input: char** of array of strings and the len of it
Output: none
*/
{
    char* temp = NULL;
    for (int i = 0; i < n - ONE; i++)     
    { 
        // Last i elements are already in place   
        for (int j = 0; j < n - i - ONE; j++) 
        {
            if (strcmp(arr[j], arr[j + ONE]) > 0)
            {
                temp = arr[j];
                arr[j] = arr[j + ONE];
                arr[j + ONE] = temp;
            }
        }
    }
}

void myFgets(char* str)
/*
* This function will get a string and put it in an array
* Input: the string that we want to put it in and the length of the string
* Output: None
*/
{
    fgets(str, STR_LEN, stdin);
    str[strcspn(str, "\n")] = 0;
}