
#ifndef GLOBAL_H
#define GLOBAL_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// Structs
typedef struct virus {
    short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

typedef struct linkSigPosition {
    struct linkSigPosition *nextPos;
    int i;
} linkSigPosition;

typedef struct fun_desc {
    char *name;
    void (*fun)();
} fun_desc;

// Global variables
fun_desc menu[];
char fileName[256];
bool isLittleEndian;
link* virus_list;
FILE* output;
char commandLineFileName[256];
linkSigPosition* virusSig_positions;

#define VIRL "VIRL"
#define VIRB "VIRB"

// Function declarations
void SetSigFileName();
virus* readVirus(FILE* file);
void printVirus(virus* v);
void checkMagicNumber(FILE* file);
void ex();
void printSig();
void loadSig();
void findSigPositions();
linkSigPosition* list_append2(linkSigPosition *virus_list, int data);
void list_free2(linkSigPosition *virus_list);
void fixFile();
void list_print(link *virus_list, FILE *stream);
link* list_append(link *virus_list, virus *data);
void list_free(link *virus_list);
void detect_virus(char *buffer, unsigned int size, link *virus_list);
void detect_viruses();
void findSig(char *buffer, unsigned int size, link *virus_list);
void neutralize_virus(char *fileName, int signatureOffset);



#endif // GLOBAL_H

fun_desc menu[]= {
    { "Set signatures file name", SetSigFileName },
    { "Load signatures", loadSig },
    { "Print signatures", printSig },
    { "Detect viruses", detect_viruses },
    { "Fix file", fixFile },
    { "Quit", ex },
    { NULL, NULL }
};


// Function definitions

void SetSigFileName() {
    printf("Enter new signature file name: ");
    if (fgets(fileName, sizeof(fileName), stdin) != NULL) {
        // Remove the newline character if it exists
        size_t len = strlen(fileName);
        if (len > 0 && fileName[len - 1] == '\n') {
            fileName[len - 1] = '\0';
        }
    }
    printf("\nThe current file is %s\n", fileName);
}

virus* readVirus(FILE* file) {
    virus* v = (virus*)malloc(sizeof(virus));
    if (isLittleEndian) {
        if (fread(&v->SigSize, 1, 2, file) != 2) {
            free(v);
            return NULL;
        }
    } else {
        unsigned char buffer[2];
        if (fread(buffer, 1, 2, file) != 2) {
            free(v);
            return NULL;
        }
        v->SigSize = buffer[0] * 256 + buffer[1]; // reconstruct 16-bit value
    }

    if (fread(v->virusName, 16, 1, file) != 1) {
        free(v);
        return NULL;
    }

    v->sig = (unsigned char*)malloc(v->SigSize);    

    if (fread(v->sig, 1, v->SigSize, file) != v->SigSize) {
        free(v->sig);
        free(v);
        return NULL;
    }

    return v;
}

void printVirus(virus* v) {
    fprintf(output, "Virus name: %s\n", v->virusName);
    fprintf(output, "Virus signature length: %u\n", v->SigSize);
    fprintf(output, "Virus signature:\n");
    for (int i = 0; i < v->SigSize; i++) {
        fprintf(output, "%02X ", v->sig[i]);
    }
    fprintf(output, "\n");
}

void checkMagicNumber(FILE* file) {
    char magicNumber[5] = {0}; // 4 bytes for magic number + 1 for null terminator
    if (fread(magicNumber, 1, 4, file) != 4) {
        perror("Error reading magic number");
        fclose(file);
        exit(1);
    }

    if (strcmp(magicNumber, VIRL) != 0 && strcmp(magicNumber, VIRB) != 0) {
        fprintf(stderr, "Invalid magic number: %s\n", magicNumber);
        fclose(file);
        exit(1);
    }

    if (strcmp(magicNumber, VIRB) == 0) {
        isLittleEndian = false;
    }
}

void ex() {
    list_free(virus_list);
    exit(1);
}

void printSig() {
    printf("Current file name: %s\n", fileName);
    if (virus_list != NULL) {
        list_print(virus_list, output);
    } else {
        printf("No signatures loaded\n");
    }
}

void loadSig() {
    FILE* file = fopen(fileName, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }
    checkMagicNumber(file); // updates 'isLittleEndian' variable
    virus* v;
    while ((v = readVirus(file)) != NULL) {
        virus_list = list_append(virus_list, v);
    }
    fclose(file);
}

void detect_viruses() {
    FILE* commandLineFile = fopen(commandLineFileName , "rb");
    if (commandLineFile == NULL) {
        perror("Error opening file");
        return;
    }

    // Determine file size
    fseek(commandLineFile, 0, SEEK_END);
    long fileSize = ftell(commandLineFile);
    fseek(commandLineFile, 0, SEEK_SET);

    // Allocate memory dynamically for the buffer based on file size
    char *buffer = (char *)malloc(fileSize);

    // Read the file into the dynamically allocated buffer
    size_t bytesRead = fread(buffer, 1, fileSize, commandLineFile);
    if (bytesRead != fileSize) {
        perror("Failed to read entire file");
        free(buffer);
        fclose(commandLineFile);
        return;
    }

    // Perform virus detection on the buffer
    detect_virus(buffer, (unsigned int)fileSize, virus_list);

    // Free the dynamically allocated buffer
    free(buffer);
    fclose(commandLineFile);
}

void detect_virus(char *buffer, unsigned int size, link *virus_list) {
    if(buffer == NULL)
    {
        perror("buffer is empty");
        return;
    }
    if(virus_list == NULL)
    {
        perror("list is empty");
    }
    link *current = virus_list;
    while (current != NULL) {
        virus *v = current->vir;
        if(v!=NULL){
            for(unsigned int i=0; i <= size - v->SigSize; i++){
                // Ensure we don't read out of bounds
                    if (memcmp(buffer + i, v->sig, v->SigSize) == 0) {
                        printf("Virus detected!\n");
                        printf("Starting byte location: %u\n", i);
                        printf("Virus name: %s\n", v->virusName);
                        printf("Virus signature size: %u\n", v->SigSize);
                    }
            }
        }
        current = current->nextVirus;
    }
}

void findSigPositions() {
    FILE* commandLineFile = fopen(commandLineFileName , "rb");
    if (commandLineFile == NULL) {
        perror("Error opening file");
        return;
    }

    // Determine file size
    fseek(commandLineFile, 0, SEEK_END);
    long fileSize = ftell(commandLineFile);
    fseek(commandLineFile, 0, SEEK_SET);

    // Allocate memory dynamically for the buffer based on file size
    char *buffer = (char *)malloc(fileSize);

    // Read the file into the dynamically allocated buffer
    size_t bytesRead = fread(buffer, 1, fileSize, commandLineFile);
    if (bytesRead != fileSize) {
        perror("Failed to read entire file");
        free(buffer);
        fclose(commandLineFile);
        return;
    }

    // Perform virus detection on the buffer
    findSig(buffer, (unsigned int)fileSize, virus_list);

    // Free the dynamically allocated buffer
    free(buffer);
    fclose(commandLineFile);
}

void findSig(char *buffer, unsigned int size, link *virus_list)
{
    if(buffer == NULL)
    {
        perror("buffer is empty");
        return;
    }
    if(virus_list == NULL)
    {
        perror("list is empty");
    }
    link *current = virus_list;
    while (current != NULL) {
        virus *v = current->vir;
        if(v!=NULL){
            for(unsigned int i=0; i <= size - v->SigSize; i++){
                // Ensure we don't read out of bounds
                if (memcmp(buffer + i, v->sig, v->SigSize) == 0) {
                   virusSig_positions = list_append2(virusSig_positions , i);
                }
            }
        }
        current = current->nextVirus;
    }
}
void fixFile(){
    findSigPositions();
    linkSigPosition* curr = virusSig_positions;
    while(curr != NULL){
        neutralize_virus(commandLineFileName , curr->i);
        curr = curr->nextPos;
    }
    linkSigPosition* toDelete = virusSig_positions;
    virusSig_positions = NULL;
    list_free2(toDelete);
}

void neutralize_virus(char *fileName, int signatureOffset){
    
    FILE *file2 = fopen(fileName, "rb+");
    if (file2 == NULL) {
        perror("Error opening file");
        return;
    }

    // Calculate the position of the virus in the file
    long int virusPosition = signatureOffset;

    // Seek to the position of the virus in the file
    if (fseek(file2, virusPosition, SEEK_SET) != 0) {
        perror("Error seeking to virus position");
        fclose(file2);
        return;
    }

    // Write the neutralized byte (RET instruction)
    char retInstruction = 0xC3; // RET instruction in x86 assembly
    if (fwrite(&retInstruction, sizeof(char), 1, file2) != 1) {
        perror("Error writing neutralized byte");
        fclose(file2);
        return;
    }

    printf("Virus neutralized successfully!\n");

    // Close the file
    fclose(file2);
}    



// Linked list functions
void list_print(link *virus_list, FILE *stream) {
    while (virus_list != NULL) {
        output = stream;
        printVirus(virus_list->vir);
        fprintf(stream, "\n\n");
        virus_list = virus_list->nextVirus;
    }
}

link* list_append(link *virus_list, virus *data) {
    link *new_link = (link*)malloc(sizeof(link));
    new_link->vir = data;
    new_link->nextVirus = virus_list;
    return new_link;
}

linkSigPosition* list_append2(linkSigPosition *virus_sig_list, int data) {
    linkSigPosition *new_link = (linkSigPosition*)malloc(sizeof(linkSigPosition));
    new_link->i = data;
    new_link->nextPos = virus_sig_list;
    return new_link;
}

void list_free(link *virus_list) {
    while (virus_list != NULL) {
        link *temp = virus_list;
        virus_list = virus_list->nextVirus;
        free(temp->vir->sig); // Free the signature memory
        free(temp->vir);      // Free the virus structure memory
        free(temp);           // Free the link structure memory
    }
}

void list_free2(linkSigPosition *virus_list) {
    while (virus_list != NULL) {
        linkSigPosition *temp = virus_list;
        virus_list = virus_list->nextPos;
        free(temp);          // Free the link structure memory
    }
}

int main(int argc, char **argv) {
    isLittleEndian = true; // default file is LittleEndian
    strncpy(fileName, "signatures-L" , 256);
    char input[128];
    int choice;
    virus_list = NULL;
    virusSig_positions = NULL;
    output = stdout; // default stream to use
    if (argc > 1) {
         strncpy(commandLineFileName, argv[1], 256);
    }    
    while (1) {
        printf("Select operation from the following menu:\n");
        for (int i = 0; menu[i].name != NULL; i++) {
            printf("%d) %s\n", i, menu[i].name);
        }
        printf("Option: ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }
        if (sscanf(input, "%d", &choice) != 1) {
            printf("Invalid input\n");
            continue;
        }

        if(choice >= 0 && menu[choice].name != NULL) {
            menu[choice].fun(virus_list, fileName);
        } 
        else {
            printf("Not within bounds\n");
            break; 
        }
    }

    return 0;
}


// ** task 2a ** 
//chmod u+x infected
//./infected
//./virusDetector infected
//hexedit infected
//ctrl+G - 263 (where the virus begins)
//put C3 where the virus begins 