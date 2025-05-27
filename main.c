#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>

#define MAX_BUFFER_SIZE 100
#define MAX_ARG_SIZE 30
#define ROOT_DIR "/"
#define SCAN_STRINGS_WITH_SPACES "%63[^\n]%*c"

const char *HOME_DIR()
{
    return getenv("HOME");
}

typedef enum
{
    _echo_,
    _cd_,
    _export_,
    _exit_,
    END_BUILTIN_COMMANDS
} BuiltInCommand;

const char *builtinCommandString[] = {
    "echo",
    "cd",
    "export",
    "exit"
};

/// @brief Extracts built-in commands' respective enum values
BuiltInCommand get_builtin_command_value(char *inputCommand);

/// @brief Converts shellCommand into char* args[]
char **slice_shell_command(char *shellCommand);

/// @brief Main shell interface
void shell();

/// @brief cd to '/'
void setup_environment();

/// @brief
void execute_shell_builtin(BuiltInCommand arg, char **args, const int argsCount);

void execute_command(char **args, const int argsCount);
void on_child_exit();
/// @brief extracts environment variable value
char *extract_env_variable(char **envVarStatement);

void cd(const char *p_path);
void echo(char *arg_echoStatement);
void export_variable(const char *arg_exportStatement);

int main()
{
    // Disable GTK_MODULES messages
    unsetenv("GTK_MODULES");

    // Set the signal handler for child process termination
    signal(SIGCHLD, on_child_exit);

    setup_environment(ROOT_DIR);
    shell();

    return 0;
}

void on_child_exit()
{
    pid_t terminatedProcess;

    /* Creates/Opens a txt file to record processes termination */
    FILE *log_file = fopen("loghistory.txt", "a");
    if (log_file == NULL)
    {
        perror("ERROR: Log registration failed");
        return;
    }

    // Get the current time
    time_t t = time(NULL);
    struct tm *tm_info = localtime(&t);
    char time_str[30];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    // Handle terminated child processes
    while ((terminatedProcess = waitpid(-1, NULL, WNOHANG)) > 0)
    {
        fprintf(log_file, "Process %d terminated at %s\n", terminatedProcess, time_str);
    }

    fclose(log_file);
}

BuiltInCommand get_builtin_command_value(char *inputCommand)
{
    for (int i = 0; i < END_BUILTIN_COMMANDS; ++i)
    {
        if (strcmp(builtinCommandString[i], inputCommand) == 0)
            return (BuiltInCommand)i;
    }
    return END_BUILTIN_COMMANDS;
}

void handle_double_quote(char **currentArg, char **shellCommand)
{

    char *tempStr = strtok_r(*shellCommand, "\"", shellCommand);

    if (tempStr == NULL)
        return;

    *currentArg = realloc(*currentArg, strlen(*currentArg) + strlen(tempStr) + 2);
    strcat(*currentArg, tempStr);
    strcat(*currentArg, "\"");
}

char **slice_shell_command(char *shellCommand)
{
    char **shellCommandArgs = (char **)malloc(MAX_ARG_SIZE);
    short argsCount = 0;

    char *ptr_saveStatus;
    char *tempStr = strtok_r(shellCommand, " ", &ptr_saveStatus);

    /* Extracts strings seperated by whitespace*/
    while (tempStr != NULL)
    {
        shellCommandArgs[argsCount] = strdup(tempStr);

        if (strchr(tempStr, '"'))
        {

            handle_double_quote(&shellCommandArgs[argsCount], &ptr_saveStatus);
        }

        tempStr = strtok_r(NULL, " ", &ptr_saveStatus);
        ++argsCount;
    }

    /* Resize to the exact number of arguments in the command*/
    shellCommandArgs = realloc(shellCommandArgs, (argsCount) * sizeof(char *));

    return shellCommandArgs;
}

void setup_environment()
{
    chdir(ROOT_DIR);
}

void free_shell_args(char **shellCommandArgs, const int argsCount)
{
    for (int i = 0; i < argsCount; ++i)
    {
        free(shellCommandArgs[i]);
    }
    free(shellCommandArgs);
}

void print_shell_prompt()
{
    // extract current working dir
    char cwd[MAX_BUFFER_SIZE];
    getcwd(cwd, sizeof(cwd));

    // Changes home dir with ~
    if (strcmp(cwd, HOME_DIR()) == 0)
    {
        strcpy(cwd, "~");
    }

    // extract the host (device name)
    char hostName[MAX_BUFFER_SIZE];
    gethostname(hostName, sizeof(hostName));

    // extract this device user
    char *user = getenv("USER");

    // Prints shell prompt
    printf("Simple-shell : %s@%s:%s$ ", user, hostName, cwd);

}

void shell()
{
    BuiltInCommand currentCommand = END_BUILTIN_COMMANDS;

    do
    {

        print_shell_prompt();

        char *shellCommand = (char *)malloc(MAX_BUFFER_SIZE);
        scanf(SCAN_STRINGS_WITH_SPACES, shellCommand);

        /* Slice the Input into arguments */
        char **shellCommandArgs = slice_shell_command(shellCommand);

        // Starts with one argument (the null at the end)
        int argsCount = 0;

        // Counts the number of arguments
        while (shellCommandArgs[argsCount] != NULL)
        {
            ++argsCount;
        }

        free(shellCommand);

        /* Extract the base shell command */
        BuiltInCommand extractedCommand = get_builtin_command_value(shellCommandArgs[0]);

        switch (extractedCommand)
        {
        case END_BUILTIN_COMMANDS:
            execute_command(shellCommandArgs, argsCount);
            break;

        default:
            execute_shell_builtin(extractedCommand, shellCommandArgs, argsCount);
            break;
        }

        currentCommand = extractedCommand;

        free_shell_args(shellCommandArgs, argsCount);

    } while (currentCommand != _exit_);
}

void execute_command(char **args, const int argsCount)
{
    // status for foreground or background process
    bool foreground = true;

    /* Handles background process*/
    if (argsCount && strcmp(args[argsCount - 1], "&") == 0)
    {
        // disables foreground
        foreground = false;

        // Adds a NULL to the end of the args
        args[argsCount - 1] = NULL;
    }

    pid_t child_id = fork();

    if (child_id == 0)
    {
        execvp(args[0], args);
        perror("ERROR\n");
        exit(0);
    }
    else if (child_id > 0 && foreground)
    {
        waitpid(child_id, NULL, WUNTRACED);
    }
}

void execute_shell_builtin(BuiltInCommand arg, char **args, const int argsCount)
{
    /* Checks for too many arguments*/
    if (argsCount >= 2 && args[2] != NULL)
        goto HANDLE_ERROR;

    switch (arg)
    {
    case _echo_:
        echo(args[1]);
        break;

    case _cd_:
        cd(args[1]);
        break;

    case _exit_:
        exit(0);
        break;

    case _export_:
        export_variable(args[1]);
        break;
    }

    return;

HANDLE_ERROR:
    printf("ERROR too many arguments : args[2] : %s != (null)\n", args[2]);
}

void cd(const char *p_path)
{
    int status = 0;

    if (p_path == NULL)
        chdir(ROOT_DIR);
    else
        status = chdir(strcmp(p_path, "~") == 0 ? HOME_DIR() : p_path);

    if (status == -1)
    {
        printf("ERROR : Invalid Directory\n");
    }
}

char *extract_env_variable(char **envVarStatement)
{
    /* Increment after $*/
    ++*envVarStatement;

    char *variable = (char *)malloc(MAX_BUFFER_SIZE);

    /* Init with $ and end with null terminator*/
    variable[0] = '\0';

    for (; **envVarStatement != '\0' && **envVarStatement != ' ' && **envVarStatement != '$'; ++*envVarStatement)
    {
        strncat(variable, *envVarStatement, 1);
        char *env_value = getenv(variable);

        if (env_value != NULL)
        {
            free(variable);
            return env_value;
        }
    }

    /*Go back to the previous char for the loop*/
    --*envVarStatement;
    free(variable);
    return NULL;
}

void echo(char *echoStatement)
{
    /* Returns on NULL string*/
    if (echoStatement == NULL)
        goto RETURN;

    /*Terminate if double quotes are not paired*/
    if (*echoStatement == '"' && echoStatement[strlen(echoStatement) - 1] != '"')
        goto ERROR_HANDLER;

    for (; *echoStatement != '\0'; ++echoStatement)
    {

        if (*echoStatement == '"')
            continue;

        if (*echoStatement == '$' && *(echoStatement + 1) != '\0')
        {
            char *newEnvVar = extract_env_variable(&echoStatement);
            /* Print if env variable exists*/
            if (newEnvVar != NULL)
                printf("%s", newEnvVar);
        }
        else
            printf("%c", *echoStatement);
    }

RETURN:
    printf("\n");
    return;

ERROR_HANDLER:
    printf("ERROR : \" must have a closing pair\n");
}

int handle_env_var_id(char **newEnvVar, char **inputEnvVar)
{
    /* String to hold values of existing env variables*/
    char *existingEnvVarValue = NULL;

    /* Checks for existing env variable*/
    if (**inputEnvVar == '$')
    {
        existingEnvVarValue = extract_env_variable(inputEnvVar);
    }

    /* Checks the format for initial char ( alphabet or _ )*/
    bool inputEnVar_correctFormat = isalpha(**inputEnvVar) || **inputEnvVar == '_';

    bool existingnewEnvVar_correctFormat =
        (existingEnvVarValue == NULL ? false
                                     : isalpha(*existingEnvVarValue) || *existingEnvVarValue == '_');

    /* Handles Invalid identifier first char existence*/
    if (!inputEnVar_correctFormat && !existingnewEnvVar_correctFormat)
    {
        return -1;
    }

    if (existingEnvVarValue == NULL)
        strncat(*newEnvVar, *inputEnvVar, 1);
    else
        strcat(*newEnvVar, existingEnvVarValue);

    /* Increments to check for the rest of chars in loop*/
    ++*inputEnvVar;

    for (; **inputEnvVar != '\0'; ++*inputEnvVar)
    {
        /* Resets existing env variable to null to avoid incorrect concat*/
        existingEnvVarValue = NULL;

        if (**inputEnvVar == '$')
        {
            existingEnvVarValue = extract_env_variable(inputEnvVar);
        }

        /* Checks correct idetifier correct format (alphabet , num  or _) */
        inputEnVar_correctFormat = isalpha(**inputEnvVar) || **inputEnvVar == '_' || isdigit(**inputEnvVar);

        existingnewEnvVar_correctFormat =
            (existingEnvVarValue == NULL ? false
                                         : isalpha(*existingEnvVarValue) || *existingEnvVarValue == '_' || isdigit(*existingEnvVarValue));

        /* Handles Invalid identifier chars existence*/
        if (!inputEnVar_correctFormat && !existingEnvVarValue)
        {
            return -1;
        }

        /* Concat the valid char/string to our new Variable*/
        if (existingEnvVarValue != NULL)
        {
            strcat(*newEnvVar, existingEnvVarValue);
        }
        else
        {
            strncat(*newEnvVar, *inputEnvVar, 1);
        }
    }
    return 0;
}

int handle_env_assigned_val(char **newEnvVal, char **inputEnvVal)
{
    /* Handle non closing double quotes*/
    if (**inputEnvVal == '"' && (*inputEnvVal)[strlen(*inputEnvVal) - 1] != '"')
        return -1;

    for (; **inputEnvVal != '\0'; ++*inputEnvVal)
    {
        if (**inputEnvVal == '"')
            continue;

        if (**inputEnvVal == '$')
        {
            // Extracts the env variable value
            char *existingEnvVar = extract_env_variable(inputEnvVal);

            // Concat if the var exists
            if (existingEnvVar != NULL)
            {
                strcat(*newEnvVal, existingEnvVar);
            }
        }
        else
        {
            strncat(*newEnvVal, *inputEnvVal, 1);
        }
    }

    return 0;
}

void export_variable(const char *arg_exportStatement)
{

    if (arg_exportStatement == NULL)
        goto ERROR_HANDLER;

    char *newEnvVar = (char *)malloc(MAX_BUFFER_SIZE);
    char *newEnvValue = (char *)malloc(MAX_BUFFER_SIZE);

    /* Init the strings with null terminator*/
    *newEnvValue = *newEnvVar = '\0';

    /* copies the export statement for strtok modifier*/
    char *exportStatement = strdup(arg_exportStatement);

    /* Extracts the Variable */
    char *tempStr = strtok(exportStatement, "=");

    // Handles no = sign
    if (tempStr == arg_exportStatement)
        goto ERROR_HANDLER;

    // Status of extracting the variable identifier (0: no error)
    int errorStatus = handle_env_var_id(&newEnvVar, &tempStr);

    if (errorStatus)
        goto ERROR_HANDLER;

    /* Extracts the Variable assigned value */
    tempStr = strtok(NULL, "");

    // Handle empty string after =
    if (*tempStr == '\0')
        goto ERROR_HANDLER;

    // 0 : no error
    errorStatus = handle_env_assigned_val(&newEnvValue, &tempStr);

    if (errorStatus)
        goto ERROR_HANDLER;

    /* Add Null terminator to the end*/
    newEnvValue[strlen(newEnvValue)] = '\0';
    newEnvVar[strlen(newEnvVar)] = '\0';

    /* Sets the real size*/
    newEnvVar = realloc(newEnvVar, strlen(newEnvVar) + 1);
    newEnvValue = realloc(newEnvValue, strlen(newEnvValue) + 1);

    /* Sets enviroment variable*/
    setenv(strdup(newEnvVar), strdup(newEnvValue), 1);

    goto FREE_VARIABLES;

ERROR_HANDLER:
    printf("ERROR : Invalid Export Statment\n");

FREE_VARIABLES:
    free(newEnvVar);
    free(newEnvValue);
    free(exportStatement);
}