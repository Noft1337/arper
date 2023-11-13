

#define LOGGER_VERSION "1.0.1"
#define INFO 1
#define WARNING 2
#define CRITICAL 3
#define ERROR 4

extern void set_type_msg(char msg[], int type);
extern void set_time_string(char *time_string);
extern void logger(char *msg, int type, ...);
