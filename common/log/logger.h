#ifndef H_LOGGER
#define H_LOGGER

#define LOGGER_E_SUCCESSFUL     0
#define LOGGER_E_INVALID_NAME   1
#define LOGGER_E_IGNORED        2

#define LOGGER_LEVEL_ERROR      0
#define LOGGER_LEVEL_WARN       1
#define LOGGER_LEVEL_INFO       2
#define LOGGER_LEVEL_DEBUG      3

typedef struct logger_s* logger_t;

int logger_create(logger_t *destination, char *name, int level);

int logger_info(logger_t logger, char *fmt, ...);
int logger_warn(logger_t logger, char *fmt, ...);
int logger_error(logger_t logger, char *fmt, ...);
int logger_debug(logger_t logger, char *fmt, ...);

void logger_destroy(logger_t logger);

#endif