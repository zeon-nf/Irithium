#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <pwd.h>

#define MAX_LINE     1024
#define MAX_ITEMS    256
#define MAX_NAME_LEN 256

typedef enum {
    SEC_NONE,
    SEC_PACKAGES,
    SEC_USERS,
    SEC_SERVICES,
    SEC_POSTINST
} Section;

typedef struct {
    char name[MAX_NAME_LEN];
    char version_op[8];
    char version[64];
} Package;

typedef struct {
    char alias[MAX_NAME_LEN];
    Package items[MAX_ITEMS];
    int count;
} PackageGroup;

typedef struct {
    char name[MAX_NAME_LEN];
} User;

typedef struct {
    char name[MAX_NAME_LEN];
} Service;

typedef struct {
    char cmd[MAX_LINE];
} PostinstCmd;

typedef struct {
    PackageGroup groups[MAX_ITEMS];
    int group_count;

    User users[MAX_ITEMS];
    int user_count;

    Service services[MAX_ITEMS];
    int service_count;

    PostinstCmd postinst[MAX_ITEMS];
    int postinst_count;
} Config;

static char *ltrim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

static void rtrim(char *s) {
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
}

static void strip_comment(char *s) {
    int in_str = 0;
    for (size_t i = 0; i < strlen(s); i++) {
        if (s[i] == '"') in_str = !in_str;
        if (!in_str && s[i] == '#') {
            s[i] = '\0';
            break;
        }
    }
}

static int extract_quoted(const char *s, char *out, size_t out_size) {
    const char *start = strchr(s, '"');
    if (!start) return 0;
    start++;
    const char *end = strchr(start, '"');
    if (!end) return 0;
    size_t len = (size_t)(end - start);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return 1;
}

static void parse_package_entry(const char *raw, Package *pkg) {
    char tmp[MAX_LINE];
    strncpy(tmp, raw, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *geq = strstr(tmp, ">=");
    if (geq) {
        *geq = '\0';
        strncpy(pkg->version_op, ">=", sizeof(pkg->version_op) - 1);
        char *ver = geq + 2;
        while (*ver && isspace((unsigned char)*ver)) ver++;
        strncpy(pkg->version, ver, sizeof(pkg->version) - 1);
    } else {
        pkg->version_op[0] = '\0';
        pkg->version[0] = '\0';
    }
    rtrim(tmp);
    strncpy(pkg->name, tmp, sizeof(pkg->name) - 1);
}

static int parse_config(const char *path, Config *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "error: cannot open config file: %s\n", path);
        return 0;
    }

    memset(cfg, 0, sizeof(*cfg));

    char line[MAX_LINE];
    int started = 0;
    int finished = 0;
    Section sec = SEC_NONE;
    PackageGroup *cur_group = NULL;

    while (fgets(line, sizeof(line), f)) {
        rtrim(line);
        char *s = ltrim(line);

        if (!started) {
            if (strcmp(s, "!STRT!") == 0) started = 1;
            continue;
        }
        if (strcmp(s, "!FNSH!") == 0) {
            finished = 1;
            break;
        }

        strip_comment(s);
        rtrim(s);
        if (*s == '\0') continue;

        if (strncmp(s, "func ", 5) == 0) {
            char *fname = ltrim(s + 5);
            rtrim(fname);
            if (strcmp(fname, "packages") == 0)      sec = SEC_PACKAGES;
            else if (strcmp(fname, "users") == 0)    sec = SEC_USERS;
            else if (strcmp(fname, "services") == 0) sec = SEC_SERVICES;
            else if (strcmp(fname, "postinst:") == 0 || strcmp(fname, "postinst") == 0)
                sec = SEC_POSTINST;
            cur_group = NULL;
            continue;
        }

        if (sec == SEC_PACKAGES && strncmp(s, "define ", 7) == 0) {
            char *rest = ltrim(s + 7);
            char *as = strstr(rest, " as:");
            if (!as) continue;
            *as = '\0';
            char alias[MAX_NAME_LEN];
            strncpy(alias, rest, sizeof(alias) - 1);
            rtrim(alias);

            if (cfg->group_count >= MAX_ITEMS) continue;
            cur_group = &cfg->groups[cfg->group_count++];
            memset(cur_group, 0, sizeof(*cur_group));
            strncpy(cur_group->alias, alias, sizeof(cur_group->alias) - 1);
            continue;
        }

        if (sec == SEC_PACKAGES && cur_group && s[0] == '"') {
            char pkg_str[MAX_LINE];
            if (!extract_quoted(s, pkg_str, sizeof(pkg_str))) continue;
            if (cur_group->count >= MAX_ITEMS) continue;
            Package *pkg = &cur_group->items[cur_group->count++];
            memset(pkg, 0, sizeof(*pkg));
            parse_package_entry(pkg_str, pkg);
            continue;
        }

        if (sec == SEC_USERS && s[0] == '"') {
            if (cfg->user_count >= MAX_ITEMS) continue;
            char uname[MAX_NAME_LEN];
            if (!extract_quoted(s, uname, sizeof(uname))) continue;
            strncpy(cfg->users[cfg->user_count++].name, uname, MAX_NAME_LEN - 1);
            continue;
        }

        if (sec == SEC_SERVICES && s[0] == '"') {
            if (cfg->service_count >= MAX_ITEMS) continue;
            char sname[MAX_NAME_LEN];
            if (!extract_quoted(s, sname, sizeof(sname))) continue;
            strncpy(cfg->services[cfg->service_count++].name, sname, MAX_NAME_LEN - 1);
            continue;
        }

        if (sec == SEC_POSTINST && strncmp(s, "sys.run[", 8) == 0) {
            if (cfg->postinst_count >= MAX_ITEMS) continue;
            char *inner_start = strchr(s + 8, '(');
            if (!inner_start) continue;
            inner_start++;
            char *inner_end = strrchr(inner_start, ')');
            if (!inner_end) continue;
            *inner_end = '\0';
            char cmd_str[MAX_LINE];
            if (!extract_quoted(inner_start, cmd_str, sizeof(cmd_str))) continue;
            strncpy(cfg->postinst[cfg->postinst_count++].cmd, cmd_str, MAX_LINE - 1);
            continue;
        }

        if (strcmp(s, "then;") == 0) {
            sec = SEC_NONE;
            cur_group = NULL;
            continue;
        }
    }

    fclose(f);

    if (!started) {
        fprintf(stderr, "error: missing !STRT! marker\n");
        return 0;
    }
    if (!finished) {
        fprintf(stderr, "error: missing !FNSH! marker\n");
        return 0;
    }

    return 1;
}

static int run_cmd_argv(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static int run_cmd_argv_yes(char *const argv[]) {
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        execvp(argv[0], argv);
        perror("execvp");
        _exit(127);
    }

    close(pipefd[0]);
    const char *yes = "yes\n";
    write(pipefd[1], yes, 4);
    close(pipefd[1]);

    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static int napt_install_one(const char *pkg, int apply_host) {
    if (apply_host) {
        char *argv[] = { "napt", "install", (char *)pkg, "--apply-host", NULL };
        return run_cmd_argv_yes(argv);
    } else {
        char *argv[] = { "napt", "install", (char *)pkg, NULL };
        return run_cmd_argv_yes(argv);
    }
}

static int useradd_user(const char *name) {
    char *argv[] = { "useradd", "-m", (char *)name, NULL };
    return run_cmd_argv(argv);
}

static int systemctl_enable(const char *name) {
    char *argv[] = { "systemctl", "enable", "--now", (char *)name, NULL };
    return run_cmd_argv(argv);
}

static int run_shell_cmd(const char *cmd) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }
    if (pid == 0) {
        char *argv[] = { "sh", "-c", (char *)cmd, NULL };
        execvp("sh", argv);
        perror("execvp");
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

static void apply_config(const Config *cfg, int apply_host) {
    int total = 0;
    for (int g = 0; g < cfg->group_count; g++) total += cfg->groups[g].count;

    if (total > 0) {
        char **pkg_args = malloc(total * sizeof(char *));
        char (*pkg_bufs)[MAX_LINE] = malloc(total * MAX_LINE);
        if (!pkg_args || !pkg_bufs) {
            fprintf(stderr, "error: out of memory\n");
            free(pkg_args);
            free(pkg_bufs);
            return;
        }

        int idx = 0;
        printf("Installing packages:\n");
        for (int g = 0; g < cfg->group_count; g++) {
            const PackageGroup *grp = &cfg->groups[g];
            for (int i = 0; i < grp->count; i++) {
                const Package *pkg = &grp->items[i];
                if (pkg->version_op[0] && pkg->version[0])
                    snprintf(pkg_bufs[idx], MAX_LINE, "%s (%s %s)", pkg->name, pkg->version_op, pkg->version);
                else
                    snprintf(pkg_bufs[idx], MAX_LINE, "%s", pkg->name);
                printf("  -> %s\n", pkg_bufs[idx]);
                pkg_args[idx] = pkg_bufs[idx];
                idx++;
            }
        }

        for (int j = 0; j < idx; j++) {
            int rc = napt_install_one(pkg_args[j], apply_host);
            if (rc != 0)
                fprintf(stderr, "warning: napt install failed for %s (rc=%d)\n", pkg_args[j], rc);
        }

        free(pkg_args);
        free(pkg_bufs);
    }

    for (int i = 0; i < cfg->user_count; i++) {
        const char *uname = cfg->users[i].name;
        struct passwd *pw = getpwnam(uname);
        if (pw) {
            printf("User %s already exists, skipping.\n", uname);
            continue;
        }
        printf("Creating user: %s\n", uname);
        int rc = useradd_user(uname);
        if (rc != 0)
            fprintf(stderr, "  warning: useradd failed for %s (rc=%d)\n", uname, rc);
    }

    for (int i = 0; i < cfg->service_count; i++) {
        printf("Enabling service: %s\n", cfg->services[i].name);
        int rc = systemctl_enable(cfg->services[i].name);
        if (rc != 0) {
            fprintf(stderr, "  warning: systemctl enable failed for %s (rc=%d)\n", cfg->services[i].name, rc);
        }
    }

    if (cfg->postinst_count > 0) {
        printf("Running postinst commands...\n");
        for (int i = 0; i < cfg->postinst_count; i++) {
            printf("  $ %s\n", cfg->postinst[i].cmd);
            int rc = run_shell_cmd(cfg->postinst[i].cmd);
            if (rc != 0) {
                fprintf(stderr, "  warning: postinst command failed (rc=%d)\n", rc);
            }
        }
    }
}

static void generate_example(void) {
    const char *example =
        "# Irithium configuration file\n"
        "# Generated by: irithium --gen,this is a example!\n"
        "#\n"
        "# Syntax reference:\n"
        "#   func packages             - declare package groups\n"
        "#   define @group_name as:    - start a named package group\n"
        "#   \"pkg\"                     - package name\n"
        "#   \"pkg\" >=1.2.3             - package with minimum version constraint\n"
        "#   func users                - declare system users to create\n"
        "#   func services             - declare systemd services to enable\n"
        "#   func postinst:            - commands to run after all installations\n"
        "#   sys.run[(\"command\")]       - shell command executed in postinst\n"
        "#   then;                     - closes a postinst block\n"
        "\n"
        "!STRT!\n"
        "\n"
        "func packages\n"
        "\n"
        "# Core system packages required by Arvor Linux\n"
        "define @core as:\n"
        "\"nsm\"             # snapshot manager\n"
        "\"napt\"            # package manager\n"
        "\"nlc\"             # chroot launcher\n"
        "\n"
        "# Desktop environment and user-facing applications\n"
        "define @desktop as:\n"
        "\"gnome\"     # example DE \n"
        "\"ptyxis\"          # terminal\n"
        "\n"
        "func users\n"
        "\n"
        "# System users to create with home directories\n"
        "define @users as:\n"
        "\"ferret\"\n"
        "\"stoat\"\n"
        "\n"
        "func services\n"
        "\n"
        "# Systemd services to enable and start immediately\n"
        "define @services as:\n"
        "\"naptd\"           # napt background daemon\n"
        "\n"
        "func postinst:\n"
        "\n"
        "# Post-installation commands run after all packages and users are set up\n"
        "sys.run[(\"logger -t irithium 'Configuration applied successfully'\")]\n"
        "sys.run[(\"echo 'Arvor Linux configured by Irithium' > /etc/irithium-stamp\")]\n"
        "\n"
        "then;\n"
        "!FNSH!\n";

    char cwd[4096];
    if (!getcwd(cwd, sizeof(cwd))) {
        perror("error: getcwd");
        return;
    }

    char out_path[4096 + 12];
    snprintf(out_path, sizeof(out_path), "%s/example.config.nf", cwd);

    FILE *f = fopen(out_path, "w");
    if (!f) {
        fprintf(stderr, "error: cannot write %s: %s\n", out_path, strerror(errno));
        return;
    }
    fputs(example, f);
    fclose(f);
    printf("Generated: %s\n", out_path);
}

static void show_help(void) {
    printf(
        "irithium - Irithium - Arvor Linux configuration applier\n\n"
        "Usage: irithium [options]\n\n"
        "Options:\n"
        "  --predef <file>   Load and apply a .config.nf predefinition file\n"
        "  --apply-host      Skip chroot test, apply directly to host (or set APPLY_HOST=1)\n"
        "  --gen             Generate an example .config.nf in the current directory\n"
        "  --help            Show this help message\n"
    );
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        show_help();
        return 1;
    }

    const char *predef_path = NULL;
    int do_gen = 0;
    int apply_host = 0;

    const char *env_apply = getenv("APPLY_HOST");
    if (env_apply && strcmp(env_apply, "1") == 0) apply_host = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            show_help();
            return 0;
        } else if (strcmp(argv[i], "--gen") == 0) {
            do_gen = 1;
        } else if (strcmp(argv[i], "--apply-host") == 0) {
            apply_host = 1;
        } else if (strcmp(argv[i], "--predef") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "error: --predef requires a file argument\n");
                return 1;
            }
            predef_path = argv[++i];
        } else {
            fprintf(stderr, "error: unknown option: %s\n", argv[i]);
            show_help();
            return 1;
        }
    }

    if (do_gen) {
        generate_example();
        return 0;
    }

    if (predef_path) {
        if (geteuid() != 0) {
            fprintf(stderr, "error: root privileges required\n");
            return 1;
        }
        Config *cfg = malloc(sizeof(Config));
        if (!cfg) {
            fprintf(stderr, "error: out of memory\n");
            return 1;
        }
        if (!parse_config(predef_path, cfg)) {
            free(cfg);
            return 1;
        }
        apply_config(cfg, apply_host);
        free(cfg);
        return 0;
    }

    show_help();
    return 1;
}
