#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <errno.h>

int main() {
    printf("1. Инициализация seccomp...\n");

    // Создаем контекст фильтра: по умолчанию РАЗРЕШАЕМ все системные вызовы
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (ctx == NULL) {
        perror("Ошибка seccomp_init");
        return 1;
    }

    // Добавляем правила: ЗАПРЕЩАЕМ вызовы fork и clone.
    // SCMP_ACT_ERRNO(EPERM) вернет процессу ошибку "Operation not permitted" вместо аварийного завершения.
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(fork), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 0);

    // Применяем фильтр к текущему процессу
    if (seccomp_load(ctx) < 0) {
        perror("Ошибка seccomp_load");
        seccomp_release(ctx);
        return 1;
    }
    seccomp_release(ctx);

    printf("2. Фильтры seccomp успешно применены.\n");
    printf("3. Делаем попытку вызова fork()...\n");

    // Пытаемся вызвать заблокированный fork
    pid_t pid = fork();

    if (pid == -1) {
        // Если seccomp отработал верно, fork вернет -1
        perror("-> Результат вызова fork");
    } else if (pid == 0) {
        printf("Дочерний процесс!\n");
        return 0;
    } else {
        printf("Родительский процесс!\n");
    }

    // Демонстрация того, что остальные системные вызовы (например, write внутри printf) работают
    printf("4. Демонстрация: программа продолжает работу после заблокированного системного вызова.\n");

    return 0;
}
