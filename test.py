"""
Domain availability checker with DNS and ping verification.
Optimized for Windows/Linux cross-platform support.
"""
import sys
import ssl
import platform
import asyncio
import aiodns
import aiohttp
from typing import Callable

# Константы
DNS_SERVERS = ('1.1.1.1', '8.8.8.8', '9.9.9.9')
DNS_TIMEOUT = 10.0
PING_TIMEOUT = 5.0
HTTP_TIMEOUT = 10.0
TCP_TIMEOUT = 5.0
DEFAULT_CONCURRENCY = 30


async def check_dns(domain: str, timeout: float = DNS_TIMEOUT, retries: int = 2) -> tuple[bool, str | None]:
    """
    Проверяет DNS-резолв домена через несколько серверов.
    Возвращает (success, ip_address).
    Если A-запись не найдена, проверяет SOA (чтобы не удалять корневые домены типа oaiusercontent.com).
    """
    for attempt in range(retries):
        resolver = aiodns.DNSResolver()
        for server in DNS_SERVERS:
            resolver.nameservers = [server]
            try:
                # Попытка 1: Ищем A-запись (IPv4)
                result = await asyncio.wait_for(
                    resolver.query(domain, 'A'),
                    timeout=timeout
                )
                if result:
                    return True, result[0].host
            except (aiodns.error.DNSError, asyncio.TimeoutError):
                # Если A-записи нет, проверяем SOA (существует ли зона вообще)
                # Делаем это только на последней попытке или если ошибка явная (NODATA)
                try:
                    await asyncio.wait_for(
                        resolver.query(domain, 'SOA'),
                        timeout=timeout
                    )
                    # Зона существует, но нет A-записи (нормально для CDN/Service roots)
                    return True, None
                except (aiodns.error.DNSError, asyncio.TimeoutError):
                    continue
                    
        # Небольшая пауза перед retry (если сервер вообще не ответил)
        if attempt < retries - 1:
            await asyncio.sleep(0.5)
            
    return False, None


async def check_ping(domain: str, timeout: float = PING_TIMEOUT) -> bool:
    """
    Асинхронный ping с кроссплатформенной поддержкой.
    Примечание: многие живые серверы блокируют ICMP (ping).
    """
    is_windows = platform.system().lower() == 'windows'
    
    if is_windows:
        cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), domain]
    else:
        cmd = ['ping', '-c', '1', '-W', str(int(timeout)), domain]
    
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout + 2)
        return proc.returncode == 0
    except asyncio.TimeoutError:
        if proc:
            proc.kill()
        return False
    except Exception:
        return False


async def check_tcp_port(host: str, port: int, timeout: float = TCP_TIMEOUT) -> bool:
    """
    Проверяет открыт ли TCP-порт.
    host может быть доменом или IP-адресом.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def check_http(domain: str, timeout: float = HTTP_TIMEOUT) -> bool:
    """
    Проверяет HTTP/HTTPS доступность домена.
    """
    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    
    # Создаём SSL-контекст который не проверяет сертификаты, но поддерживает SNI
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    connector = aiohttp.TCPConnector(ssl=ssl_context, limit=1)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout_obj,
            headers=headers
        ) as session:
            for scheme in ('https', 'http'):
                url = f"{scheme}://{domain}"
                try:
                    async with session.head(url, allow_redirects=True) as resp:
                        return True
                except Exception:
                    # Некоторые серверы не поддерживают HEAD, пробуем GET
                    try:
                        async with session.get(url, allow_redirects=True) as resp:
                            return True
                    except Exception:
                        continue
    except Exception:
        pass
    return False


async def check_domain(
    domain: str, 
    semaphore: asyncio.Semaphore,
    use_http: bool = True
) -> tuple[str, bool, dict]:
    """
    Проверяет домен по четырём критериям: DNS → HTTP → TCP → Ping.
    
    Логика:
    - Живой, если работает ХОТЯ БЫ ОДИН метод (DNS или HTTP или TCP или Ping).
    - Мёртвый, если не работает НИЧЕГО.
    
    Возвращает (domain, is_alive, details).
    """
    async with semaphore:
        details = {'dns': False, 'http': False, 'tcp': False, 'ping': False}
        
        try:
            # Шаг 1: DNS
            dns_ok, ip_address = await check_dns(domain)
            details['dns'] = dns_ok
            
            # Шаг 2: HTTP (только если DNS ок, так эффективнее)
            if dns_ok and use_http:
                details['http'] = await check_http(domain)
            
            # Шаг 3: TCP (только если есть IP)
            if ip_address:
                for port in (443, 80):
                    if await check_tcp_port(ip_address, port):
                        details['tcp'] = True
                        break
            
            # Шаг 4: Ping (как последний шанс, даже если DNS провалился)
            target = ip_address if ip_address else domain
            details['ping'] = await check_ping(target)
            
            # Итоговое решение: жив, если хоть что-то сработало
            is_alive = details['dns'] or details['http'] or details['tcp'] or details['ping']
            
            return domain, is_alive, details
            
        except Exception:
            return domain, False, details


async def run_checks(
    domains: list[str],
    concurrency: int = DEFAULT_CONCURRENCY,
    use_http: bool = True,
    progress_callback: Callable[[int, int], None] | None = None
) -> tuple[list[tuple[str, dict]], list[tuple[str, dict]]]:
    """
    Запускает проверку всех доменов с ограничением параллельности.
    
    Возвращает (alive_domains, dead_domains) с деталями проверки.
    
    Гарантии:
    - Каждый домен будет проверен (нет пропусков)
    - Результаты возвращаются по мере готовности
    - Semaphore предотвращает перегрузку
    """
    semaphore = asyncio.Semaphore(concurrency)
    total = len(domains)
    
    # Создаём все задачи сразу
    tasks = [
        asyncio.create_task(check_domain(d, semaphore, use_http))
        for d in domains
    ]
    
    alive = []
    dead = []
    processed = 0
    
    # Обрабатываем результаты по мере готовности
    for coro in asyncio.as_completed(tasks):
        try:
            domain, is_alive, details = await coro
        except Exception:
            # Не должно случиться, но на всякий случай
            continue
        
        if is_alive:
            alive.append((domain, details))
        else:
            dead.append((domain, details))
        
        processed += 1
        if progress_callback:
            progress_callback(processed, total)
    
    return alive, dead


def print_progress(current: int, total: int) -> None:
    """Выводит прогресс в одну строку."""
    pct = (current / total * 100) if total > 0 else 0
    print(f"\rПрогресс: {current}/{total} ({pct:.1f}%)", end='', flush=True)


def load_domains(file_path: str) -> list[str]:
    """Загружает домены из файла, пропуская пустые строки, комментарии и дубликаты."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            seen = set()
            domains = []
            for line in f:
                domain = line.strip()
                if domain and not domain.startswith('#') and domain not in seen:
                    seen.add(domain)
                    domains.append(domain)
            return domains
    except FileNotFoundError:
        print(f"Ошибка: файл '{file_path}' не найден.")
        sys.exit(1)


def main():
    file_path = 'list.txt'
    domains = load_domains(file_path)
    
    if not domains:
        print("Список доменов пуст.")
        sys.exit(0)
    
    print(f"Начало проверки {len(domains)} доменов...")
    print("Метод: DNS → HTTP → TCP → Ping\n")
    
    alive, dead = asyncio.run(
        run_checks(domains, use_http=True, progress_callback=print_progress)
    )
    
    print()  # Новая строка после прогресса
    print(f"\n{'='*50}")
    print(f"Проверено: {len(domains)}")
    print(f"Рабочих:   {len(alive)}")
    print(f"Мёртвых:   {len(dead)}")
    
    if dead:
        print(f"\n{'='*50}")
        print("Мёртвые домены:")
        for domain, details in dead:
            status = []
            if not details['dns']:
                status.append("DNS✗")
            else:
                status.append("DNS✓")
                if not details['http']:
                    status.append("HTTP✗")
                if not details.get('tcp', False):
                    status.append("TCP✗")
                if not details['ping']:
                    status.append("Ping✗")
            print(f"  - {domain} [{' '.join(status)}]")
        
        # Предложение удалить мёртвые домены
        print(f"\n{'='*50}")
        answer = input("Удалить мёртвые домены из list.txt? (Y/N): ").strip().lower()
        if answer == 'y':
            remove_dead_domains(file_path, dead)


def remove_dead_domains(file_path: str, dead: list[tuple[str, dict]]) -> None:
    """
    Интерактивно удаляет мёртвые домены из файла.
    Сохраняет структуру файла (комментарии, пустые строки).
    """
    dead_domains = {d[0] for d in dead}
    
    # Читаем файл как есть (сохраняем структуру)
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    removed = 0
    new_lines = []
    
    for line in lines:
        stripped = line.strip()
        
        # Если строка — мёртвый домен, спрашиваем
        if stripped in dead_domains:
            # Формируем статус для отображения
            for domain, details in dead:
                if domain == stripped:
                    status = []
                    if not details['dns']:
                        status.append("DNS✗")
                    else:
                        status.append("DNS✓ HTTP✗ TCP✗ Ping✗")
                    status_str = ' '.join(status)
                    break
            
            answer = input(f"Удалить '{stripped}' [{status_str}]? (Y/N): ").strip().lower()
            if answer == 'y':
                removed += 1
                continue  # Пропускаем строку (не добавляем в new_lines)
        
        new_lines.append(line)
    
    # Записываем обратно
    with open(file_path, 'w', encoding='utf-8') as f:
        f.writelines(new_lines)
    
    print(f"\nУдалено: {removed} доменов")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nПроверка прервана пользователем.")
        sys.exit(0)

