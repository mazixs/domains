import subprocess
import sys
import asyncio
import contextlib
import aiodns

async def check_dns(domain):
    dns_servers = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
    resolver = aiodns.DNSResolver()
    for server in dns_servers:
        resolver.nameservers = [server]
        try:
            await resolver.query(domain, 'A')
            return True  # Если хотя бы один ответил, считаем успешным
        except aiodns.error.DNSError:
            continue  # Пробуем следующий сервер
    return False

async def check_ping(domain):
    try:
        # Асинхронный ping (1 пакет, таймаут ожидания ответа 2с; общий таймаут процесса 5с)
        proc = await asyncio.create_subprocess_exec(
            'ping', '-c', '1', '-W', '2', domain,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            return False
        return proc.returncode == 0
    except Exception:
        return False

def chunked(seq, size):
    for i in range(0, len(seq), size):
        yield seq[i:i+size]

async def check_one(domain, sem):
    async with sem:
        dns_ok = await check_dns(domain)
        ping_ok = await check_ping(domain) if dns_ok else False
        is_dead = (not dns_ok) and (not ping_ok)
        return domain, dns_ok, ping_ok, is_dead

async def run_checks(domains, chunk_size: int = 50, concurrency: int = 25):
    sem = asyncio.Semaphore(concurrency)
    dead = []
    working = 0
    total = len(domains)
    chunks_total = (total + chunk_size - 1) // chunk_size if chunk_size > 0 else 1
    processed = 0
    for idx, chunk in enumerate(chunked(domains, chunk_size), 1):
        tasks = [check_one(d, sem) for d in chunk]
        results = await asyncio.gather(*tasks)
        for domain, dns_ok, ping_ok, is_dead in results:
            if is_dead:
                dead.append(domain)
            else:
                working += 1
        processed += len(chunk)
        # Короткий статус прогресса (без детальных результатов)
        print(f"Прогресс: {processed}/{total} (чанк {idx}/{chunks_total})", end='\r', flush=True)
    # Перевод строки после финального обновления прогресса
    print()
    return total, working, dead

def main():
    file_path = 'list.txt'  # Путь к файлу, если скрипт в той же папке
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Файл {file_path} не найден.")
        sys.exit(1)

    domains = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        domains.append(line)

    # Запускаем асинхронные проверки пакетами (чанками)
    print(f"Начало проверки {len(domains)} доменов...", flush=True)
    total, working, dead = asyncio.run(run_checks(domains))
    not_working = len(dead)

    print(f"Проверено: {total}")
    print(f"Рабочих: {working}")
    print(f"Не рабочих: {not_working}")
    if dead:
        print("\nМертвые домены (нет DNS и нет ping):")
        for d in dead:
            print(d)

if __name__ == "__main__":
    main()

