import tldextract

def filter_domains(input_file, output_file):
    """
    Reads list.txt and extracts base 2nd level domains.
    Transforms subdomains (e.g., 'sub.example.com') into 'example.com'.
    Preserves comments and structure, but removes duplicates per section.
    """
    
    extract = tldextract.TLDExtract(include_psl_private_domains=False)

    try:
        with open(input_file, 'r', encoding='utf-8') as f_in:
            lines = f_in.readlines()
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
        return

    # We need to track unique domains we've already written to avoid duplicates.
    # Since we want to preserve structure (headers/comments), we can't just set() everything.
    # Strategy:
    # - Read lines sequentially.
    # - If comment/empty: Write immediately.
    # - If domain: Extract 2nd level. If we haven't seen this 2nd level domain yet (globally or per block? Globally is safer for router configs), write it.
    # But router configs often group by service. Let's assume global uniqueness is better to avoid duplicate rules.
    
    seen_domains = set()
    
    with open(output_file, 'w', encoding='utf-8') as f_out:
        processed_count = 0
        written_count = 0
        
        for line in lines:
            original_line = line
            stripped = line.strip()
            
            # Preserve empty lines and comments
            if not stripped or stripped.startswith('#'):
                f_out.write(original_line)
                continue
            
            processed_count += 1
            try:
                ext = extract(stripped)
                
                if ext.domain and ext.suffix:
                    # It's a domain name (e.g. google.com, sub.google.co.uk)
                    # Reconstruct only the registered domain: domain + . + suffix
                    base_domain = f"{ext.domain}.{ext.suffix}"
                    
                    if base_domain not in seen_domains:
                        f_out.write(f"{base_domain}\n")
                        seen_domains.add(base_domain)
                        written_count += 1
                elif not ext.domain and not ext.suffix and stripped:
                     # Probably an IP address or something tldextract couldn't parse as a domain
                     # Keep it as is if unique
                     if stripped not in seen_domains:
                         f_out.write(f"{stripped}\n")
                         seen_domains.add(stripped)
                         written_count += 1
                else:
                    # Weird case, maybe just suffix or just domain? 
                    # fallback to original line if unique
                    if stripped not in seen_domains:
                         f_out.write(f"{stripped}\n")
                         seen_domains.add(stripped)
                         written_count += 1
                    
            except Exception as e:
                print(f"Warning: Could not parse '{stripped}': {e}")

    print(f"Processed {processed_count} entries.")
    print(f"Extracted {written_count} unique 2nd-level domains.")
    print(f"Output written to {output_file}")

if __name__ == "__main__":
    input_path = "list.txt"
    output_path = "list_2nd_level.txt"
    
    print(f"Extracting 2nd level domains from {input_path}...")
    filter_domains(input_path, output_path)
