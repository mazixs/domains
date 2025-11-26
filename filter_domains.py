import tldextract

def filter_domains(input_file, output_file):
    """
    Reads list.txt and filters out domains that are 3rd level or deeper.
    Keeps 2nd level domains (e.g. example.com, google.co.uk).
    Preserves comments and file structure.
    """
    
    # Initialize tldextract (it might download the suffix list)
    # We trust the default cache location.
    extract = tldextract.TLDExtract(include_psl_private_domains=False)

    try:
        with open(input_file, 'r', encoding='utf-8') as f_in:
            lines = f_in.readlines()
    except FileNotFoundError:
        print(f"Error: File {input_file} not found.")
        return

    with open(output_file, 'w', encoding='utf-8') as f_out:
        processed_count = 0
        kept_count = 0
        
        for line in lines:
            original_line = line
            stripped = line.strip()
            
            # Preserve empty lines and comments
            if not stripped or stripped.startswith('#'):
                f_out.write(original_line)
                continue
            
            # Check if it's a domain
            processed_count += 1
            try:
                ext = extract(stripped)
                
                # Check for IP address (tldextract returns empty suffix/domain sometimes or puts it in domain)
                # For 1.1.1.1: domain='1.1.1.1', suffix='', subdomain=''
                # So it satisfies 'not ext.subdomain'.
                
                if not ext.subdomain:
                    # It is 2nd level (or TLD+1) or IP
                    f_out.write(original_line)
                    kept_count += 1
                else:
                    # It has a subdomain, skip (e.g. www.google.com)
                    pass
                    
            except Exception as e:
                # In case of weird parsing error, maybe keep it or log?
                # We'll assume keep to be safe, or skip?
                # If it fails to parse, it's likely not a valid domain, but let's print and skip
                print(f"Warning: Could not parse '{stripped}': {e}")

    print(f"Processed {processed_count} domains.")
    print(f"Kept {kept_count} 2nd-level domains.")
    print(f"Output written to {output_file}")

if __name__ == "__main__":
    input_path = "list.txt"
    output_path = "list_2nd_level.txt"
    
    print(f"Filtering domains from {input_path}...")
    filter_domains(input_path, output_path)
