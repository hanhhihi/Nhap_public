#### Wordlists

- Directory discovery: `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`
    
- File discovery: `/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt`
    
- PayloadsAllTheThings: [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc)
    
- SecLists directory: `/usr/share/seclists/Discovery/Web-Content/common.txt`
    
- SecLists file: `/usr/share/seclists/Discovery/Web-Content/big.txt`
    
- Custom Wordlist from HTML:
    

```bash
# Get the website content
curl http://example.com > example.txt

# Remove duplicated entries

# Crate the dictionary
html2dic example.txt
or
cewl -w createWordlist.txt https://www.example.com

# Improve the wordlist with rules
john ---wordlist=wordlist.txt --rules --stdout > wordlist-modified.txt
```

- LFI Wordlist for Linux: [https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt)
    
- LFI Wordlist for Windows[https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt)
    
- General LFI Wordlist alternative: [https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt)
