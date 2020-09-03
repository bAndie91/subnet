
Use Case
===

- check an IP is within one or more IP range
- answer is command's return code
- support named IP ranges, see cidr.txt
- list all named IP range an IP is in
- good for scripting
- IPv4, IPv6

Examples
===

- Check an IP is in a subnet
  - `subnet 192.168.1.1 192.168.1.0/24`
- Check by well known network name
  - `subnet 192.168.100.100 class-C`
- Check multiple ranges
  - `subnet 192.168.100.100 class-C 192.168.100.0/24`
  - one match sufficient
- List named networks
  - `subnet 10.8.1.0`
  - output:
    ```
    private-net
    rfc1918
    class-A
    priv-class-A
    ```


# issues
Please submit issues via PR to some file `issue/TITLE.txt`.
