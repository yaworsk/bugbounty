> [How I made $31500 by by submitting a bug to facebook](https://medium.com/@win3zz/how-i-made-31500-by-submitting-a-bug-to-facebook-d31bb046e204)
#### Takeaways
- Subdomain enumeration to identify services run by Facebook
- RTFM for third party services
- Download and decompile Java source code
-- Look for unauthenticated services
-- Look for SSRF vulnerabilities (e.g., http or https references)
- Combine vulnerabilities between systems

> [My expense report resulted in a server side request forgery on Lyft](https://www.nahamsec.com/posts/my-expense-report-resulted-in-a-server-side-request-forgery-ssrf-on-lyft)
#### Takeaways
- PDF generators are notorious for SSRF
- Test generators with simple HTML tags
- Read the code; search for HTML tags which take a URL attribute
- Validate your payloads if things aren't firing
