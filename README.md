# eWPT
eWPT Notes

- Information Gathreing:

  - Tools
    ```
    Whois
    nslookup
    Netcraft
    netcat
    httprint, 
    whatweb,
    wappalyzer
    ```
  - Subdomain Enumeration:
    ```
    Google
    Brurtefoce

    Toolsl:
     SubLister
    Subfinder
    findomain
    amass 
    Zone Transfer (attack)

     dnsrecon: https://github.com/darkoperator/dnsrecon
    • subbrute: https://github.com/TheRook/subbrute
    • fierce: https://github.com/davidpepper/fierce-domain-scanner
    • Nmap: http://nmap.org/book/man-host-discovery.html
    • dnsenum: https://code.google.com/archive/p/dnsenum/downloads
    • knock: https://github.com/guelfoweb/knock
    • theHarvester: https://github.com/laramies/theHarvester
    • recon-ng: https://bitbucket.org/LaNMaSteR53/recon-ng/wiki/Usage Guide
    ```
    
  - Url Extracting:
    ```
    waybackurls
    waybackurls
    BurpSpider
    ```
    
  - FingerPrinting:
    ```
    Wappalayzer
    Whatwep
    Check Response Headers

    Our first step in this case will be to consider the overall scope of
    the application:
    • What is it for?
    • Does it allow user registration?
    • Does it have an administration panel?
    • Does it take input from the user?
    • What kind of input?
    • Does it accept file uploads?
    • Does it use JavaScript or Ajax or Flash? And so on.
    ```
    
  - Enumerate Resources (Files):
    ```
    Burb -Spider
    DirBuster
    Drib
    DirSearch
    Fuff
    Wfuzz
    Enumerate User
    Patator
    BurbBurb -Spider
    
    Enumerate Http Method
      Burbsuite
      Netcat
      Using Option Http Header

    Public file search tools
      Google Dorks
      Foca
      Metagoofil
    ```
    
  - Google Dorking Methods:
    ```
    https://pentest-tools.com/information-gathering/google-hacking
    https://www.exploit-db.com/google-hacking-database
    http://www.googleguide.com/advanced_operators_reference.html

    Shodan Dorking
    Shodan Searcher Zeyad Azima
    ```
    
- XSS:
  ```
  ```
    
- Sql Injection:
  ```
  Detecting the number of fields needed to exploit an in-band SQL
  injection looks like the following:
    • 9999 UNION SELECT NULL; -- -
    • 9999 UNION SELECT NULL, NULL; -- -
    • ...
    • 9999 UNION SELECT NULL, NULL, NULL, NULL; -- -

    • SELECT id, real_name FROM users WHERE id='9999'
      UNION SELECT NULL; -- -

    • SELECT id, real_name FROM users WHERE id='9999'
      UNION SELECT NULL, NULL; -- -

    ' UNION SELECT null, null; -- -
    ' UNION SELECT 1, null; -- -
    ' UNION SELECT 1, null; -- -
    ' UNION SELECT 1, 1; -- -
    ' UNION SELECT 1, 'a'; -- -
  ```
    
- Flash exploit:
  ```
        Adobe Flash is a technology used to create video, animations and
    other rich content. Flash files can be used as standalone
    applications or be embedded in HTML pages.
    The contents can be developed using several tools: Adobe Flash
    Professional (the most popular), Flash Develop, Ajax Animator,
    Flash Minibuilder, etc.

    To build the logic of the application, Adobe provides a scripting
    language called ActionScript. This language is based on ECMA-262
    specs and is very similar to JavaScript.

    Examples of commercial decompiler:
    • Sothink Flash decompiler
    • Trillix Flash decompiler

    allowScriptAccess can have three values:

    Always
    • The SWF file can always communicate with the HTML page regardless of the
    domain(SWF can be on a domain A and communicate with domain B).
    sameDomain
    • The SWF file can communicate with the HTML page only if they share the
    same domain.
    Never
    • The SWF file can never communicate with the HTML page

    Always
    • The SWF file can always communicate with the HTML page regardless of the
    domain(SWF can be on a domain A and communicate with domain B).
    sameDomain

          Pssing Argument to Flash Files

    Method 1 – Direct reference
    Flash is not embedded in an HTML page and arguments are
    provided directly through the URI. When the browser directly
    loads the URI, a dummy HTML page is created.

    Method 2 – Flash Embedded in HTML page
    Flash is embedded in an HTML page and arguments are passed
    through the attribute data of the object element.

    Method 3 – FlashArgs attribute
    Flash is embedded in the HTML page and arguments are passed
    through the attribute FlashArgs of the object element.

              Flash Security Model
    Sandbox and stakeholder are two important concepts in the Flash
    security paradigm.
    In this chapter, we will go through them while trying to both depict
    the Flash security model and how it impacts overall web
    application security.

              Stack Holders
    Who:
    The Administration role is represented by the system administrator
    responsible for the Flash player installation.
    They can configure Flash security settings that will affect all
    operating system users. 

    How:
    • This text configuration file is read when Flash player starts. It allows administrators
    to grant or restrict access to a variety of features. In Microsoft systems, it is
    generally located in the directory system32\Macromed\Flash.
    mms.cfg

    The Global Flash Player Trust directory
    • Administrators can register SWF files as trusted for all operating system users; this
    means that SWF files can interact with other SWF files and can load data from local
    and remote locations.

                      User Role
    How:
    Settings manager, Settings UI
    • The Settings Manager and Settings UI provide security-related options such as:
    camera and microphone settings, shared object storage settings, settings
    related to legacy content, and so on.

    User Flash Player Trust directory
    • Users can register SWF files as trusted; this means that SWF files can interact
    with other SWF files and can load data from local and remote locations.

                      Website Role

    Depending on the requested resource, ActionScript can initiate
    two different types of connection:
    • Document-based server connection for ActionScript objects
        • Loader (to load SWF files or images JPG, PNG, GIF)
        • Sound
        • URLLoader (to load text or binary data)
        • URLStream
        • Socket connection for ActionScript objects
        • Actionscript socket
        • XMLSocket

               Socket policy file
    This policy file is checked by the Flash player whether or not it is a
    socket connection.
    By default, the Flash player looks for a socket policy file on port
    843; we refer to this policy file as the Master policy file.

                 Author Role

    Who:
    The author role is represented by the developer of the Flash
    animation.
    This role can affect the interaction between SWF files available on
    different domains.

    How:
    The API Security.allowDomain(<allowedDomain>) grants
    permissions to the following features:
    • The interaction between different SWF files (Flash CrossScripting)
    • Display list access
    • Event detection
    • Full access to properties and methods of the Stage object

                           Method Native Url
    https://web.archive.org/web/20170328012534/https:/help.adobe.com/en_US/ActionScript/3.0_ProgrammingAS3/WS5b3ccc516d4fbf351e63e3d118a9b90204-7c9b.html

    Flash features an internal storage mechanism based on Local
    Shared Objects.
    Conceptually, Local Shared Objects are similar to browser cookies:
    • They can be used to track user activity or to store preferences.
    • They are read-only by subdomains that have set them.

    However, there are also some significant differences:
    • They are not sent back and forth over HTTP connections.
    • They do not expire.

    • They are stored in a dedicated Flash directory and are shared
    by all browsers on a system.
      • Example: a local shared object set through the Mozilla browser by a domain
    example.com can be read by a Chrome browser (installed on the same
    machine) visiting the same domain. (Cross-browser access.)
    • Path in Windows 7: C:\Users\<user>\AppData\Roaming\Macromedia\Flash
    Player\#SharedObjects\
    • They can contain complex (and large amounts of) data, so
    they offer the advanced features of local storage.

    A Flash Parameter injection vulnerability occurs when:

     The attacker can insert malicious code into the web
    application.
     The web application passes the input provided by the attacker
    to the Flash animation without any significant sanitization.
    The Flash animation, embedded in the HTML page, does not
    sanitize input parameters.
     The SWF source code allows HTML injections or XSS.

    Features 
     Actionscript 2/3 disassembling
     SWF tag viewing
     Local Shared Object (LSO) analyzing
     Dynamic function calling

               Finding Hardcoded Sensitive Informations 
    As we said earlier, Flash contents need to be compiled before they can
    be run.
    Many Flash developers believe that it is impossible to obtain the source
    code of the Flash application once compiled. They are often misled by
    this idea, and may, in turn, hardcode information:
    • URLs of hidden resources
    • Resources that should be hidden to regular users
    • Credentials of services

    The following is a brief walkthrough of the security checks to
    perform when you encounter a Flash component on a website.
    Main areas to check are:
    • Client-side components (SWF files and container page)
    • The Communication protocol between the client side player
    and the server-side components
    • Server-side components

    Static analysis of the SWF source code:
    Obtain the source code of the SWF files and search for
    interesting hard-coded information (URL, credentials info,
    etc.).
     Check if input parameters are sanitized.

    Analysis of the container page (generally the HTML page
    containing the Flash SWF file):
    • Check the allowScriptAccess parameter.
    • Check if input arguments that will be passed to the Flash are
    sanitized.

    Analysis of the website hosting the Flash application
    • Check if the policy file (crossdomain.xml) is configured
    properly.
    Search for common vulnerabilities
    • If the input is not sanitized, you must check whether an
    attacker can take advantage of it. Check for common
    vulnerabilities (HTML injections, XSS). You could use the
    SWFinvestigator’s XSS fuzzer.

    A complex Flash application may make use of web services. So,
    each request could be sent according to a given protocol:
    • SOAP
    • AMF
  ```
    
- Authentication & Authorization:
  ```
    Web applications should create the password reset link and
    maintain the following rules:
    • The link should contain a token
    • The token should abide by the following rules:
    • Minimum length N characters: N>6
    • Wide Character Set: For example, [A-Za-z0-9]
    • Purely random and unpredictable
    • Subject to expiration soon: 30 or 60 
    minutes 

    Publicly known default credentials can quickly result in
    compromise, as illustrated by bAdmin, Phenoelit, and CIRT.

    The following is an example of guessable password reset link. In
    this case, an attacker only needs the user email address.

    It is worth noting that there are techniques and tools that work on both
    third-party and in-house CAPTCHA schemes:
    • Cintruder: https://cintruder.03c8.net/
    • Bypass CAPTCHA with OCR engine:
    http://www.debasish.in/2012/01/bypass-captcha-using-pythonand.html
    • Decoding CAPTCHA: https://boyter.org/decoding-captchas/
    • OWASP: Testing for CAPTCHA: https://boyter.org/decodingcaptchas/

    Besides automated tools, you should also consider that it is cheap
    enough to hire people for breaking CAPTCHA puzzles:
    • Virtual sweatshops versus capt
    • Spammers use the human touch to avoid CAPTCHA
    • Virtual sweatshops defeat Bot-or-Not Tests
    For this reason, CAPTCHA should be only considered as a small
    added security difficulty against attackers.

    https://owasp.org/www-project-top-ten/
    A4 
    A7
    A8

  ```
    
- Session Security:
  ```
    It is also very important to not store session tokens in:


    • URL: the session token will be leaked to external sites through
    the referrer header and in the user browser history
    • HTML: the session token could be cached in the browser or
    intermediate proxies
    • HTML5 Web Storage:
    • Localstorage: will last until it is explicitly deleted, so this may make session
    last too long.
    • Sessionstorage: is only destroyed when the browser is closed. There may be
    users that will not close their browser in a long time.

    Session Hijacking refers to the exploitation of a valid session
    assigned to a user. The attacker can get the victim’s session
    identifier using a few different methods, though typically an XSS is
    used.
    • Note that if the session identifier is weakly generated (see
    the previous chapter), the attacker might be able to bruteforce the session ID

    Session fixation is a session hijacking attack where, as the name
    suggests, the attacker fixates a sessionID and forces the victim to
    use it (after the user logs in).
    The attack can be divided into two phases:
    1. The attacker obtains a valid sessionID
    2. The attacker forces the victim to use this sessionID to
    establish a personal session with the web server

    This is not a vulnerability; however, it could turn into Session
    Fixation if:

    The session identifier remains the same after a
    successfully reserved operation (for example, a login)
    • The session identifier can be propagated (for example: via
    URL or JavaScript) 
  ```
    
  
