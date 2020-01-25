<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<!--
  The above 2 meta tags *must* come first in the <head>
  to consistently ensure proper document rendering.
  Any other head element should come *after* these tags.
 -->
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
</head>
<body>

<a href="https://therealadamburford.github.io/Create-KeyTab/">https://therealadamburford.github.io/Create-KeyTab/</a> 
<p>
<b>Create A KeyTab File Using PowerShell Script</b>
  
This scipt will generate off-line keytab files for use with Active Directory.

This script was developed on a Windows 10 system. It should run on any Windows 10 or Windows 2016 system.

When creating a keytab with AES the SALT the primary/principal part of the UPN is case sensitive. The realm portion is hashed uppercase, even if is not uppercase in the UPN attribute. The script forces the realm to uppercase.

Using the -SALT option, a custom SALT can be used for an account. This would be required if creating a Keytab used with a computer object.

From MS-KILE 3.1.1.2 Cryptographic Material
KILE concatenates the following information to use as the key salt for principals:

- User accounts: \< DNS of the realm, converted to upper case\> | \<user name\>
  
- Computer accounts: \< DNS name of the realm, converted to upper case \> | "host" | \< computer name, converted to lower case with trailing "$" stripped off \> | "." | \< DNS name of the realm, converted to lower case \>  
</body>
</html>
