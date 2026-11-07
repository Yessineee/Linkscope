phishing operator: 

1- They want to steal your personal data such as email/password , credit card credentials,etc using keyloggers for example.

2- They use tools such as fake captcha or Website Spoofing.

malicious page: 

1- Send some random popups with urgent titles and lucrative offers for example "Congrats you won an iphone, click on this link to proceed" in order to fall for the trap and make you click on the fake links and make you download malware or a virus or even a ransomware.

2- You need to show a very specific types of popups with specific icons and effects so they make it crucial for you to click on them.

privacy leakage:

1- Get your ip adress as well as your location and maybe your personal details so they can sell them for advertisers or in the dark web.



## Phishing operator:

- Goal: Not get detected by security browser extensions such as Linkscope
- What they control: the domaine name, redirects, etc
- How they defeat or abuse Linkscope: Use precise domain names, break the content script
- Where it shows up: fake login pages such as paypa1.com. 
- Status: Open

## Assets to protect
- API keys, browsing history.

## Out of scope
- ClickFix

## Malicious page:

- Goal: Use evasion techniques to avoid Linkscope from detecting the fake popups and scripts
- How they defeat or abuse Linkscope: Injecting scripts or code lines such as : "<input name="action">"
- Status: Open

## Privacy leakage:

- Goal: Leak sensible informations such as IP address, user browser history, etc
- How they defeat or abuse Linkscope: Use precise domain names, break the content script
- Status: Open