---
layout: page
title: About me
subtitle: A noob who instead will keep on moving
---

**Who is f0rm2l1n?** What a werid name?

In fact, I choose this weird word just because it consists of "forma" plus "lin". The former one reminds people of the famous sherlock holmes (in Chinese pronunciation....) while the other happens to be my first name.

Anyhow, it make senses for me.

* * *

I am a student, enjoying + suffering from fighting for the doctor's degree at [ICSR](https://icsr.zju.edu.cn/en/), ZJU in Hangzhou, China, under the supervision of Prof. [Yajin (Andy) Zhou](https://yajin.org/).

Moreover, I am currently involved as a research intern in Ant Security Light-Year Lab, focusing on finding vulnerabilities in kernel.

Moreover, I like the CTF game for its coolness and I also play for my school band: [Azure Assassin Alliance](https://ctftime.org/team/4070).

![AAA-smaller.bmp.png](https://s2.loli.net/2023/08/03/9LxKQdHpEm2VcoD.png){: .mx-auto.d-block :}

It's hard to balance the time between researching and CTFing, also a bunch of other things, ~~girlfriend included~~. Though life is so cruel, we have to be happy :D.

> By the way, I was married already, feel sorry for the girls I have not met ever :D

## Bugs

- [CVE-2021-3573](https://nvd.nist.gov/vuln/detail/CVE-2021-3573) BT CUAF that causes LPE (known as Blue Klostski)
- [CVE-2021-3564](https://access.redhat.com/security/cve/cve-2021-3564) BT CUAF when device registration fails
- [CVE-2021-3640](https://access.redhat.com/security/cve/cve-2021-3640) BT CUAF like the blue klostiski but in SCO subsystem
- [CVE-2021-3760](https://access.redhat.com/security/cve/cve-2021-3760) NFC CUAF to rfkill reference
- [CVE-2021-4202](https://access.redhat.com/security/cve/cve-2021-4202) NFC CUAF like blue klostiski
- [CVE-2022-1198](https://access.redhat.com/security/cve/cve-2022-1198) 6pack driver CUAF
- [CVE-2022-2318](https://access.redhat.com/security/cve/cve-2022-2318) rose driver CUAF
- also participate into finding several concurrenct bugs like:
    - [CVE-2022-1734](https://access.redhat.com/security/cve/cve-2022-1734) NFC firmware downloading procedure double free
    - [CVE-2022-1974](https://access.redhat.com/security/cve/cve-2022-1974) NFC firmware downloading procedure race condition
    - [CVE-2022-1199](https://access.redhat.com/security/cve/cve-2022-1199) AX25 null-ptr-deref from race in sendmsg
    - [CVE-2022-1204](https://access.redhat.com/security/cve/cve-2022-1204) AX25 race condition in rebinding
    - [CVE-2022-1205](https://access.redhat.com/security/cve/cve-2022-1205) AX25 null-ptr-deref from race in timer
    - [CVE-2022-1516](https://access.redhat.com/security/cve/cve-2022-1516) X25 null-ptr-deref
- [CVE-2023-0468](https://access.redhat.com/security/cve/cve-2023-0468) and [CVE-2023-0469](https://access.redhat.com/security/cve/cve-2023-0469), two interesting io_uring CVEs
    - one of this CVE has been used to kill kCTF (by someone else T.T)
- [CVE-2023-3439](https://access.redhat.com/security/cve/cve-2023-3439) MCTP use-after-free read
- [CVE-2023-3863](https://access.redhat.com/security/cve/cve-2023-3863) NFC race condition
- [CVE-2023-3772](https://access.redhat.com/security/cve/cve-2023-3772) XFRM null-ptr-deref
- [CVE-2023-3773](https://access.redhat.com/security/cve/cve-2023-3773) XFRM heap data leakage

> However, I have not yet found the Dream lover (bug). I guess it is okay as a researcher but not cool at all for a security researcher. Keep going f0rm2l1n.

## Publications & Awards

**2022**

[\.] **Ma, Lin** , et al. "When Top-down Meets Bottom-up: Detecting and Exploiting Use-After-Cleanup Bugs in Linux Kernel" [IEEE Symposium on Security and Privacy 2023](https://www.ieee-security.org/TC/SP2023/).

> CUAF is difficult, while UAC is somewhat easier, check out the [paper](https://www.computer.org/csdl/proceedings-article/sp/2023/933600b472/1Js0DZUDcyI).

**2020**

[\.] **Ma, Lin** , et al. "Atlas: A First Step Toward Multipath Validation." Computer Networks (2020):107224.

> That is my first paper ;P, about path validation algorithm. The [click router](https://alan-mushi.github.io/2015/09/15/Click-Modular-Router-tutorial-intro.html) is an interesting emulator that you can try on.

[\.] Qiang Liu^, Cen Zhang^, **Lin Ma** , et al. "FirmGuide: Boosting the Capability of Rehosting Embedded Linux Kernels through Model-Guided Kernel Execution". AES 2021

[\.] Muhui Jiang, **Lin Ma** , et al. ECMO: Peripheral Transplantation to Rehost Embedded Linux Kernels. CCS 2021

> Enter the lab, help the seniors do some experiments, and learn the spirit from them.

[\.] **Lin Ma**, et al. "Revisiting Challenges for Selective Data Protection of Real Applications." APSys 2021

> My paper for the Undergraduate

## Others

I have been the TA for the courses "SSEC: Software-Security" for many years, you can check them at

- [ssec21 spring repo](https://gitee.com/zjuicsr/ssec21spring-stu)
- [ssec22 spring repo](https://gitee.com/zjuicsr/ssec22spring-stu)
- [ssec23 summer repo](https://gitee.com/zjuicsr/ssec23summer-stu)

I have also been one of the mman at the wheel for our school summer courses about basic CTF, please check them at

- [CTF 101 summer course 2022](https://github.com/team-s2/ctf_summer_courses)
- [CTF 101 summer course 2023](https://courses.zjusec.com/)

