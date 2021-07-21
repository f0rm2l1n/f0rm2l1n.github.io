---
layout: post
title: Journey through old Linux kernel CVEs
subtitle: Standing on the shoulders of giants
tags: [CVE, Kernel]
---

> Recently, I was assigned a mission to help with reviewing some old Linux kernel CVEs. The main job is to work through these vulnerabilities in a customized *QEMU environment*.

Okay, in conclusion, I have reviewed and did experiments about 12 old CVEs, which mainly have related POC or explanation in Google. I successfully hijack the kernel using some of them but also felt frustrated handling others. Moreover, some of my friends have asked me why keep digging in the old vulnerability instead of trying to find some new ones? Well, of course I want to find kernel bugs 0-days, but it is totally a different thing. I mean, learning old CVEs can help me to learn about the kernel inside, learn exploit skills and also can help me accumulate some insights. In fact, I think this journey is really something to me.

I just want to share this with all of you, hope you will like it.

## CVE lists

The order is casually decided... I will finish them as soon as possible :)

* [CVE-2015-3636](../2020-05-07-CVE-2015-3636) ping-pong root.

* [CVE-2016-8655](../CVE-2016-8655) under working

* [CVE-2016-0728](../2020-06-07-CVE-2016-0728) ref-count overflow

* [CVE-2016-4557](../CVE-2016-4557) under working

* [CVE-2016-9793](../CVE-2016-9793) under working

* [CVE-2016-5195](../2020-06-06-CVE-2016-5195) Dirty-COW.

* [CVE-2017-7038](../CVE-2017-7038) under working

* [CVE-2017-1000112](../CVE-2017-1000112) under working

* [CVE-2017-6074](../CVE-2017-6074) under working

* [CVE-2017-10661](../CVE-2017-10661) under working

* [CVE-2018-5333](../CVE-2018-5333) under working

* [CVE-2019-9213](../CVE-2019-9213) under working

* * *

For there is a lot of [good tutorial](https://github.com/xairy/linux-kernel-exploitation) to help you settle down an environment, you can check these before starting the real exploit.

* * *
**UPDATED**: 

Congratulations to my senior, Qiang Liu, as his paper was accepted by the ASE 2021, So happy that I have done my contribution in this work.
