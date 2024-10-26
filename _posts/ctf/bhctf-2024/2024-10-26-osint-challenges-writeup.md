---
title: BlockHarbor CTF 2024 Tasks - OSINT
date: 2024-10-05 14:17:00 +0200
categories:
  - CTF
  - BHCTF-2024
tags:
  - ctf
  - ctf-osint
description: My solutions for OSINT challenges of the BlockHarbor CTF 2024
---

# Intro

This September I had a great time playing BlockHarbor Automotive CTF Season 2. This year, the CTF was organized by 
BlockHarbor & VicOne. 

The first round of the comtetition was in `jeopardy` style. It allowed to team up to 5 people. I played alone in my free
time and didn't solve all the challenges. And after playing, I still decided to publish my writeup, although not full as
I initially wanted to. Hope this will be interesting for other organizers, as well as this and next year participants.

This post will describe challenges in the `OSINT` category. For other tasks, check my other posts.

So, let's get straight to the challenges!

# OSINT category
The first category to solve was  `OSINT`. The tasks go in no particular order.

## 1 OR 2

What is the make and color of our other vehicle we owned? One is grey.

Write answer in format: `bh{color_make}`, for example: `bh{yellow_cadillac}`

---

### Google Images
The task is to find a car owned by BlockHarbor somewhere in the internet. I started from [Google Images](https://images.google.com/) and searched `BlockHarbor` string. What I found was mostly grey Ford Mach-O - not our target. 

### Social Networks
Next step was to check social networks. I started from [X (Twitter)](https://x.com/Block_Harbor). Quickly ran through `posts` and `media` but didn't find any suitable car photos.
Next I decided to check [LinkedIn Images](https://www.linkedin.com/company/block-harbor/posts/?feedView=images). 
After some scrolling found the following image:
![red-car](assets/img/2024-10-05-block_harbor_ctf_2024_osint/1_or_2.png){: w="700" h="400" }
Red car with `Block Harbor` logo
To learn the make of the car, I used [Google Image Search](https://images.google.com/)
### Flag
`bh{red_ford}`

## I Know a Lot About Cars
You say you know your cars. Let’s check how well you know them. What is the make and model of this vehicle? 
![red-car](assets/img/2024-10-05-block_harbor_ctf_2024_osint/iknowcars.png){: w="700" h="400" }
Write the answer using the following format: Make Model. For example: `bh{Volkswagen_Beetle}`

---
### Google Images
As in the previous challenge, I used [Google Image Search](https://images.google.com/) to search by provided image and easily found the answer.
### Flag
`bh{Lamborghini_Cheetah}`

## Scanning plates
What country’s license place is this? The answer format is just the country’s name.
![[license.plate.png]]

---
### Google Images
Again, I used [Google Image Search](https://images.google.com/) to search by provided image. But this time I searched only part of the image - the license plate:
![[plate_search.png]]
Found this link: https://www.olavsplates.com/lithuania.html
### Flag
`Lithuania`